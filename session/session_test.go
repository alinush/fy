package session

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
)

func TestDKGAndSign(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	// Create participants
	participants := make([]*Participant, total)
	allIDs := []int{1, 2, 3}

	for i := 0; i < total; i++ {
		p, err := NewParticipant(g, threshold, total, i+1)
		if err != nil {
			t.Fatalf("failed to create participant %d: %v", i+1, err)
		}
		participants[i] = p
	}

	// Round 1: Generate broadcasts and private shares
	r1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		r1, err := p.GenerateRound1(rand.Reader, allIDs)
		if err != nil {
			t.Fatalf("participant %d failed to generate round 1: %v", i+1, err)
		}
		r1Outputs[i] = r1
	}

	// Collect all broadcasts
	broadcasts := make([]*frost.Round1Data, total)
	for i, r1 := range r1Outputs {
		broadcasts[i] = r1.Broadcast
	}

	// Process round 1 for each participant
	results := make([]*DKGResult, total)
	for i, p := range participants {
		// Collect private shares sent to this participant
		var privateShares []*frost.Round1PrivateData
		for j, r1 := range r1Outputs {
			if i == j {
				continue // skip own shares
			}
			if share, ok := r1.PrivateShares[p.ID()]; ok {
				privateShares = append(privateShares, share)
			}
		}

		result, err := p.ProcessRound1(&Round1Input{
			Broadcasts:    broadcasts,
			PrivateShares: privateShares,
		})
		if err != nil {
			t.Fatalf("participant %d failed to process round 1: %v", i+1, err)
		}
		results[i] = result
	}

	// Verify all participants have the same group key
	for i := 1; i < total; i++ {
		if !results[i].GroupKey.Equal(results[0].GroupKey) {
			t.Error("participants have different group keys")
		}
	}

	t.Run("Signing", func(t *testing.T) {
		message := []byte("hello session API")

		// Use first 'threshold' participants to sign
		signers := participants[:threshold]

		// Create signing sessions
		sessions := make([]*SigningSession, threshold)
		commitments := make([]*frost.SigningCommitment, threshold)

		for i, p := range signers {
			sess, err := p.NewSigningSession(rand.Reader, message)
			if err != nil {
				t.Fatalf("signer %d failed to create session: %v", i+1, err)
			}
			sessions[i] = sess
			commitments[i] = sess.Commitment()
		}

		// Generate signature shares
		shares := make([]*frost.SignatureShare, threshold)
		for i, sess := range sessions {
			share, err := sess.Sign(commitments)
			if err != nil {
				t.Fatalf("signer %d failed to sign: %v", i+1, err)
			}
			shares[i] = share
		}

		// Aggregate
		sig, err := Aggregate(signers[0].FROST(), message, commitments, shares)
		if err != nil {
			t.Fatalf("failed to aggregate: %v", err)
		}

		// Verify
		err = Verify(signers[0].FROST(), message, sig, results[0].GroupKey)
		if err != nil {
			t.Error("signature verification failed")
		}

		// Wrong message should fail
		err = Verify(signers[0].FROST(), []byte("wrong message"), sig, results[0].GroupKey)
		if err == nil {
			t.Error("signature should not verify with wrong message")
		}
	})
}

func TestNonceReusePrevention(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3
	allIDs := []int{1, 2, 3}

	// Create and run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, _ := NewParticipant(g, threshold, total, i+1)
		participants[i] = p
	}

	r1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		r1, _ := p.GenerateRound1(rand.Reader, allIDs)
		r1Outputs[i] = r1
	}

	broadcasts := make([]*frost.Round1Data, total)
	for i, r1 := range r1Outputs {
		broadcasts[i] = r1.Broadcast
	}

	for i, p := range participants {
		var privateShares []*frost.Round1PrivateData
		for j, r1 := range r1Outputs {
			if i == j {
				continue
			}
			if share, ok := r1.PrivateShares[p.ID()]; ok {
				privateShares = append(privateShares, share)
			}
		}
		p.ProcessRound1(&Round1Input{
			Broadcasts:    broadcasts,
			PrivateShares: privateShares,
		})
	}

	// Create a signing session
	message := []byte("test nonce reuse")
	sess, err := participants[0].NewSigningSession(rand.Reader, message)
	if err != nil {
		t.Fatal(err)
	}

	commitment := sess.Commitment()
	commitments := []*frost.SigningCommitment{commitment}

	// First sign should succeed
	_, err = sess.Sign(commitments)
	if err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// Second sign should fail (nonce reuse prevention)
	_, err = sess.Sign(commitments)
	if err == nil {
		t.Error("second sign should fail to prevent nonce reuse")
	}

	// IsConsumed should return true
	if !sess.IsConsumed() {
		t.Error("session should be marked as consumed")
	}
}

func TestSigningSessionWithoutDKG(t *testing.T) {
	g := &bjj.BJJ{}
	p, _ := NewParticipant(g, 2, 3, 1)

	// Try to create a signing session without completing DKG
	_, err := p.NewSigningSession(rand.Reader, []byte("test"))
	if err == nil {
		t.Error("should fail to create signing session without DKG")
	}
}

func TestDuplicateRound1Generation(t *testing.T) {
	g := &bjj.BJJ{}
	allIDs := []int{1, 2, 3}

	p, _ := NewParticipant(g, 2, 3, 1)

	// First round 1 should succeed
	_, err := p.GenerateRound1(rand.Reader, allIDs)
	if err != nil {
		t.Fatal(err)
	}

	// Second round 1 should fail
	_, err = p.GenerateRound1(rand.Reader, allIDs)
	if err == nil {
		t.Error("should not allow generating round 1 twice")
	}
}

func TestParticipantIDValidation(t *testing.T) {
	g := &bjj.BJJ{}

	// ID too low
	_, err := NewParticipant(g, 2, 3, 0)
	if err == nil {
		t.Error("should reject ID of 0")
	}

	// ID too high
	_, err = NewParticipant(g, 2, 3, 4)
	if err == nil {
		t.Error("should reject ID greater than total")
	}

	// Valid IDs
	for id := 1; id <= 3; id++ {
		_, err := NewParticipant(g, 2, 3, id)
		if err != nil {
			t.Errorf("should accept ID %d", id)
		}
	}
}

func TestQuickSign(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3
	allIDs := []int{1, 2, 3}

	// Run DKG using session API
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, _ := NewParticipant(g, threshold, total, i+1)
		participants[i] = p
	}

	r1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		r1, _ := p.GenerateRound1(rand.Reader, allIDs)
		r1Outputs[i] = r1
	}

	broadcasts := make([]*frost.Round1Data, total)
	for i, r1 := range r1Outputs {
		broadcasts[i] = r1.Broadcast
	}

	keyShares := make([]*frost.KeyShare, total)
	for i, p := range participants {
		var privateShares []*frost.Round1PrivateData
		for j, r1 := range r1Outputs {
			if i == j {
				continue
			}
			if share, ok := r1.PrivateShares[p.ID()]; ok {
				privateShares = append(privateShares, share)
			}
		}
		result, _ := p.ProcessRound1(&Round1Input{
			Broadcasts:    broadcasts,
			PrivateShares: privateShares,
		})
		keyShares[i] = result.KeyShare
	}

	// Use QuickSign with threshold key shares
	message := []byte("quick sign test")
	sig, err := QuickSign(participants[0].FROST(), rand.Reader, keyShares[:threshold], message)
	if err != nil {
		t.Fatalf("QuickSign failed: %v", err)
	}

	// Verify
	err = Verify(participants[0].FROST(), message, sig, keyShares[0].GroupKey)
	if err != nil {
		t.Error("signature verification failed")
	}
}

func TestSetKeyShare(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3
	allIDs := []int{1, 2, 3}

	// Run DKG for first participant only
	p1, _ := NewParticipant(g, threshold, total, 1)
	p2, _ := NewParticipant(g, threshold, total, 2)

	r1_1, _ := p1.GenerateRound1(rand.Reader, allIDs)
	r1_2, _ := p2.GenerateRound1(rand.Reader, allIDs)

	broadcasts := []*frost.Round1Data{r1_1.Broadcast, r1_2.Broadcast}

	result1, _ := p1.ProcessRound1(&Round1Input{
		Broadcasts:    broadcasts,
		PrivateShares: []*frost.Round1PrivateData{r1_2.PrivateShares[1]},
	})
	result2, _ := p2.ProcessRound1(&Round1Input{
		Broadcasts:    broadcasts,
		PrivateShares: []*frost.Round1PrivateData{r1_1.PrivateShares[2]},
	})

	// Create a new participant and set key share (simulating restore from storage)
	p1Restored, _ := NewParticipant(g, threshold, total, 1)
	p1Restored.SetKeyShare(result1.KeyShare)

	// Should be able to sign with restored participant
	message := []byte("restored participant test")

	sess1, err := p1Restored.NewSigningSession(rand.Reader, message)
	if err != nil {
		t.Fatal(err)
	}
	sess2, err := p2.NewSigningSession(rand.Reader, message)
	if err != nil {
		t.Fatal(err)
	}

	commitments := []*frost.SigningCommitment{sess1.Commitment(), sess2.Commitment()}

	share1, _ := sess1.Sign(commitments)
	share2, _ := sess2.Sign(commitments)

	sig, err := Aggregate(p1Restored.FROST(), message, commitments, []*frost.SignatureShare{share1, share2})
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(p1Restored.FROST(), message, sig, result2.GroupKey)
	if err != nil {
		t.Error("signature verification failed")
	}
}

func TestAggregateValidation(t *testing.T) {
	g := &bjj.BJJ{}
	f, _ := frost.New(g, 2, 3)

	// Empty shares
	_, err := Aggregate(f, []byte("test"), nil, nil)
	if err == nil {
		t.Error("should fail with no shares")
	}

	// Empty commitments
	_, err = Aggregate(f, []byte("test"), nil, []*frost.SignatureShare{{}})
	if err == nil {
		t.Error("should fail with no commitments")
	}

	// Mismatched counts
	_, err = Aggregate(f, []byte("test"),
		[]*frost.SigningCommitment{{}},
		[]*frost.SignatureShare{{}, {}})
	if err == nil {
		t.Error("should fail with mismatched counts")
	}
}

func TestSigningWithDifferentSubsets(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 4
	allIDs := []int{1, 2, 3, 4}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, _ := NewParticipant(g, threshold, total, i+1)
		participants[i] = p
	}

	r1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		r1, _ := p.GenerateRound1(rand.Reader, allIDs)
		r1Outputs[i] = r1
	}

	broadcasts := make([]*frost.Round1Data, total)
	for i, r1 := range r1Outputs {
		broadcasts[i] = r1.Broadcast
	}

	results := make([]*DKGResult, total)
	for i, p := range participants {
		var privateShares []*frost.Round1PrivateData
		for j, r1 := range r1Outputs {
			if i == j {
				continue
			}
			if share, ok := r1.PrivateShares[p.ID()]; ok {
				privateShares = append(privateShares, share)
			}
		}
		result, _ := p.ProcessRound1(&Round1Input{
			Broadcasts:    broadcasts,
			PrivateShares: privateShares,
		})
		results[i] = result
	}

	message := []byte("subset signing test")

	// Test different signer subsets (minimal set for correctness)
	subsets := [][]int{
		{0, 1},       // threshold (participants 1 and 2)
		{0, 1, 2, 3}, // all participants
	}

	for _, subset := range subsets {
		signers := make([]*Participant, len(subset))
		for i, idx := range subset {
			signers[i] = participants[idx]
		}

		// Create sessions and commitments
		sessions := make([]*SigningSession, len(signers))
		commitments := make([]*frost.SigningCommitment, len(signers))
		for i, p := range signers {
			sess, _ := p.NewSigningSession(rand.Reader, message)
			sessions[i] = sess
			commitments[i] = sess.Commitment()
		}

		// Sign
		shares := make([]*frost.SignatureShare, len(signers))
		for i, sess := range sessions {
			share, _ := sess.Sign(commitments)
			shares[i] = share
		}

		// Aggregate and verify
		sig, err := Aggregate(signers[0].FROST(), message, commitments, shares)
		if err != nil {
			t.Fatalf("subset %v: aggregate failed: %v", subset, err)
		}

		err = Verify(signers[0].FROST(), message, sig, results[0].GroupKey)
		if err != nil {
			t.Errorf("subset %v: verification failed", subset)
		}
	}
}

func TestMissingOwnCommitment(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3
	allIDs := []int{1, 2, 3}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, _ := NewParticipant(g, threshold, total, i+1)
		participants[i] = p
	}

	r1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		r1, _ := p.GenerateRound1(rand.Reader, allIDs)
		r1Outputs[i] = r1
	}

	broadcasts := make([]*frost.Round1Data, total)
	for i, r1 := range r1Outputs {
		broadcasts[i] = r1.Broadcast
	}

	for i, p := range participants {
		var privateShares []*frost.Round1PrivateData
		for j, r1 := range r1Outputs {
			if i == j {
				continue
			}
			if share, ok := r1.PrivateShares[p.ID()]; ok {
				privateShares = append(privateShares, share)
			}
		}
		p.ProcessRound1(&Round1Input{
			Broadcasts:    broadcasts,
			PrivateShares: privateShares,
		})
	}

	// Create signing session
	message := []byte("test")
	sess, _ := participants[0].NewSigningSession(rand.Reader, message)

	// Try to sign with commitments that don't include our own
	sess2, _ := participants[1].NewSigningSession(rand.Reader, message)
	wrongCommitments := []*frost.SigningCommitment{sess2.Commitment()}

	_, err := sess.Sign(wrongCommitments)
	if err == nil {
		t.Error("should fail when own commitment is missing")
	}
}
