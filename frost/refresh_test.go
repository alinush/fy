package frost

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/f3rmion/fy/bjj"
)

// runRefresh performs a complete refresh protocol round for all participants,
// returning new key shares. All n participants must participate.
func runRefresh(t *testing.T, f *FROST, keyShares []*KeyShare) []*KeyShare {
	t.Helper()

	total := len(keyShares)

	// Create refresh participants.
	rps := make([]*RefreshParticipant, total)
	for i, ks := range keyShares {
		rp, err := f.NewRefreshParticipant(rand.Reader, ks.ID)
		if err != nil {
			t.Fatalf("failed to create refresh participant %d: %v", i+1, err)
		}
		rps[i] = rp
	}

	// Round 1: Broadcast commitments.
	broadcasts := make([]*RefreshRound1Data, total)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Round 1: Send private deltas to each other participant.
	for i := range total {
		for j := range total {
			if i == j {
				continue
			}
			privateData, err := f.RefreshRound1PrivateSend(rps[i], keyShares[j].ID)
			if err != nil {
				t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
			}
			err = f.RefreshRound2ReceiveDelta(rps[j], privateData, broadcasts[i].Commitments)
			if err != nil {
				t.Fatalf("participant %d failed to verify delta from %d: %v", j+1, i+1, err)
			}
		}
	}

	// Finalize: Compute new key shares.
	newShares := make([]*KeyShare, total)
	for i, rp := range rps {
		ks, err := f.RefreshFinalize(rp, keyShares[i], broadcasts)
		if err != nil {
			t.Fatalf("participant %d failed to finalize refresh: %v", i+1, err)
		}
		newShares[i] = ks
	}

	return newShares
}

func TestRefreshBasic_2of3(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	// DKG.
	keyShares := runDKG(t, f, total)

	// Refresh.
	newShares := runRefresh(t, f, keyShares)

	// Sign with threshold signers using new shares.
	message := []byte("post-refresh signing test")
	signAndVerify(t, f, newShares[:threshold], message)
}

func TestRefreshPreservesGroupKey(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)
	originalGroupKey := keyShares[0].GroupKey

	newShares := runRefresh(t, f, keyShares)

	// Verify every participant's group key is unchanged.
	for i, ns := range newShares {
		if !ns.GroupKey.Equal(originalGroupKey) {
			t.Errorf("participant %d: group key changed after refresh", i+1)
		}
	}

	// Also verify all new shares agree on the group key.
	for i := 1; i < total; i++ {
		if !newShares[i].GroupKey.Equal(newShares[0].GroupKey) {
			t.Errorf("participants %d and 0 have different group keys after refresh", i)
		}
	}
}

func TestRefreshChangesSecretKeys(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Save old secret keys for comparison.
	oldSecrets := make([][]byte, total)
	for i, ks := range keyShares {
		oldSecrets[i] = ks.SecretKey.Bytes()
	}

	newShares := runRefresh(t, f, keyShares)

	// Verify every participant's secret key has changed.
	for i, ns := range newShares {
		if ns.SecretKey.Equal(keyShares[i].SecretKey) {
			// Use byte comparison as a fallback since the old share was consumed.
			t.Errorf("participant %d: secret key unchanged after refresh", i+1)
		}
		newBytes := ns.SecretKey.Bytes()
		if string(newBytes) == string(oldSecrets[i]) {
			t.Errorf("participant %d: secret key bytes unchanged after refresh", i+1)
		}
	}
}

func TestRefreshSignWithSubsets(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)
	newShares := runRefresh(t, f, keyShares)

	message := []byte("subset signing after refresh")

	// All valid 2-of-3 subsets.
	subsets := [][]int{
		{0, 1},
		{0, 2},
		{1, 2},
	}

	for _, subset := range subsets {
		name := fmt.Sprintf("signers_%d_%d", subset[0]+1, subset[1]+1)
		t.Run(name, func(t *testing.T) {
			signers := make([]*KeyShare, len(subset))
			for i, idx := range subset {
				signers[i] = newShares[idx]
			}
			signAndVerify(t, f, signers, message)
		})
	}
}

func TestRefreshMultipleRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multiple refresh rounds in short mode")
	}

	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)
	originalGroupKey := keyShares[0].GroupKey

	message := []byte("multi-round refresh test")

	// First refresh + sign.
	shares1 := runRefresh(t, f, keyShares)
	signAndVerify(t, f, shares1[:threshold], message)

	if !shares1[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after first refresh")
	}

	// Second refresh + sign.
	shares2 := runRefresh(t, f, shares1)
	signAndVerify(t, f, shares2[:threshold], []byte("after second refresh"))

	if !shares2[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after second refresh")
	}

	// Verify secret keys changed between rounds.
	for i := range total {
		if shares1[i].SecretKey.Equal(shares2[i].SecretKey) {
			t.Errorf("participant %d: secret key unchanged between refresh rounds", i+1)
		}
	}
}

func TestRefreshThresholds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping threshold table test in short mode")
	}

	g := &bjj.BJJ{}

	configs := []struct {
		threshold int
		total     int
	}{
		{2, 3},
		{3, 5},
	}

	for _, cfg := range configs {
		name := fmt.Sprintf("%d_of_%d", cfg.threshold, cfg.total)
		t.Run(name, func(t *testing.T) {
			f, err := New(g, cfg.threshold, cfg.total)
			if err != nil {
				t.Fatal(err)
			}

			keyShares := runDKG(t, f, cfg.total)
			newShares := runRefresh(t, f, keyShares)

			// Sign with exactly threshold signers.
			message := []byte("threshold refresh test")
			signAndVerify(t, f, newShares[:cfg.threshold], message)

			// Verify group key preserved.
			if !newShares[0].GroupKey.Equal(keyShares[0].GroupKey) {
				t.Error("group key changed after refresh")
			}
		})
	}
}

func TestRefreshCheatingConstantTerm(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create honest refresh participants for participants 1 and 2.
	rps := make([]*RefreshParticipant, total)
	for i := range 2 {
		rp, err := f.NewRefreshParticipant(rand.Reader, keyShares[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp
	}

	// Participant 3 cheats: create a normal refresh participant, then
	// overwrite coefficients[0] with a non-zero value.
	cheater, err := f.NewRefreshParticipant(rand.Reader, keyShares[2].ID)
	if err != nil {
		t.Fatal(err)
	}

	// Manually set coefficients[0] to a non-zero scalar.
	nonZero, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cheater.coefficients[0] = nonZero
	// Recompute commitments to match the cheating coefficients.
	cheater.commitments[0] = g.NewPoint().ScalarMult(nonZero, g.Generator())
	rps[2] = cheater

	// Broadcast (includes the cheating commitment).
	broadcasts := make([]*RefreshRound1Data, total)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Exchange deltas.
	for i := range total {
		for j := range total {
			if i == j {
				continue
			}
			privateData, err := f.RefreshRound1PrivateSend(rps[i], keyShares[j].ID)
			if err != nil {
				t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
			}
			err = f.RefreshRound2ReceiveDelta(rps[j], privateData, broadcasts[i].Commitments)
			if err != nil {
				t.Fatalf("participant %d failed to verify delta from %d: %v", j+1, i+1, err)
			}
		}
	}

	// RefreshFinalize should detect that the sum of Commitments[0] is not identity.
	_, err = f.RefreshFinalize(rps[0], keyShares[0], broadcasts)
	if err == nil {
		t.Fatal("expected error from RefreshFinalize when a participant cheats on constant term")
	}
}

func TestRefreshFeldmanVSSFailure(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create refresh participants.
	rps := make([]*RefreshParticipant, total)
	for i, ks := range keyShares {
		rp, err := f.NewRefreshParticipant(rand.Reader, ks.ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp
	}

	broadcasts := make([]*RefreshRound1Data, total)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Participant 0 sends a tampered delta to participant 1.
	tamperedData, err := f.RefreshRound1PrivateSend(rps[0], keyShares[1].ID)
	if err != nil {
		t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
	}

	// Tamper with the delta: add a random scalar to corrupt it.
	tamper, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tamperedData.Delta = g.NewScalar().Add(tamperedData.Delta, tamper)

	// Participant 1 should reject the tampered delta.
	err = f.RefreshRound2ReceiveDelta(rps[1], tamperedData, broadcasts[0].Commitments)
	if err == nil {
		t.Fatal("expected error from RefreshRound2ReceiveDelta with tampered delta")
	}
}

func TestRefreshNotEnoughParticipants(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create refresh participants for only 2 of 3.
	rps := make([]*RefreshParticipant, 2)
	for i := range 2 {
		rp, err := f.NewRefreshParticipant(rand.Reader, keyShares[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp
	}

	// Broadcast from only 2 participants.
	broadcasts := make([]*RefreshRound1Data, 2)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Exchange deltas between the 2 participants.
	privateData, err := f.RefreshRound1PrivateSend(rps[0], keyShares[1].ID)
	if err != nil {
		t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
	}
	if err := f.RefreshRound2ReceiveDelta(rps[1], privateData, broadcasts[0].Commitments); err != nil {
		t.Fatal(err)
	}
	privateData, err = f.RefreshRound1PrivateSend(rps[1], keyShares[0].ID)
	if err != nil {
		t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
	}
	if err := f.RefreshRound2ReceiveDelta(rps[0], privateData, broadcasts[1].Commitments); err != nil {
		t.Fatal(err)
	}

	// RefreshFinalize should reject because we only have 2 of 3 broadcasts.
	_, err = f.RefreshFinalize(rps[0], keyShares[0], broadcasts)
	if err == nil {
		t.Fatal("expected error from RefreshFinalize with fewer than n broadcasts")
	}
}

func TestRefreshSecretZeroing(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create a single refresh participant and hold a reference.
	rp, err := f.NewRefreshParticipant(rand.Reader, keyShares[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify coefficients exist before finalization.
	if rp.coefficients == nil {
		t.Fatal("coefficients should not be nil before finalize")
	}

	// Run the full refresh protocol using runRefresh (which calls RefreshFinalize).
	// We need to do this manually for this one participant to retain the rp reference.
	rps := make([]*RefreshParticipant, total)
	rps[0] = rp
	for i := 1; i < total; i++ {
		rp2, err := f.NewRefreshParticipant(rand.Reader, keyShares[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp2
	}

	broadcasts := make([]*RefreshRound1Data, total)
	for i, r := range rps {
		broadcasts[i] = r.Round1Broadcast()
	}

	for i := range total {
		for j := range total {
			if i == j {
				continue
			}
			pd, err := f.RefreshRound1PrivateSend(rps[i], keyShares[j].ID)
			if err != nil {
				t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
			}
			if err := f.RefreshRound2ReceiveDelta(rps[j], pd, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Finalize participant 0 (our tracked reference).
	_, err = f.RefreshFinalize(rp, keyShares[0], broadcasts)
	if err != nil {
		t.Fatal(err)
	}

	// After finalize, coefficients and receivedDeltas should be nil (zeroed).
	if rp.coefficients != nil {
		t.Error("coefficients should be nil after RefreshFinalize")
	}
	if rp.receivedDeltas != nil {
		t.Error("receivedDeltas should be nil after RefreshFinalize")
	}
}

func TestRefreshOldSharesMixedWithNew(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Save copies of old key shares before refresh.
	oldShares := make([]*KeyShare, total)
	for i, ks := range keyShares {
		oldShares[i] = &KeyShare{
			ID:        ks.ID,
			SecretKey: g.NewScalar().Set(ks.SecretKey),
			PublicKey: g.NewPoint().Set(ks.PublicKey),
			GroupKey:  g.NewPoint().Set(ks.GroupKey),
		}
	}

	newShares := runRefresh(t, f, keyShares)

	// Verify that new shares work correctly on their own.
	message := []byte("mixed shares test")
	signAndVerify(t, f, newShares[:threshold], message)

	// Now try signing with a mix: old share 0 + new share 1.
	// This should produce an invalid signature because the shares
	// are from different polynomials after refresh.
	mixedSigners := []*KeyShare{oldShares[0], newShares[1]}

	nonces := make([]*SigningNonce, threshold)
	commitments := make([]*SigningCommitment, threshold)
	for i, ks := range mixedSigners {
		n, c, err := f.SignRound1(rand.Reader, ks)
		if err != nil {
			t.Fatalf("mixed signer %d failed round 1: %v", i, err)
		}
		nonces[i] = n
		commitments[i] = c
	}

	sigShares := make([]*SignatureShare, threshold)
	for i, ks := range mixedSigners {
		ss, err := f.SignRound2(ks, nonces[i], message, commitments)
		if err != nil {
			t.Fatalf("mixed signer %d failed round 2: %v", i, err)
		}
		sigShares[i] = ss
	}

	sig, err := f.Aggregate(message, commitments, sigShares)
	if err != nil {
		t.Fatalf("failed to aggregate mixed signature: %v", err)
	}

	// The signature from mixed old+new shares must NOT verify against the group key.
	if f.Verify(message, sig, newShares[0].GroupKey) {
		t.Error("signature from mixed old+new shares should not verify")
	}
}

func TestRefreshDuplicateDelta(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create refresh participants.
	rps := make([]*RefreshParticipant, total)
	for i, ks := range keyShares {
		rp, err := f.NewRefreshParticipant(rand.Reader, ks.ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp
	}

	broadcasts := make([]*RefreshRound1Data, total)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Participant 0 sends a delta to participant 1 (first time: accepted).
	privateData, err := f.RefreshRound1PrivateSend(rps[0], keyShares[1].ID)
	if err != nil {
		t.Fatalf("RefreshRound1PrivateSend failed: %v", err)
	}
	err = f.RefreshRound2ReceiveDelta(rps[1], privateData, broadcasts[0].Commitments)
	if err != nil {
		t.Fatalf("first delta should be accepted: %v", err)
	}

	// Same sender sends again to participant 1 (duplicate: rejected).
	err = f.RefreshRound2ReceiveDelta(rps[1], privateData, broadcasts[0].Commitments)
	if err == nil {
		t.Fatal("expected error for duplicate delta from same participant, got nil")
	}
}

func TestRefreshZeroID(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	// Participant with ID=0 must be rejected.
	zeroID := g.NewScalar()
	_, err = f.NewRefreshParticipant(rand.Reader, zeroID)
	if err == nil {
		t.Fatal("expected error for zero participant ID, got nil")
	}
}

func TestRefreshRecipientIDMismatch(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	keyShares := runDKG(t, f, total)

	// Create refresh participants.
	rps := make([]*RefreshParticipant, total)
	for i, ks := range keyShares {
		rp, err := f.NewRefreshParticipant(rand.Reader, ks.ID)
		if err != nil {
			t.Fatal(err)
		}
		rps[i] = rp
	}

	broadcasts := make([]*RefreshRound1Data, total)
	for i, rp := range rps {
		broadcasts[i] = rp.Round1Broadcast()
	}

	// Participant 0 sends a delta intended for participant 1.
	privateData, err := f.RefreshRound1PrivateSend(rps[0], keyShares[1].ID)
	if err != nil {
		t.Fatal(err)
	}

	// Try to receive it as participant 2 (wrong recipient).
	err = f.RefreshRound2ReceiveDelta(rps[2], privateData, broadcasts[0].Commitments)
	if err == nil {
		t.Fatal("expected error for recipient ID mismatch, got nil")
	}
}
