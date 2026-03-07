package session

import (
	"testing"

	"github.com/f3rmion/fy/dkls23/dkg"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

func TestDKLS23DKGAndSign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKLS23 DKG test in short mode")
	}

	threshold := uint8(2)
	total := uint8(3)
	sessionID := []byte("test-session-id!")

	// Create participants
	participants := make([]*DKLS23Participant, total)
	for i := uint8(1); i <= total; i++ {
		p, err := NewDKLS23Participant(threshold, total, i, sessionID)
		if err != nil {
			t.Fatalf("failed to create participant %d: %v", i, err)
		}
		participants[i-1] = p
	}

	// Phase 1: Generate polynomials
	phase1Outputs := make([]*DKLS23DKGPhase1Output, total)
	for i, p := range participants {
		output, err := p.DKGPhase1()
		if err != nil {
			t.Fatalf("participant %d failed phase 1: %v", i+1, err)
		}
		phase1Outputs[i] = output
	}

	// Exchange polynomial points
	// Each participant receives points from all others
	receivedPolyPoints := make([]map[uint8][]byte, total)
	for i := range participants {
		receivedPolyPoints[i] = make(map[uint8][]byte)
	}

	// Phase 2: Generate commitments
	phase2Outputs := make([]*DKLS23DKGPhase2Output, total)
	for i, p := range participants {
		// Collect polynomial points for this participant
		polyPoints := make(map[uint8]group.Scalar)
		for j, output := range phase1Outputs {
			if i == j {
				continue
			}
			// Party j sends their evaluation at index i+1 to party i
			polyPoints[uint8(j+1)] = output.PolyPoints[i]
		}

		output, err := p.DKGPhase2(polyPoints)
		if err != nil {
			t.Fatalf("participant %d failed phase 2: %v", i+1, err)
		}
		phase2Outputs[i] = output
	}

	// Phase 3: Reveal and init multiplication
	phase3Outputs := make([]*DKLS23DKGPhase3Output, total)
	for i, p := range participants {
		output, err := p.DKGPhase3()
		if err != nil {
			t.Fatalf("participant %d failed phase 3: %v", i+1, err)
		}
		phase3Outputs[i] = output
	}

	// Phase 4: Finalize
	parties := make([]*sign.Party, total)
	for i, p := range participants {
		// Collect all proof commitments (including our own)
		proofCommitments := make([]*dkg.ProofCommitment, total)
		for j, output := range phase2Outputs {
			proofCommitments[j] = output.ProofCommitment
		}

		// Collect zero commitments received in phase 2
		zeroCommitments := make([]*dkg.Phase2to4ZeroTransmit, 0, total-1)
		for j, output := range phase2Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.ZeroCommitments[uint8(i+1)]; ok {
				zeroCommitments = append(zeroCommitments, msg)
			}
		}

		// Collect zero seeds received in phase 3
		zeroSeeds := make([]*dkg.Phase3to4ZeroTransmit, 0, total-1)
		for j, output := range phase3Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.ZeroSeeds[uint8(i+1)]; ok {
				zeroSeeds = append(zeroSeeds, msg)
			}
		}

		// Collect mul init received in phase 3
		mulInit := make([]*dkg.Phase3to4MulTransmit, 0, total-1)
		for j, output := range phase3Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.MulInit[uint8(i+1)]; ok {
				mulInit = append(mulInit, msg)
			}
		}

		err := p.DKGPhase4(&DKLS23DKGPhase4Input{
			ProofCommitments: proofCommitments,
			ZeroCommitments:  zeroCommitments,
			ZeroSeeds:        zeroSeeds,
			MulInit:          mulInit,
		})
		if err != nil {
			t.Fatalf("participant %d failed phase 4: %v", i+1, err)
		}

		parties[i] = p.Party()
		if parties[i] == nil {
			t.Fatalf("participant %d has nil party after DKG", i+1)
		}
	}

	// Verify all parties have the same public key
	for i := 1; i < int(total); i++ {
		if !pointsEqual(parties[i].PublicKey, parties[0].PublicKey) {
			t.Error("parties have different public keys")
		}
	}

	t.Run("Signing", func(t *testing.T) {
		messageHash := DKLS23MessageHash([]byte("hello DKLS23 session API"))
		signID := []byte("sign-session-1")

		// Use first 'threshold' parties to sign
		signerParties := parties[:threshold]

		// Build counterparties for each signer
		signerIndices := make([]uint8, threshold)
		for i, p := range signerParties {
			signerIndices[i] = p.Index
		}

		// Create signing sessions
		sessions := make([]*DKLS23SigningSession, threshold)
		for i, p := range signerParties {
			counterparties := make([]uint8, 0, threshold-1)
			for _, idx := range signerIndices {
				if idx != p.Index {
					counterparties = append(counterparties, idx)
				}
			}

			sess, err := NewDKLS23SigningSession(p, messageHash, signID, counterparties)
			if err != nil {
				t.Fatalf("signer %d failed to create session: %v", i+1, err)
			}
			sessions[i] = sess
		}

		// Phase 1
		phase1SignOutputs := make([]*DKLS23SignPhase1Output, threshold)
		for i, sess := range sessions {
			output, err := sess.Phase1()
			if err != nil {
				t.Fatalf("signer %d failed sign phase 1: %v", i+1, err)
			}
			phase1SignOutputs[i] = output
		}

		// Collect phase 1 messages by receiver
		phase1ByReceiver := make(map[uint8]map[uint8]*sign.Phase1ToPhase2Transmit)
		for i, output := range phase1SignOutputs {
			for receiver, msg := range output.Messages {
				if phase1ByReceiver[receiver] == nil {
					phase1ByReceiver[receiver] = make(map[uint8]*sign.Phase1ToPhase2Transmit)
				}
				phase1ByReceiver[receiver][signerParties[i].Index] = msg
			}
		}

		// Phase 2
		phase2SignOutputs := make([]*DKLS23SignPhase2Output, threshold)
		for i, sess := range sessions {
			received := phase1ByReceiver[signerParties[i].Index]
			output, err := sess.Phase2(received)
			if err != nil {
				t.Fatalf("signer %d failed sign phase 2: %v", i+1, err)
			}
			phase2SignOutputs[i] = output
		}

		// Collect phase 2 messages by receiver
		phase2ByReceiver := make(map[uint8]map[uint8]*sign.Phase2ToPhase3Transmit)
		for i, output := range phase2SignOutputs {
			for receiver, msg := range output.Messages {
				if phase2ByReceiver[receiver] == nil {
					phase2ByReceiver[receiver] = make(map[uint8]*sign.Phase2ToPhase3Transmit)
				}
				phase2ByReceiver[receiver][signerParties[i].Index] = msg
			}
		}

		// Phase 3
		phase3SignOutputs := make([]*DKLS23SignPhase3Output, threshold)
		for i, sess := range sessions {
			received := phase2ByReceiver[signerParties[i].Index]
			output, err := sess.Phase3(received)
			if err != nil {
				t.Fatalf("signer %d failed sign phase 3: %v", i+1, err)
			}
			phase3SignOutputs[i] = output
		}

		// Collect all broadcasts
		broadcasts := make([]*sign.Phase3Broadcast, threshold)
		for i, output := range phase3SignOutputs {
			broadcasts[i] = output.Broadcast
		}

		// Phase 4
		sig, err := sessions[0].Phase4(broadcasts, true)
		if err != nil {
			t.Fatalf("failed to finalize signature: %v", err)
		}

		if sig == nil {
			t.Fatal("signature is nil")
		}

		// Basic sanity checks on signature
		if sig.R == [32]byte{} {
			t.Error("signature R is zero")
		}
		if sig.S == [32]byte{} {
			t.Error("signature S is zero")
		}
	})
}

func TestDKLS23QuickSign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKLS23 DKG test in short mode")
	}

	threshold := uint8(2)
	total := uint8(3)
	sessionID := []byte("quick-sign-test!")

	// Run DKG
	parties := runDKLS23DKG(t, threshold, total, sessionID)

	// Use QuickSign with threshold parties
	messageHash := DKLS23MessageHash([]byte("quick sign test"))
	signID := []byte("sign-1")

	sig, err := DKLS23QuickSign(parties[:threshold], messageHash, signID, true)
	if err != nil {
		t.Fatalf("QuickSign failed: %v", err)
	}

	if sig == nil {
		t.Fatal("signature is nil")
	}
}

func TestDKLS23ParticipantValidation(t *testing.T) {
	sessionID := []byte("test-session-val")

	// Index too low
	_, err := NewDKLS23Participant(2, 3, 0, sessionID)
	if err == nil {
		t.Error("should reject index of 0")
	}

	// Index too high
	_, err = NewDKLS23Participant(2, 3, 4, sessionID)
	if err == nil {
		t.Error("should reject index greater than total")
	}

	// Threshold too low
	_, err = NewDKLS23Participant(1, 3, 1, sessionID)
	if err == nil {
		t.Error("should reject threshold of 1")
	}

	// Threshold too high
	_, err = NewDKLS23Participant(4, 3, 1, sessionID)
	if err == nil {
		t.Error("should reject threshold greater than total")
	}

	// Valid parameters
	for i := uint8(1); i <= 3; i++ {
		_, err := NewDKLS23Participant(2, 3, i, sessionID)
		if err != nil {
			t.Errorf("should accept index %d", i)
		}
	}
}

func TestDKLS23SigningSessionValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKLS23 DKG test in short mode")
	}

	threshold := uint8(2)
	total := uint8(3)
	sessionID := []byte("validation-test!")

	parties := runDKLS23DKG(t, threshold, total, sessionID)

	messageHash := DKLS23MessageHash([]byte("test"))
	signID := []byte("sign-1")

	// Wrong number of counterparties
	_, err := NewDKLS23SigningSession(parties[0], messageHash, signID, []uint8{2, 3})
	if err == nil {
		t.Error("should reject wrong number of counterparties")
	}

	// Counterparty includes self
	_, err = NewDKLS23SigningSession(parties[0], messageHash, signID, []uint8{1})
	if err == nil {
		t.Error("should reject counterparty list including self")
	}

	// Invalid counterparty index
	_, err = NewDKLS23SigningSession(parties[0], messageHash, signID, []uint8{5})
	if err == nil {
		t.Error("should reject invalid counterparty index")
	}

	// Valid session
	_, err = NewDKLS23SigningSession(parties[0], messageHash, signID, []uint8{2})
	if err != nil {
		t.Errorf("should accept valid parameters: %v", err)
	}
}

func TestDKLS23PhaseOrdering(t *testing.T) {
	sessionID := []byte("phase-order-test")

	p, _ := NewDKLS23Participant(2, 3, 1, sessionID)

	// Phase 2 before phase 1 should fail
	_, err := p.DKGPhase2(nil)
	if err == nil {
		t.Error("should fail phase 2 before phase 1")
	}

	// Phase 3 before phase 1 should fail
	_, err = p.DKGPhase3()
	if err == nil {
		t.Error("should fail phase 3 before phase 1")
	}

	// Phase 1 should succeed
	_, err = p.DKGPhase1()
	if err != nil {
		t.Fatalf("phase 1 failed: %v", err)
	}

	// Duplicate phase 1 should fail
	_, err = p.DKGPhase1()
	if err == nil {
		t.Error("should not allow duplicate phase 1")
	}
}

func TestDKLS23SetParty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKLS23 DKG test in short mode")
	}

	threshold := uint8(2)
	total := uint8(3)
	sessionID := []byte("set-party-test!!")

	// Run DKG
	parties := runDKLS23DKG(t, threshold, total, sessionID)

	// Create new participant and set party (simulating restore)
	restored, _ := NewDKLS23Participant(threshold, total, 1, sessionID)
	if err := restored.SetParty(parties[0]); err != nil {
		t.Fatalf("failed to set party: %v", err)
	}

	if restored.Party() == nil {
		t.Error("party should not be nil after SetParty")
	}

	// Should be able to sign with restored participant
	messageHash := DKLS23MessageHash([]byte("restored test"))
	signID := []byte("sign-restored")

	// Use restored party and party 2
	signingParties := []*sign.Party{restored.Party(), parties[1]}
	sig, err := DKLS23QuickSign(signingParties, messageHash, signID, true)
	if err != nil {
		t.Fatalf("signing with restored party failed: %v", err)
	}

	if sig == nil {
		t.Error("signature should not be nil")
	}
}

// Helper function to run full DKG
func runDKLS23DKG(t *testing.T, threshold, total uint8, sessionID []byte) []*sign.Party {
	t.Helper()

	participants := make([]*DKLS23Participant, total)
	for i := uint8(1); i <= total; i++ {
		p, err := NewDKLS23Participant(threshold, total, i, sessionID)
		if err != nil {
			t.Fatalf("failed to create participant %d: %v", i, err)
		}
		participants[i-1] = p
	}

	// Phase 1
	phase1Outputs := make([]*DKLS23DKGPhase1Output, total)
	for i, p := range participants {
		output, err := p.DKGPhase1()
		if err != nil {
			t.Fatalf("participant %d failed phase 1: %v", i+1, err)
		}
		phase1Outputs[i] = output
	}

	// Phase 2
	phase2Outputs := make([]*DKLS23DKGPhase2Output, total)
	for i, p := range participants {
		polyPoints := make(map[uint8]group.Scalar)
		for j, output := range phase1Outputs {
			if i == j {
				continue
			}
			polyPoints[uint8(j+1)] = output.PolyPoints[i]
		}

		output, err := p.DKGPhase2(polyPoints)
		if err != nil {
			t.Fatalf("participant %d failed phase 2: %v", i+1, err)
		}
		phase2Outputs[i] = output
	}

	// Phase 3
	phase3Outputs := make([]*DKLS23DKGPhase3Output, total)
	for i, p := range participants {
		output, err := p.DKGPhase3()
		if err != nil {
			t.Fatalf("participant %d failed phase 3: %v", i+1, err)
		}
		phase3Outputs[i] = output
	}

	// Phase 4
	parties := make([]*sign.Party, total)
	for i, p := range participants {
		proofCommitments := make([]*dkg.ProofCommitment, total)
		for j, output := range phase2Outputs {
			proofCommitments[j] = output.ProofCommitment
		}

		zeroCommitments := make([]*dkg.Phase2to4ZeroTransmit, 0, total-1)
		for j, output := range phase2Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.ZeroCommitments[uint8(i+1)]; ok {
				zeroCommitments = append(zeroCommitments, msg)
			}
		}

		zeroSeeds := make([]*dkg.Phase3to4ZeroTransmit, 0, total-1)
		for j, output := range phase3Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.ZeroSeeds[uint8(i+1)]; ok {
				zeroSeeds = append(zeroSeeds, msg)
			}
		}

		mulInit := make([]*dkg.Phase3to4MulTransmit, 0, total-1)
		for j, output := range phase3Outputs {
			if i == j {
				continue
			}
			if msg, ok := output.MulInit[uint8(i+1)]; ok {
				mulInit = append(mulInit, msg)
			}
		}

		err := p.DKGPhase4(&DKLS23DKGPhase4Input{
			ProofCommitments: proofCommitments,
			ZeroCommitments:  zeroCommitments,
			ZeroSeeds:        zeroSeeds,
			MulInit:          mulInit,
		})
		if err != nil {
			t.Fatalf("participant %d failed phase 4: %v", i+1, err)
		}

		parties[i] = p.Party()
	}

	return parties
}

// Helper to compare points
func pointsEqual(a, b group.Point) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	aBytes := a.Bytes()
	bBytes := b.Bytes()
	if len(aBytes) != len(bBytes) {
		return false
	}
	for i := range aBytes {
		if aBytes[i] != bBytes[i] {
			return false
		}
	}
	return true
}
