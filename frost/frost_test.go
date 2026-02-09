package frost

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/secp256k1"
)

func TestDKGAndSign(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("DKG", func(t *testing.T) {
		// Create participants
		participants := make([]*Participant, total)
		for i := 0; i < total; i++ {
			p, err := f.NewParticipant(rand.Reader, i+1)
			if err != nil {
				t.Fatalf("failed to create participant %d: %v", i+1, err)
			}
			participants[i] = p
		}

		// Round 1: Each participant broadcasts commitments
		broadcasts := make([]*Round1Data, total)
		for i, p := range participants {
			broadcasts[i] = p.Round1Broadcast()
		}

		// Round 1: Each participant sends private shares to others
		for i, sender := range participants {
			for j := 0; j < total; j++ {
				if i == j {
					continue // don't send to self
				}
				privateData := f.Round1PrivateSend(sender, j+1)

				// Recipient receives and verifies
				err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
				if err != nil {
					t.Fatalf("participant %d failed to verify share from %d: %v", j+1, i+1, err)
				}
			}
		}

		// Finalize: Each participant computes their key share
		keyShares := make([]*KeyShare, total)
		for i, p := range participants {
			ks, err := f.Finalize(p, broadcasts)
			if err != nil {
				t.Fatalf("participant %d failed to finalize: %v", i+1, err)
			}
			keyShares[i] = ks
		}

		// Verify all participants have the same group key
		for i := 1; i < total; i++ {
			if !keyShares[i].GroupKey.Equal(keyShares[0].GroupKey) {
				t.Error("participants have different group keys")
			}
		}

		t.Run("Sign", func(t *testing.T) {
			message := []byte("hello FROST")

			// Use first 'threshold' participants to sign
			signers := keyShares[:threshold]

			// Round 1: Generate nonces and commitments
			nonces := make([]*SigningNonce, threshold)
			commitments := make([]*SigningCommitment, threshold)
			for i, ks := range signers {
				n, c, err := f.SignRound1(rand.Reader, ks)
				if err != nil {
					t.Fatalf("signer %d failed round 1: %v", i+1, err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2: Generate signature shares
			sigShares := make([]*SignatureShare, threshold)
			for i, ks := range signers {
				ss, err := f.SignRound2(ks, nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("signer %d failed round 2: %v", i+1, err)
				}
				sigShares[i] = ss
			}

			// Aggregate signature
			sig, err := f.Aggregate(message, commitments, sigShares)
			if err != nil {
				t.Fatalf("failed to aggregate signature: %v", err)
			}

			// Verify signature
			if !f.Verify(message, sig, keyShares[0].GroupKey) {
				t.Error("signature verification failed")
			}

			// Verify with wrong message fails
			if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
				t.Error("signature should not verify with wrong message")
			}
		})
	})
}

func TestSigningWithDifferentSignerSubsets(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 4

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatal(err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < total; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatal(err)
		}
		keyShares[i] = ks
	}

	message := []byte("test message")

	// Test different signer subsets (minimal set for correctness)
	subsets := [][]int{
		{0, 1},       // threshold (participants 1 and 2)
		{1, 2, 3},    // threshold+1 (participants 2, 3, and 4)
		{0, 1, 2, 3}, // all participants
	}

	for _, subset := range subsets {
		t.Run(subsetName(subset), func(t *testing.T) {
			signers := make([]*KeyShare, len(subset))
			for i, idx := range subset {
				signers[i] = keyShares[idx]
			}

			// Round 1
			nonces := make([]*SigningNonce, len(signers))
			commitments := make([]*SigningCommitment, len(signers))
			for i, ks := range signers {
				n, c, err := f.SignRound1(rand.Reader, ks)
				if err != nil {
					t.Fatal(err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2
			sigShares := make([]*SignatureShare, len(signers))
			for i, ks := range signers {
				ss, err := f.SignRound2(ks, nonces[i], message, commitments)
				if err != nil {
					t.Fatal(err)
				}
				sigShares[i] = ss
			}

			// Aggregate
			sig, err := f.Aggregate(message, commitments, sigShares)
			if err != nil {
				t.Fatal(err)
			}

			// Verify
			if !f.Verify(message, sig, keyShares[0].GroupKey) {
				t.Error("signature verification failed")
			}
		})
	}
}

func subsetName(subset []int) string {
	name := "signers"
	for _, idx := range subset {
		name += fmt.Sprintf("_%d", idx+1)
	}
	return name
}

func TestSigningWithDifferentThresholds(t *testing.T) {
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

			// Run DKG
			participants := make([]*Participant, cfg.total)
			for i := 0; i < cfg.total; i++ {
				p, err := f.NewParticipant(rand.Reader, i+1)
				if err != nil {
					t.Fatal(err)
				}
				participants[i] = p
			}

			broadcasts := make([]*Round1Data, cfg.total)
			for i, p := range participants {
				broadcasts[i] = p.Round1Broadcast()
			}

			for i, sender := range participants {
				for j := 0; j < cfg.total; j++ {
					if i == j {
						continue
					}
					privateData := f.Round1PrivateSend(sender, j+1)
					if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
						t.Fatal(err)
					}
				}
			}

			keyShares := make([]*KeyShare, cfg.total)
			for i, p := range participants {
				ks, err := f.Finalize(p, broadcasts)
				if err != nil {
					t.Fatal(err)
				}
				keyShares[i] = ks
			}

			// Sign with exactly threshold signers
			message := []byte("threshold signing test")
			signers := keyShares[:cfg.threshold]

			nonces := make([]*SigningNonce, cfg.threshold)
			commitments := make([]*SigningCommitment, cfg.threshold)
			for i, ks := range signers {
				n, c, err := f.SignRound1(rand.Reader, ks)
				if err != nil {
					t.Fatal(err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			sigShares := make([]*SignatureShare, cfg.threshold)
			for i, ks := range signers {
				ss, err := f.SignRound2(ks, nonces[i], message, commitments)
				if err != nil {
					t.Fatal(err)
				}
				sigShares[i] = ss
			}

			sig, err := f.Aggregate(message, commitments, sigShares)
			if err != nil {
				t.Fatal(err)
			}

			if !f.Verify(message, sig, keyShares[0].GroupKey) {
				t.Error("signature verification failed")
			}
		})
	}
}

func TestSignatureVerificationFailures(t *testing.T) {
	g := &bjj.BJJ{}
	f, _ := New(g, 2, 3)

	// Run DKG
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		p, _ := f.NewParticipant(rand.Reader, i+1)
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, 3)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
		}
	}

	keyShares := make([]*KeyShare, 3)
	for i, p := range participants {
		keyShares[i], _ = f.Finalize(p, broadcasts)
	}

	// Create a valid signature
	message := []byte("original message")
	signers := keyShares[:2]

	nonces := make([]*SigningNonce, 2)
	commitments := make([]*SigningCommitment, 2)
	for i, ks := range signers {
		nonces[i], commitments[i], _ = f.SignRound1(rand.Reader, ks)
	}

	sigShares := make([]*SignatureShare, 2)
	for i, ks := range signers {
		sigShares[i], _ = f.SignRound2(ks, nonces[i], message, commitments)
	}

	sig, _ := f.Aggregate(message, commitments, sigShares)

	// Verify the valid signature works
	if !f.Verify(message, sig, keyShares[0].GroupKey) {
		t.Fatal("valid signature should verify")
	}

	t.Run("WrongMessage", func(t *testing.T) {
		if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
			t.Error("signature should not verify with wrong message")
		}
	})

	t.Run("WrongGroupKey", func(t *testing.T) {
		// Create a different group key by running another DKG
		f2, _ := New(g, 2, 3)
		p2, _ := f2.NewParticipant(rand.Reader, 1)
		wrongGroupKey := g.NewPoint().ScalarMult(p2.coefficients[0], g.Generator())

		if f.Verify(message, sig, wrongGroupKey) {
			t.Error("signature should not verify with wrong group key")
		}
	})

	t.Run("TamperedSignatureR", func(t *testing.T) {
		// Tamper with R component
		tamperedR := g.NewPoint().Add(sig.R, g.Generator())
		tamperedSig := &Signature{R: tamperedR, Z: sig.Z}

		if f.Verify(message, tamperedSig, keyShares[0].GroupKey) {
			t.Error("signature should not verify with tampered R")
		}
	})

	t.Run("TamperedSignatureZ", func(t *testing.T) {
		// Tamper with Z component
		one := g.NewScalar()
		one.SetBytes([]byte{1})
		tamperedZ := g.NewScalar().Add(sig.Z, one)
		tamperedSig := &Signature{R: sig.R, Z: tamperedZ}

		if f.Verify(message, tamperedSig, keyShares[0].GroupKey) {
			t.Error("signature should not verify with tampered Z")
		}
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		// Sign empty message
		emptyMsg := []byte{}

		nonces := make([]*SigningNonce, 2)
		commitments := make([]*SigningCommitment, 2)
		for i, ks := range signers {
			nonces[i], commitments[i], _ = f.SignRound1(rand.Reader, ks)
		}

		sigShares := make([]*SignatureShare, 2)
		for i, ks := range signers {
			sigShares[i], _ = f.SignRound2(ks, nonces[i], emptyMsg, commitments)
		}

		emptySig, _ := f.Aggregate(emptyMsg, commitments, sigShares)

		if !f.Verify(emptyMsg, emptySig, keyShares[0].GroupKey) {
			t.Error("empty message signature should verify")
		}

		// But original sig should not verify with empty message
		if f.Verify(emptyMsg, sig, keyShares[0].GroupKey) {
			t.Error("original signature should not verify with empty message")
		}
	})
}

func TestThresholdValidation(t *testing.T) {
	g := &bjj.BJJ{}

	t.Run("ThresholdTooLow", func(t *testing.T) {
		_, err := New(g, 1, 3)
		if err == nil {
			t.Error("expected error for threshold < 2")
		}
	})

	t.Run("TotalLessThanThreshold", func(t *testing.T) {
		_, err := New(g, 3, 2)
		if err == nil {
			t.Error("expected error for total < threshold")
		}
	})
}

func TestBlake2bHasher(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	// Use Blake2bHasher (Ledger compatible)
	f, err := NewWithHasher(g, threshold, total, NewBlake2bHasher())
	if err != nil {
		t.Fatal(err)
	}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatal(err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < total; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatal(err)
		}
		keyShares[i] = ks
	}

	// Sign with Blake2b hasher
	message := []byte("test message with blake2b")
	signers := keyShares[:threshold]

	nonces := make([]*SigningNonce, threshold)
	commitments := make([]*SigningCommitment, threshold)
	for i, ks := range signers {
		n, c, err := f.SignRound1(rand.Reader, ks)
		if err != nil {
			t.Fatal(err)
		}
		nonces[i] = n
		commitments[i] = c
	}

	sigShares := make([]*SignatureShare, threshold)
	for i, ks := range signers {
		ss, err := f.SignRound2(ks, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
		sigShares[i] = ss
	}

	sig, err := f.Aggregate(message, commitments, sigShares)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if !f.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("signature verification failed with Blake2b hasher")
	}

	// Verify wrong message fails
	if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
		t.Error("signature should not verify with wrong message")
	}

	// Verify that signature from Blake2b hasher doesn't verify with SHA256 hasher
	f2, _ := New(g, threshold, total)
	if f2.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("blake2b signature should not verify with sha256 hasher")
	}
}

func TestPoseidonHasher(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	// Use PoseidonHasher (zkSNARK optimized)
	f, err := NewWithHasher(g, threshold, total, NewPoseidonHasher())
	if err != nil {
		t.Fatal(err)
	}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatal(err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < total; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatal(err)
		}
		keyShares[i] = ks
	}

	// Sign with Poseidon hasher
	message := []byte("test message with poseidon")
	signers := keyShares[:threshold]

	nonces := make([]*SigningNonce, threshold)
	commitments := make([]*SigningCommitment, threshold)
	for i, ks := range signers {
		n, c, err := f.SignRound1(rand.Reader, ks)
		if err != nil {
			t.Fatal(err)
		}
		nonces[i] = n
		commitments[i] = c
	}

	sigShares := make([]*SignatureShare, threshold)
	for i, ks := range signers {
		ss, err := f.SignRound2(ks, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
		sigShares[i] = ss
	}

	sig, err := f.Aggregate(message, commitments, sigShares)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if !f.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("signature verification failed with Poseidon hasher")
	}

	// Verify wrong message fails
	if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
		t.Error("signature should not verify with wrong message")
	}

	// Verify that signature from Poseidon hasher doesn't verify with SHA256 hasher
	f2, _ := New(g, threshold, total)
	if f2.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("poseidon signature should not verify with sha256 hasher")
	}

	// Verify that signature from Poseidon hasher doesn't verify with Blake2b hasher
	f3, _ := NewWithHasher(g, threshold, total, NewBlake2bHasher())
	if f3.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("poseidon signature should not verify with blake2b hasher")
	}
}

func TestPoseidonHasherDomainSeparation(t *testing.T) {
	g := &bjj.BJJ{}
	h := NewPoseidonHasher()

	// Test that different hash functions produce different outputs for same input
	input := []byte("test input")

	h1 := h.H1(g, input, input, input)
	h2 := h.H2(g, make([]byte, 32), make([]byte, 32), input)
	h3 := h.H3(g, input, input, input)

	if h1.Equal(h3) {
		t.Error("H1 and H3 should produce different outputs (different domains)")
	}

	// H2 uses different input format, so comparison is less meaningful
	// but verify it's not zero
	if h2.IsZero() {
		t.Error("H2 should not produce zero")
	}

	// Test determinism
	h1Again := h.H1(g, input, input, input)
	if !h1.Equal(h1Again) {
		t.Error("H1 should be deterministic")
	}
}

func TestPoseidonHasherH4H5(t *testing.T) {
	g := &bjj.BJJ{}
	h := NewPoseidonHasher()

	// Test H4 and H5 produce 32-byte outputs
	msg := []byte("test message")
	commitList := []byte("commitment list data")

	h4Out := h.H4(g, msg)
	h5Out := h.H5(g, commitList)

	if len(h4Out) != 32 {
		t.Errorf("H4 should return 32 bytes, got %d", len(h4Out))
	}

	if len(h5Out) != 32 {
		t.Errorf("H5 should return 32 bytes, got %d", len(h5Out))
	}

	// Test that H4 and H5 produce different outputs for different domains
	h4WithCommit := h.H4(g, commitList)
	h5WithMsg := h.H5(g, msg)

	if string(h4Out) == string(h5WithMsg) {
		t.Error("H4(msg) should differ from H5(msg) due to domain separation")
	}

	if string(h4WithCommit) == string(h5Out) {
		t.Error("H4(commit) should differ from H5(commit) due to domain separation")
	}
}

func TestComputeGroupCommitment(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatal(err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < total; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatal(err)
		}
		keyShares[i] = ks
	}

	t.Run("EmptyCommitments", func(t *testing.T) {
		_, err := f.ComputeGroupCommitment([]byte("msg"), nil)
		if err != ErrInvalidCommitment {
			t.Errorf("expected ErrInvalidCommitment, got %v", err)
		}

		_, err = f.ComputeGroupCommitment([]byte("msg"), []*SigningCommitment{})
		if err != ErrInvalidCommitment {
			t.Errorf("expected ErrInvalidCommitment, got %v", err)
		}
	})

	t.Run("MatchesAggregateR", func(t *testing.T) {
		message := []byte("test group commitment")
		signers := keyShares[:threshold]

		// Generate nonces and commitments
		nonces := make([]*SigningNonce, threshold)
		commitments := make([]*SigningCommitment, threshold)
		for i, ks := range signers {
			n, c, err := f.SignRound1(rand.Reader, ks)
			if err != nil {
				t.Fatal(err)
			}
			nonces[i] = n
			commitments[i] = c
		}

		// Compute group commitment using the new function
		R, err := f.ComputeGroupCommitment(message, commitments)
		if err != nil {
			t.Fatalf("ComputeGroupCommitment failed: %v", err)
		}

		// Generate signature shares and aggregate
		sigShares := make([]*SignatureShare, threshold)
		for i, ks := range signers {
			ss, err := f.SignRound2(ks, nonces[i], message, commitments)
			if err != nil {
				t.Fatal(err)
			}
			sigShares[i] = ss
		}

		sig, err := f.Aggregate(message, commitments, sigShares)
		if err != nil {
			t.Fatal(err)
		}

		// Verify R from ComputeGroupCommitment matches R in the signature
		if !R.Equal(sig.R) {
			t.Error("ComputeGroupCommitment R does not match Aggregate R")
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		message := []byte("determinism test")
		signers := keyShares[:threshold]

		nonces := make([]*SigningNonce, threshold)
		commitments := make([]*SigningCommitment, threshold)
		for i, ks := range signers {
			n, c, err := f.SignRound1(rand.Reader, ks)
			if err != nil {
				t.Fatal(err)
			}
			nonces[i] = n
			commitments[i] = c
		}

		// Compute twice with same inputs
		R1, err := f.ComputeGroupCommitment(message, commitments)
		if err != nil {
			t.Fatal(err)
		}

		R2, err := f.ComputeGroupCommitment(message, commitments)
		if err != nil {
			t.Fatal(err)
		}

		if !R1.Equal(R2) {
			t.Error("ComputeGroupCommitment should be deterministic")
		}
	})

	t.Run("DifferentMessagesProduceDifferentR", func(t *testing.T) {
		signers := keyShares[:threshold]

		nonces := make([]*SigningNonce, threshold)
		commitments := make([]*SigningCommitment, threshold)
		for i, ks := range signers {
			n, c, err := f.SignRound1(rand.Reader, ks)
			if err != nil {
				t.Fatal(err)
			}
			nonces[i] = n
			commitments[i] = c
		}

		R1, err := f.ComputeGroupCommitment([]byte("message 1"), commitments)
		if err != nil {
			t.Fatal(err)
		}

		R2, err := f.ComputeGroupCommitment([]byte("message 2"), commitments)
		if err != nil {
			t.Fatal(err)
		}

		// Different messages should produce different binding factors, thus different R
		if R1.Equal(R2) {
			t.Error("different messages should produce different group commitments")
		}
	})

	t.Run("WithPoseidonHasher", func(t *testing.T) {
		fPoseidon, err := NewWithHasher(g, threshold, total, NewPoseidonHasher())
		if err != nil {
			t.Fatal(err)
		}

		// Run DKG with Poseidon
		pParticipants := make([]*Participant, total)
		for i := 0; i < total; i++ {
			p, err := fPoseidon.NewParticipant(rand.Reader, i+1)
			if err != nil {
				t.Fatal(err)
			}
			pParticipants[i] = p
		}

		pBroadcasts := make([]*Round1Data, total)
		for i, p := range pParticipants {
			pBroadcasts[i] = p.Round1Broadcast()
		}

		for i, sender := range pParticipants {
			for j := 0; j < total; j++ {
				if i == j {
					continue
				}
				privateData := fPoseidon.Round1PrivateSend(sender, j+1)
				if err := fPoseidon.Round2ReceiveShare(pParticipants[j], privateData, pBroadcasts[i].Commitments); err != nil {
					t.Fatal(err)
				}
			}
		}

		pKeyShares := make([]*KeyShare, total)
		for i, p := range pParticipants {
			ks, err := fPoseidon.Finalize(p, pBroadcasts)
			if err != nil {
				t.Fatal(err)
			}
			pKeyShares[i] = ks
		}

		message := []byte("poseidon group commitment test")
		signers := pKeyShares[:threshold]

		nonces := make([]*SigningNonce, threshold)
		commitments := make([]*SigningCommitment, threshold)
		for i, ks := range signers {
			n, c, err := fPoseidon.SignRound1(rand.Reader, ks)
			if err != nil {
				t.Fatal(err)
			}
			nonces[i] = n
			commitments[i] = c
		}

		R, err := fPoseidon.ComputeGroupCommitment(message, commitments)
		if err != nil {
			t.Fatalf("ComputeGroupCommitment with Poseidon failed: %v", err)
		}

		// Generate signature and verify R matches
		sigShares := make([]*SignatureShare, threshold)
		for i, ks := range signers {
			ss, err := fPoseidon.SignRound2(ks, nonces[i], message, commitments)
			if err != nil {
				t.Fatal(err)
			}
			sigShares[i] = ss
		}

		sig, err := fPoseidon.Aggregate(message, commitments, sigShares)
		if err != nil {
			t.Fatal(err)
		}

		if !R.Equal(sig.R) {
			t.Error("ComputeGroupCommitment R does not match Aggregate R with Poseidon hasher")
		}

		// Verify the signature is valid
		if !fPoseidon.Verify(message, sig, pKeyShares[0].GroupKey) {
			t.Error("signature verification failed")
		}
	})
}

func TestSecp256k1Hasher(t *testing.T) {
	g := secp256k1.New()
	threshold := 2
	total := 3

	// Use Secp256k1Hasher
	f, err := NewWithHasher(g, threshold, total, NewSecp256k1Hasher())
	if err != nil {
		t.Fatal(err)
	}

	// Run DKG
	participants := make([]*Participant, total)
	for i := 0; i < total; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatal(err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < total; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatal(err)
		}
		keyShares[i] = ks
	}

	// Verify all participants have the same group key
	for i := 1; i < total; i++ {
		if !keyShares[i].GroupKey.Equal(keyShares[0].GroupKey) {
			t.Error("participants have different group keys")
		}
	}

	// Sign with secp256k1 hasher
	message := []byte("test message with secp256k1")
	signers := keyShares[:threshold]

	nonces := make([]*SigningNonce, threshold)
	commitments := make([]*SigningCommitment, threshold)
	for i, ks := range signers {
		n, c, err := f.SignRound1(rand.Reader, ks)
		if err != nil {
			t.Fatal(err)
		}
		nonces[i] = n
		commitments[i] = c
	}

	sigShares := make([]*SignatureShare, threshold)
	for i, ks := range signers {
		ss, err := f.SignRound2(ks, nonces[i], message, commitments)
		if err != nil {
			t.Fatal(err)
		}
		sigShares[i] = ss
	}

	sig, err := f.Aggregate(message, commitments, sigShares)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if !f.Verify(message, sig, keyShares[0].GroupKey) {
		t.Error("signature verification failed with secp256k1 hasher")
	}

	// Verify wrong message fails
	if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
		t.Error("signature should not verify with wrong message")
	}
}

func TestDuplicateSignerIDsRejected(t *testing.T) {
	g := &bjj.BJJ{}
	f, _ := New(g, 2, 3)

	// Run DKG
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		p, _ := f.NewParticipant(rand.Reader, i+1)
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, 3)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
		}
	}

	keyShares := make([]*KeyShare, 3)
	for i, p := range participants {
		keyShares[i], _ = f.Finalize(p, broadcasts)
	}

	t.Run("DuplicateCommitmentIDs", func(t *testing.T) {
		// Generate nonces/commitments for signer 0
		nonce, commitment, err := f.SignRound1(rand.Reader, keyShares[0])
		if err != nil {
			t.Fatal(err)
		}

		// Create commitments list with duplicate IDs
		duplicateCommitments := []*SigningCommitment{commitment, commitment}

		// SignRound2 should reject duplicate signer IDs
		_, err = f.SignRound2(keyShares[0], nonce, []byte("test"), duplicateCommitments)
		if err == nil {
			t.Error("expected error for duplicate signer IDs in commitments")
		}
	})

	t.Run("EmptyCommitmentList", func(t *testing.T) {
		nonce, _, err := f.SignRound1(rand.Reader, keyShares[0])
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.SignRound2(keyShares[0], nonce, []byte("test"), []*SigningCommitment{})
		if err == nil {
			t.Error("expected error for empty commitment list")
		}
	})

	t.Run("OwnCommitmentMissing", func(t *testing.T) {
		// Generate nonces for signer 0 and 1
		nonce0, _, err := f.SignRound1(rand.Reader, keyShares[0])
		if err != nil {
			t.Fatal(err)
		}
		_, commitment1, err := f.SignRound1(rand.Reader, keyShares[1])
		if err != nil {
			t.Fatal(err)
		}
		_, commitment2, err := f.SignRound1(rand.Reader, keyShares[2])
		if err != nil {
			t.Fatal(err)
		}

		// Try to sign with signer 0's nonce but only signer 1 and 2's commitments
		_, err = f.SignRound2(keyShares[0], nonce0, []byte("test"), []*SigningCommitment{commitment1, commitment2})
		if err == nil {
			t.Error("expected error when own commitment is missing")
		}
	})
}

func TestSecp256k1WithDifferentThresholds(t *testing.T) {
	g := secp256k1.New()

	configs := []struct {
		threshold int
		total     int
	}{
		{2, 3},
	}

	for _, cfg := range configs {
		name := fmt.Sprintf("%d_of_%d", cfg.threshold, cfg.total)
		t.Run(name, func(t *testing.T) {
			f, err := NewWithHasher(g, cfg.threshold, cfg.total, NewSecp256k1Hasher())
			if err != nil {
				t.Fatal(err)
			}

			// Run DKG
			participants := make([]*Participant, cfg.total)
			for i := 0; i < cfg.total; i++ {
				p, err := f.NewParticipant(rand.Reader, i+1)
				if err != nil {
					t.Fatal(err)
				}
				participants[i] = p
			}

			broadcasts := make([]*Round1Data, cfg.total)
			for i, p := range participants {
				broadcasts[i] = p.Round1Broadcast()
			}

			for i, sender := range participants {
				for j := 0; j < cfg.total; j++ {
					if i == j {
						continue
					}
					privateData := f.Round1PrivateSend(sender, j+1)
					if err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments); err != nil {
						t.Fatal(err)
					}
				}
			}

			keyShares := make([]*KeyShare, cfg.total)
			for i, p := range participants {
				ks, err := f.Finalize(p, broadcasts)
				if err != nil {
					t.Fatal(err)
				}
				keyShares[i] = ks
			}

			// Sign with exactly threshold signers
			message := []byte("secp256k1 threshold signing test")
			signers := keyShares[:cfg.threshold]

			nonces := make([]*SigningNonce, cfg.threshold)
			commitments := make([]*SigningCommitment, cfg.threshold)
			for i, ks := range signers {
				n, c, err := f.SignRound1(rand.Reader, ks)
				if err != nil {
					t.Fatal(err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			sigShares := make([]*SignatureShare, cfg.threshold)
			for i, ks := range signers {
				ss, err := f.SignRound2(ks, nonces[i], message, commitments)
				if err != nil {
					t.Fatal(err)
				}
				sigShares[i] = ss
			}

			sig, err := f.Aggregate(message, commitments, sigShares)
			if err != nil {
				t.Fatal(err)
			}

			if !f.Verify(message, sig, keyShares[0].GroupKey) {
				t.Error("signature verification failed")
			}
		})
	}
}
