package ot

import (
	"slices"
	"testing"

	"github.com/f3rmion/fy/dkls23"
)

func TestDLogProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OT test in short mode")
	}

	sessionID := []byte("test-session-dlog")

	// Create a sender (which generates a DLogProof)
	sender, err := NewSender(sessionID)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	// Get the proof
	proof := sender.Phase1()

	// Verify the proof
	sid := slices.Concat(sessionID, []byte("DLogProof"))
	if !proof.Verify(sid) {
		t.Error("DLogProof verification failed")
	}

	// Verify point matches s * G
	expectedPoint := dkls23.ScalarBaseMult(sender.S)
	if !dkls23.PointEqual(proof.Point, expectedPoint) {
		t.Error("Proof point does not match s * G")
	}
}

func TestEncProof(t *testing.T) {
	sessionID := []byte("test-session-enc")

	// Create receiver
	receiver, err := NewReceiver()
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	// Test with choice bit = false
	_, proof0, err := receiver.Phase1(sessionID, false)
	if err != nil {
		t.Fatalf("Phase1 bit=false failed: %v", err)
	}

	sid := slices.Concat(sessionID, []byte("EncProof"))
	if !proof0.Verify(sid) {
		t.Error("EncProof verification failed for bit=false")
	}

	// Test with choice bit = true
	_, proof1, err := receiver.Phase1(sessionID, true)
	if err != nil {
		t.Fatalf("Phase1 bit=true failed: %v", err)
	}

	if !proof1.Verify(sid) {
		t.Error("EncProof verification failed for bit=true")
	}
}

func TestBaseOTFullProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OT test in short mode")
	}

	sessionID := []byte("test-session-ot")

	// Test for both choice bits
	for _, choiceBit := range []bool{false, true} {
		t.Run(boolToString(choiceBit), func(t *testing.T) {
			// Sender Phase 1: Generate secret and proof
			sender, err := NewSender(sessionID)
			if err != nil {
				t.Fatalf("NewSender failed: %v", err)
			}
			dlogProof := sender.Phase1()

			// Receiver Phase 1: Generate receiver data
			receiver, err := NewReceiver()
			if err != nil {
				t.Fatalf("NewReceiver failed: %v", err)
			}
			rScalar, encProof, err := receiver.Phase1(sessionID, choiceBit)
			if err != nil {
				t.Fatalf("Phase1 failed: %v", err)
			}

			// Receiver Phase 2 Step 1: Verify sender's proof
			z, err := receiver.Phase2Step1(sessionID, dlogProof)
			if err != nil {
				t.Fatalf("Phase2Step1 failed: %v", err)
			}

			// Sender Phase 2: Compute both messages
			m0, m1, err := sender.Phase2(sessionID, receiver.GetSeed(), encProof)
			if err != nil {
				t.Fatalf("Sender.Phase2 failed: %v", err)
			}

			// Receiver Phase 2 Step 2: Compute receiver's message
			mb := receiver.Phase2Step2(sessionID, rScalar, z)

			// Verify receiver gets the correct message based on choice bit
			if choiceBit {
				if mb != m1 {
					t.Error("Receiver with bit=true should get m1, but messages don't match")
				}
			} else {
				if mb != m0 {
					t.Error("Receiver with bit=false should get m0, but messages don't match")
				}
			}

			// Verify receiver does NOT get the other message
			if choiceBit {
				if mb == m0 {
					t.Error("Receiver with bit=true should NOT be able to compute m0")
				}
			} else {
				if mb == m1 {
					t.Error("Receiver with bit=false should NOT be able to compute m1")
				}
			}
		})
	}
}

func TestBaseOTBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OT test in short mode")
	}

	sessionID := []byte("test-session-ot-batch")

	// Create a batch of choice bits
	bits := []bool{false, true, true, false, true, false, false, true}
	batchSize := len(bits)

	// Sender Phase 1
	sender, err := NewSender(sessionID)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}
	dlogProof := sender.Phase1()

	// Receiver Phase 1 Batch
	receiver, err := NewReceiver()
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}
	vecR, vecProof, err := receiver.Phase1Batch(sessionID, bits)
	if err != nil {
		t.Fatalf("Phase1Batch failed: %v", err)
	}

	// Sender Phase 2 Batch
	vecM0, vecM1, err := sender.Phase2Batch(sessionID, receiver.GetSeed(), vecProof)
	if err != nil {
		t.Fatalf("Phase2Batch failed: %v", err)
	}

	// Receiver Phase 2 Batch
	vecMb, err := receiver.Phase2Batch(sessionID, vecR, dlogProof)
	if err != nil {
		t.Fatalf("Receiver.Phase2Batch failed: %v", err)
	}

	// Verify each result
	for i := 0; i < batchSize; i++ {
		if bits[i] {
			if vecMb[i] != vecM1[i] {
				t.Errorf("Batch OT[%d]: receiver with bit=true should get m1", i)
			}
		} else {
			if vecMb[i] != vecM0[i] {
				t.Errorf("Batch OT[%d]: receiver with bit=false should get m0", i)
			}
		}
	}
}

func boolToString(b bool) string {
	if b {
		return "bit_true"
	}
	return "bit_false"
}
