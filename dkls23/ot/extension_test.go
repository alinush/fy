package ot

import (
	"testing"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

func TestOTExtensionInit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT test in short mode")
	}
	sessionID := []byte("test-ot-extension-init")

	// Extension Sender Phase 1 (acts as base OT receiver)
	otReceiver, correlation, vecR, encProofs, err := InitExtSenderPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitExtSenderPhase1 failed: %v", err)
	}

	if len(correlation) != Kappa {
		t.Errorf("Expected %d correlation bits, got %d", Kappa, len(correlation))
	}
	if len(vecR) != Kappa {
		t.Errorf("Expected %d scalars, got %d", Kappa, len(vecR))
	}
	if len(encProofs) != Kappa {
		t.Errorf("Expected %d proofs, got %d", Kappa, len(encProofs))
	}

	// Extension Receiver Phase 1 (acts as base OT sender)
	otSender, dlogProof, err := InitExtReceiverPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitExtReceiverPhase1 failed: %v", err)
	}
	if dlogProof == nil {
		t.Fatal("dlogProof is nil")
	}

	// Extension Receiver Phase 2
	extReceiver, err := InitExtReceiverPhase2(otSender, sessionID, otReceiver.GetSeed(), encProofs)
	if err != nil {
		t.Fatalf("InitExtReceiverPhase2 failed: %v", err)
	}
	if len(extReceiver.Seeds0) != Kappa {
		t.Errorf("Expected %d seeds0, got %d", Kappa, len(extReceiver.Seeds0))
	}

	// Extension Sender Phase 2
	extSender, err := InitExtSenderPhase2(otReceiver, sessionID, correlation, vecR, dlogProof)
	if err != nil {
		t.Fatalf("InitExtSenderPhase2 failed: %v", err)
	}
	if len(extSender.Seeds) != Kappa {
		t.Errorf("Expected %d seeds, got %d", Kappa, len(extSender.Seeds))
	}
}

func TestOTExtensionFullProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT test in short mode")
	}
	sessionID := []byte("test-ot-extension-full")

	// Initialize base OT
	otReceiver, correlation, vecR, encProofs, err := InitExtSenderPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitExtSenderPhase1 failed: %v", err)
	}

	otSender, dlogProof, err := InitExtReceiverPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitExtReceiverPhase1 failed: %v", err)
	}

	extReceiver, err := InitExtReceiverPhase2(otSender, sessionID, otReceiver.GetSeed(), encProofs)
	if err != nil {
		t.Fatalf("InitExtReceiverPhase2 failed: %v", err)
	}

	extSender, err := InitExtSenderPhase2(otReceiver, sessionID, correlation, vecR, dlogProof)
	if err != nil {
		t.Fatalf("InitExtSenderPhase2 failed: %v", err)
	}

	// Create choice bits (BatchSize bits)
	choiceBits := make([]bool, BatchSize)
	randBytes, _ := dkls23.RandBytes(BatchSize / 8)
	for i := 0; i < BatchSize; i++ {
		choiceBits[i] = (randBytes[i/8]>>(i%8))&1 == 1
	}

	// Run receiver phase 1
	extendedSeeds, dataToSender := extReceiver.RunPhase1(sessionID, choiceBits)
	if len(extendedSeeds) != Kappa {
		t.Errorf("Expected %d extended seeds, got %d", Kappa, len(extendedSeeds))
	}
	if len(dataToSender.U) != Kappa {
		t.Errorf("Expected %d U values, got %d", Kappa, len(dataToSender.U))
	}

	// Create random correlations for sender
	otWidth := uint8(1)
	inputCorrelations := make([][]group.Scalar, otWidth)
	for i := uint8(0); i < otWidth; i++ {
		inputCorrelations[i] = make([]group.Scalar, BatchSize)
		for j := 0; j < BatchSize; j++ {
			inputCorrelations[i][j], _ = dkls23.RandomScalar()
		}
	}

	// Run sender
	vectorOfV0, vectorOfTau, err := extSender.Run(sessionID, otWidth, inputCorrelations, dataToSender)
	if err != nil {
		t.Fatalf("ExtSender.Run failed: %v", err)
	}
	if len(vectorOfV0) != int(otWidth) {
		t.Errorf("Expected %d v0 vectors, got %d", otWidth, len(vectorOfV0))
	}
	if len(vectorOfTau) != int(otWidth) {
		t.Errorf("Expected %d tau vectors, got %d", otWidth, len(vectorOfTau))
	}

	// Run receiver phase 2
	vectorOfTB, err := extReceiver.RunPhase2(sessionID, otWidth, choiceBits, extendedSeeds, vectorOfTau)
	if err != nil {
		t.Fatalf("ExtReceiver.RunPhase2 failed: %v", err)
	}
	if len(vectorOfTB) != int(otWidth) {
		t.Errorf("Expected %d tB vectors, got %d", otWidth, len(vectorOfTB))
	}

	// Verify correlation: for each j, if choice=0: t_b[j] = -v0[j]
	// if choice=1: t_b[j] = correlation[j] - v0[j]
	for iter := uint8(0); iter < otWidth; iter++ {
		for j := 0; j < BatchSize; j++ {
			expected := dkls23.ScalarNeg(vectorOfV0[iter][j])
			if choiceBits[j] {
				expected = dkls23.ScalarAdd(inputCorrelations[iter][j], expected)
			}
			if !dkls23.ScalarEqual(vectorOfTB[iter][j], expected) {
				t.Errorf("Correlation mismatch at iter=%d, j=%d, choice=%v", iter, j, choiceBits[j])
			}
		}
	}
}

func TestFieldMul(t *testing.T) {
	// Test zero multiplication
	zero := make([]byte, OTSecurity/8)
	one := make([]byte, OTSecurity/8)
	one[0] = 1

	result := fieldMul(zero, one)
	for _, b := range result {
		if b != 0 {
			t.Error("0 * 1 should be 0")
			break
		}
	}

	// Test identity multiplication
	result = fieldMul(one, one)
	if result[0] != 1 {
		t.Error("1 * 1 should have first byte = 1")
	}
	for i := 1; i < len(result); i++ {
		if result[i] != 0 {
			t.Errorf("1 * 1 should have byte[%d] = 0, got %d", i, result[i])
		}
	}
}

func TestBitsToBytes(t *testing.T) {
	bits := []bool{true, false, true, false, false, false, false, true} // 0b10000101 = 133
	bytes := bitsToBytes(bits)
	if len(bytes) != 1 {
		t.Fatalf("Expected 1 byte, got %d", len(bytes))
	}
	if bytes[0] != 133 {
		t.Errorf("Expected 133, got %d", bytes[0])
	}

	// Test with more bits
	bits = []bool{true, true, true, true, true, true, true, true, false} // 255, then 0
	bytes = bitsToBytes(bits)
	if len(bytes) != 2 {
		t.Fatalf("Expected 2 bytes, got %d", len(bytes))
	}
	if bytes[0] != 255 || bytes[1] != 0 {
		t.Errorf("Expected [255, 0], got %v", bytes)
	}
}
