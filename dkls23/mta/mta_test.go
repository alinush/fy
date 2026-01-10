package mta

import (
	"testing"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

func TestMultiplication(t *testing.T) {
	sessionID := []byte("test-multiplication")

	// INITIALIZATION

	// Phase 1 - Receiver
	otSender, dlogProof, nonce, err := InitReceiverPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitReceiverPhase1 failed: %v", err)
	}

	// Phase 1 - Sender
	otReceiver, correlation, vecR, encProofs, err := InitSenderPhase1(sessionID)
	if err != nil {
		t.Fatalf("InitSenderPhase1 failed: %v", err)
	}

	// Communication: Exchange proofs and seed
	seed := otReceiver.GetSeed()

	// Phase 2 - Receiver
	mulReceiver, err := InitReceiverPhase2(otSender, sessionID, seed, encProofs, nonce)
	if err != nil {
		t.Fatalf("InitReceiverPhase2 failed: %v", err)
	}

	// Phase 2 - Sender
	mulSender, err := InitSenderPhase2(otReceiver, sessionID, correlation, vecR, dlogProof, nonce)
	if err != nil {
		t.Fatalf("InitSenderPhase2 failed: %v", err)
	}

	// PROTOCOL

	// Sample sender's input
	senderInput := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		senderInput[i], _ = dkls23.RandomScalar()
	}

	// Phase 1 - Receiver (starts the protocol)
	receiverRandom, dataToKeep, dataToSender := mulReceiver.RunPhase1(sessionID)

	// Communication round 1: Receiver sends dataToSender

	// Sender runs its protocol
	senderOutput, dataToReceiver, err := mulSender.Run(sessionID, senderInput, dataToSender)
	if err != nil {
		t.Fatalf("Sender.Run failed: %v", err)
	}

	// Communication round 2: Sender sends dataToReceiver

	// Phase 2 - Receiver
	receiverOutput, err := mulReceiver.RunPhase2(sessionID, dataToKeep, dataToReceiver)
	if err != nil {
		t.Fatalf("Receiver.RunPhase2 failed: %v", err)
	}

	// VERIFICATION
	// The sum of outputs should equal: sender_input[i] * receiver_random
	for i := 0; i < L; i++ {
		sum := dkls23.ScalarAdd(senderOutput[i], receiverOutput[i])
		expected := dkls23.ScalarMul(senderInput[i], receiverRandom)
		if !dkls23.ScalarEqual(sum, expected) {
			t.Errorf("Multiplication output[%d] incorrect: sum != input * random", i)
		}
	}
}
