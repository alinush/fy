package dkls23_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/dkg"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

func TestSign2of2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKG/sign test in short mode")
	}

	// First, run DKG to get parties
	params := dkg.Parameters{Threshold: 2, ShareCount: 2}
	sessionID := []byte("test-sign-2of2")

	data1 := &dkg.SessionData{Parameters: params, PartyIndex: 1, SessionID: sessionID}
	data2 := &dkg.SessionData{Parameters: params, PartyIndex: 2, SessionID: sessionID}

	// DKG Phase 1
	out1_1, err := dkg.Phase1(data1)
	if err != nil {
		t.Fatalf("DKG Phase1 party 1 failed: %v", err)
	}
	out1_2, err := dkg.Phase1(data2)
	if err != nil {
		t.Fatalf("DKG Phase1 party 2 failed: %v", err)
	}

	fragments1 := []group.Scalar{out1_1.PolyPoints[0], out1_2.PolyPoints[0]}
	fragments2 := []group.Scalar{out1_1.PolyPoints[1], out1_2.PolyPoints[1]}

	// DKG Phase 2
	out2_1, err := dkg.Phase2(data1, fragments1)
	if err != nil {
		t.Fatalf("Phase2 party 1 failed: %v", err)
	}
	out2_2, err := dkg.Phase2(data2, fragments2)
	if err != nil {
		t.Fatalf("Phase2 party 2 failed: %v", err)
	}

	// DKG Phase 3
	out3_1, err := dkg.Phase3(data1, out2_1.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 1 failed: %v", err)
	}
	out3_2, err := dkg.Phase3(data2, out2_2.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 2 failed: %v", err)
	}

	proofsCommitments := []*dkg.ProofCommitment{out2_1.ProofCommitment, out2_2.ProofCommitment}

	// DKG Phase 4
	input1 := &dkg.Phase4Input{
		PolyPoint:         out2_1.PolyPoint,
		ProofsCommitments: proofsCommitments,
		ZeroKept:          out3_1.ZeroKeep,
		ZeroReceived2:     out2_2.ZeroTransmit,
		ZeroReceived3:     out3_2.ZeroTransmit,
		MulKept:           out3_1.MulKeep,
		MulReceived:       out3_2.MulTransmit,
	}
	input2 := &dkg.Phase4Input{
		PolyPoint:         out2_2.PolyPoint,
		ProofsCommitments: proofsCommitments,
		ZeroKept:          out3_2.ZeroKeep,
		ZeroReceived2:     out2_1.ZeroTransmit,
		ZeroReceived3:     out3_1.ZeroTransmit,
		MulKept:           out3_2.MulKeep,
		MulReceived:       out3_1.MulTransmit,
	}

	party1, err := dkg.Phase4(data1, input1)
	if err != nil {
		t.Fatalf("DKG Phase4 party 1 failed: %v", err)
	}
	party2, err := dkg.Phase4(data2, input2)
	if err != nil {
		t.Fatalf("DKG Phase4 party 2 failed: %v", err)
	}

	if !dkls23.PointEqual(party1.PublicKey, party2.PublicKey) {
		t.Fatal("DKG produced different public keys")
	}
	t.Logf("DKG successful, public key generated")

	// Now test signing
	messageHash := dkls23.Hash([]byte("test message"), nil)
	signID := []byte("sign-session-1")

	signData1 := &sign.SignData{
		SignID:         signID,
		Counterparties: []uint8{2},
		MessageHash:    messageHash,
	}
	signData2 := &sign.SignData{
		SignID:         signID,
		Counterparties: []uint8{1},
		MessageHash:    messageHash,
	}

	// Sign Phase 1
	uniqueKeep1_1, keep1_1, transmit1_1, err := party1.Phase1(signData1)
	if err != nil {
		t.Fatalf("Sign Phase1 party 1 failed: %v", err)
	}
	uniqueKeep1_2, keep1_2, transmit1_2, err := party2.Phase1(signData2)
	if err != nil {
		t.Fatalf("Sign Phase1 party 2 failed: %v", err)
	}

	t.Logf("Sign Phase1 complete: party1 sent %d messages, party2 sent %d messages",
		len(transmit1_1), len(transmit1_2))

	// Sign Phase 2
	uniqueKeep2_1, keep2_1, transmit2_1, err := party1.Phase2(signData1, uniqueKeep1_1, keep1_1, transmit1_2)
	if err != nil {
		t.Fatalf("Sign Phase2 party 1 failed: %v", err)
	}
	uniqueKeep2_2, keep2_2, transmit2_2, err := party2.Phase2(signData2, uniqueKeep1_2, keep1_2, transmit1_1)
	if err != nil {
		t.Fatalf("Sign Phase2 party 2 failed: %v", err)
	}

	t.Logf("Sign Phase2 complete")

	// Sign Phase 3
	xCoord1, broadcast1, err := party1.Phase3(signData1, uniqueKeep2_1, keep2_1, transmit2_2)
	if err != nil {
		t.Fatalf("Sign Phase3 party 1 failed: %v", err)
	}
	xCoord2, broadcast2, err := party2.Phase3(signData2, uniqueKeep2_2, keep2_2, transmit2_1)
	if err != nil {
		t.Fatalf("Sign Phase3 party 2 failed: %v", err)
	}

	t.Logf("Sign Phase3 complete: xCoord1=%x, xCoord2=%x", xCoord1[:8], xCoord2[:8])

	// Verify xCoords match
	if string(xCoord1) != string(xCoord2) {
		t.Fatalf("xCoords don't match!")
	}

	// Sign Phase 4 - both parties need ALL broadcasts (including their own)
	allBroadcasts := []*sign.Phase3Broadcast{broadcast1, broadcast2}

	sig1, err := party1.Phase4(signData1, xCoord1, allBroadcasts, true)
	if err != nil {
		t.Fatalf("Sign Phase4 party 1 failed: %v", err)
	}

	sig2, err := party2.Phase4(signData2, xCoord2, allBroadcasts, true)
	if err != nil {
		t.Fatalf("Sign Phase4 party 2 failed: %v", err)
	}

	t.Logf("Sign Phase4 complete!")
	t.Logf("Signature: r=%x, s=%x, v=%d", sig1.R, sig1.S, sig1.RecoveryID)

	// Verify both parties got the same signature
	if sig1.R != sig2.R || sig1.S != sig2.S {
		t.Fatal("Signatures don't match!")
	}

	// Verify with ecrecover - the recovered address should match the DKG public key
	// Compute expected address from DKG public key
	compressedPubKey := dkls23.PointToBytes(party1.PublicKey)
	expectedPubKey, err := crypto.DecompressPubkey(compressedPubKey)
	if err != nil {
		t.Fatalf("Failed to decompress pubkey: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(*expectedPubKey)
	t.Logf("Expected address from DKG: %s", expectedAddr.Hex())

	// Build signature for ecrecover (R || S || V)
	ecSig := make([]byte, 65)
	copy(ecSig[0:32], sig1.R[:])
	copy(ecSig[32:64], sig1.S[:])
	ecSig[64] = sig1.RecoveryID

	// Recover public key from signature
	recoveredPubKey, err := crypto.Ecrecover(messageHash[:], ecSig)
	if err != nil {
		t.Fatalf("Ecrecover failed: %v", err)
	}

	// Verify signature (R || S only, no recovery ID)
	if !crypto.VerifySignature(recoveredPubKey, messageHash[:], ecSig[:64]) {
		t.Fatal("Signature verification failed!")
	}

	// Convert recovered public key to address
	recoveredECDSA, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		t.Fatalf("UnmarshalPubkey failed: %v", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredECDSA)
	t.Logf("Recovered address from signature: %s", recoveredAddr.Hex())

	// Verify addresses match
	if recoveredAddr != expectedAddr {
		t.Fatalf("Address mismatch! Expected %s, got %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}

	t.Logf("Test passed: ecrecover returns correct address!")
}

func TestSign2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive DKG/sign test in short mode")
	}

	// === 2-of-3 DKG ===
	params := dkg.Parameters{Threshold: 2, ShareCount: 3}
	sessionID := []byte("test-sign-2of3")

	data := make([]*dkg.SessionData, 3)
	for i := range 3 {
		data[i] = &dkg.SessionData{Parameters: params, PartyIndex: uint8(i + 1), SessionID: sessionID}
	}

	// Phase 1
	phase1Out := make([]*dkg.Phase1Output, 3)
	for i := range 3 {
		var err error
		phase1Out[i], err = dkg.Phase1(data[i])
		if err != nil {
			t.Fatalf("DKG Phase1 party %d failed: %v", i+1, err)
		}
	}

	// Gather fragments
	fragments := make([][]group.Scalar, 3)
	for i := range 3 {
		fragments[i] = make([]group.Scalar, 3)
		for j := range 3 {
			fragments[i][j] = phase1Out[j].PolyPoints[i]
		}
	}

	// Phase 2
	phase2Out := make([]*dkg.Phase2Output, 3)
	for i := range 3 {
		var err error
		phase2Out[i], err = dkg.Phase2(data[i], fragments[i])
		if err != nil {
			t.Fatalf("DKG Phase2 party %d failed: %v", i+1, err)
		}
	}

	// Phase 3
	phase3Out := make([]*dkg.Phase3Output, 3)
	for i := range 3 {
		var err error
		phase3Out[i], err = dkg.Phase3(data[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("DKG Phase3 party %d failed: %v", i+1, err)
		}
	}

	proofsCommitments := make([]*dkg.ProofCommitment, 3)
	for i := range 3 {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Phase 4
	parties := make([]*sign.Party, 3)
	for i := range 3 {
		zeroReceived2 := make([]*dkg.Phase2to4ZeroTransmit, 0)
		zeroReceived3 := make([]*dkg.Phase3to4ZeroTransmit, 0)
		mulReceived := make([]*dkg.Phase3to4MulTransmit, 0)

		for j := range 3 {
			if i == j {
				continue
			}
			for _, msg := range phase2Out[j].ZeroTransmit {
				if msg.Receiver == uint8(i+1) {
					zeroReceived2 = append(zeroReceived2, msg)
				}
			}
			for _, msg := range phase3Out[j].ZeroTransmit {
				if msg.Receiver == uint8(i+1) {
					zeroReceived3 = append(zeroReceived3, msg)
				}
			}
			for _, msg := range phase3Out[j].MulTransmit {
				if msg.Receiver == uint8(i+1) {
					mulReceived = append(mulReceived, msg)
				}
			}
		}

		input := &dkg.Phase4Input{
			PolyPoint:         phase2Out[i].PolyPoint,
			ProofsCommitments: proofsCommitments,
			ZeroKept:          phase3Out[i].ZeroKeep,
			ZeroReceived2:     zeroReceived2,
			ZeroReceived3:     zeroReceived3,
			MulKept:           phase3Out[i].MulKeep,
			MulReceived:       mulReceived,
		}

		var err error
		parties[i], err = dkg.Phase4(data[i], input)
		if err != nil {
			t.Fatalf("DKG Phase4 party %d failed: %v", i+1, err)
		}
	}

	// Verify all parties have the same public key
	for i := 1; i < 3; i++ {
		if !dkls23.PointEqual(parties[0].PublicKey, parties[i].PublicKey) {
			t.Fatalf("Party %d has different public key", i+1)
		}
	}
	t.Logf("DKG 2-of-3 successful")

	// === Sign with parties 1 and 2 (subset of 3) ===
	messageHash := dkls23.Hash([]byte("test message 2of3"), nil)
	signID := []byte("sign-2of3-session")

	party1 := parties[0] // index 1
	party2 := parties[1] // index 2

	signData1 := &sign.SignData{
		SignID:         signID,
		Counterparties: []uint8{2},
		MessageHash:    messageHash,
	}
	signData2 := &sign.SignData{
		SignID:         signID,
		Counterparties: []uint8{1},
		MessageHash:    messageHash,
	}

	// Sign Phase 1
	uniqueKeep1_1, keep1_1, transmit1_1, err := party1.Phase1(signData1)
	if err != nil {
		t.Fatalf("Sign Phase1 party 1 failed: %v", err)
	}
	uniqueKeep1_2, keep1_2, transmit1_2, err := party2.Phase1(signData2)
	if err != nil {
		t.Fatalf("Sign Phase1 party 2 failed: %v", err)
	}

	// Sign Phase 2
	uniqueKeep2_1, keep2_1, transmit2_1, err := party1.Phase2(signData1, uniqueKeep1_1, keep1_1, transmit1_2)
	if err != nil {
		t.Fatalf("Sign Phase2 party 1 failed: %v", err)
	}
	uniqueKeep2_2, keep2_2, transmit2_2, err := party2.Phase2(signData2, uniqueKeep1_2, keep1_2, transmit1_1)
	if err != nil {
		t.Fatalf("Sign Phase2 party 2 failed: %v", err)
	}

	// Sign Phase 3
	xCoord1, broadcast1, err := party1.Phase3(signData1, uniqueKeep2_1, keep2_1, transmit2_2)
	if err != nil {
		t.Fatalf("Sign Phase3 party 1 failed: %v", err)
	}
	xCoord2, broadcast2, err := party2.Phase3(signData2, uniqueKeep2_2, keep2_2, transmit2_1)
	if err != nil {
		t.Fatalf("Sign Phase3 party 2 failed: %v", err)
	}

	if string(xCoord1) != string(xCoord2) {
		t.Fatalf("xCoords don't match")
	}

	// Sign Phase 4
	allBroadcasts := []*sign.Phase3Broadcast{broadcast1, broadcast2}

	sig1, err := party1.Phase4(signData1, xCoord1, allBroadcasts, true)
	if err != nil {
		t.Fatalf("Sign Phase4 party 1 failed: %v", err)
	}
	sig2, err := party2.Phase4(signData2, xCoord2, allBroadcasts, true)
	if err != nil {
		t.Fatalf("Sign Phase4 party 2 failed: %v", err)
	}

	if sig1.R != sig2.R || sig1.S != sig2.S {
		t.Fatal("Signatures don't match")
	}

	// Verify with ecrecover
	compressedPubKey := dkls23.PointToBytes(party1.PublicKey)
	expectedPubKey, err := crypto.DecompressPubkey(compressedPubKey)
	if err != nil {
		t.Fatalf("Failed to decompress pubkey: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(*expectedPubKey)

	ecSig := make([]byte, 65)
	copy(ecSig[0:32], sig1.R[:])
	copy(ecSig[32:64], sig1.S[:])
	ecSig[64] = sig1.RecoveryID

	recoveredPubKey, err := crypto.Ecrecover(messageHash[:], ecSig)
	if err != nil {
		t.Fatalf("Ecrecover failed: %v", err)
	}
	if !crypto.VerifySignature(recoveredPubKey, messageHash[:], ecSig[:64]) {
		t.Fatal("Signature verification failed")
	}
	recoveredECDSA, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		t.Fatalf("UnmarshalPubkey failed: %v", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredECDSA)

	if recoveredAddr != expectedAddr {
		t.Fatalf("Address mismatch: expected %s, got %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}

	t.Logf("2-of-3 signing test passed: ecrecover returns correct address!")
}
