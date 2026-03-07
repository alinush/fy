package dkg

import (
	"testing"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

func TestStep1And2(t *testing.T) {
	params := &Parameters{Threshold: 2, ShareCount: 3}

	// Generate polynomial
	poly, err := Step1(params)
	if err != nil {
		t.Fatalf("Step1 failed: %v", err)
	}
	if len(poly) != int(params.Threshold) {
		t.Errorf("Expected polynomial of degree %d, got %d", params.Threshold, len(poly))
	}

	// Evaluate at all points
	points := Step2(params, poly)
	if len(points) != int(params.ShareCount) {
		t.Errorf("Expected %d points, got %d", params.ShareCount, len(points))
	}
}

func TestDKG2of2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}
	params := Parameters{Threshold: 2, ShareCount: 2}
	sessionID := []byte("test-dkg-2of2-pad")

	// Create session data for each party
	data1 := &SessionData{Parameters: params, PartyIndex: 1, SessionID: sessionID}
	data2 := &SessionData{Parameters: params, PartyIndex: 2, SessionID: sessionID}

	// Phase 1: Generate polynomial points
	out1_1, err := Phase1(data1)
	if err != nil {
		t.Fatalf("Phase1 party 1 failed: %v", err)
	}
	out1_2, err := Phase1(data2)
	if err != nil {
		t.Fatalf("Phase1 party 2 failed: %v", err)
	}

	// Communication: Exchange polynomial fragments
	// Party 1 receives: p1(1), p2(1)
	// Party 2 receives: p1(2), p2(2)
	fragments1 := []group.Scalar{out1_1.PolyPoints[0], out1_2.PolyPoints[0]}
	fragments2 := []group.Scalar{out1_1.PolyPoints[1], out1_2.PolyPoints[1]}

	// Phase 2: Compute poly_point and proof
	out2_1, err := Phase2(data1, fragments1)
	if err != nil {
		t.Fatalf("Phase2 party 1 failed: %v", err)
	}
	out2_2, err := Phase2(data2, fragments2)
	if err != nil {
		t.Fatalf("Phase2 party 2 failed: %v", err)
	}

	// Phase 3: Initialize zero shares and multiplication
	out3_1, err := Phase3(data1, out2_1.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 1 failed: %v", err)
	}
	out3_2, err := Phase3(data2, out2_2.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 2 failed: %v", err)
	}

	// Prepare proofs commitments
	proofsCommitments := []*ProofCommitment{out2_1.ProofCommitment, out2_2.ProofCommitment}

	// Phase 4: Finalize
	input1 := &Phase4Input{
		PolyPoint:         out2_1.PolyPoint,
		ProofsCommitments: proofsCommitments,
		ZeroKept:          out3_1.ZeroKeep,
		ZeroReceived2:     out2_2.ZeroTransmit,
		ZeroReceived3:     out3_2.ZeroTransmit,
		MulKept:           out3_1.MulKeep,
		MulReceived:       out3_2.MulTransmit,
	}
	input2 := &Phase4Input{
		PolyPoint:         out2_2.PolyPoint,
		ProofsCommitments: proofsCommitments,
		ZeroKept:          out3_2.ZeroKeep,
		ZeroReceived2:     out2_1.ZeroTransmit,
		ZeroReceived3:     out3_1.ZeroTransmit,
		MulKept:           out3_2.MulKeep,
		MulReceived:       out3_1.MulTransmit,
	}

	party1, err := Phase4(data1, input1)
	if err != nil {
		t.Fatalf("Phase4 party 1 failed: %v", err)
	}
	party2, err := Phase4(data2, input2)
	if err != nil {
		t.Fatalf("Phase4 party 2 failed: %v", err)
	}

	// Verify both parties have the same public key
	if !dkls23.PointEqual(party1.PublicKey, party2.PublicKey) {
		t.Error("Parties have different public keys")
	}

	// Verify parties have multiplication protocols initialized
	if len(party1.MulSenders) != 1 || len(party1.MulReceivers) != 1 {
		t.Error("Party 1 missing multiplication protocols")
	}
	if len(party2.MulSenders) != 1 || len(party2.MulReceivers) != 1 {
		t.Error("Party 2 missing multiplication protocols")
	}

	// Verify zero seeds are set up
	if len(party1.ZeroSeeds) != 1 || len(party2.ZeroSeeds) != 1 {
		t.Error("Zero seeds not properly initialized")
	}

	t.Logf("DKG 2-of-2 successful, public key generated")
}

func TestDKG2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}
	params := Parameters{Threshold: 2, ShareCount: 3}
	sessionID := []byte("test-dkg-2of3-pad")

	// Create session data for each party
	data := make([]*SessionData, 3)
	for i := 0; i < 3; i++ {
		data[i] = &SessionData{Parameters: params, PartyIndex: uint8(i + 1), SessionID: sessionID}
	}

	// Phase 1
	phase1Out := make([]*Phase1Output, 3)
	for i := 0; i < 3; i++ {
		var err error
		phase1Out[i], err = Phase1(data[i])
		if err != nil {
			t.Fatalf("Phase1 party %d failed: %v", i+1, err)
		}
	}

	// Gather fragments for each party
	fragments := make([][]group.Scalar, 3)
	for i := 0; i < 3; i++ {
		fragments[i] = make([]group.Scalar, 3)
		for j := 0; j < 3; j++ {
			fragments[i][j] = phase1Out[j].PolyPoints[i]
		}
	}

	// Phase 2
	phase2Out := make([]*Phase2Output, 3)
	for i := 0; i < 3; i++ {
		var err error
		phase2Out[i], err = Phase2(data[i], fragments[i])
		if err != nil {
			t.Fatalf("Phase2 party %d failed: %v", i+1, err)
		}
	}

	// Phase 3
	phase3Out := make([]*Phase3Output, 3)
	for i := 0; i < 3; i++ {
		var err error
		phase3Out[i], err = Phase3(data[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("Phase3 party %d failed: %v", i+1, err)
		}
	}

	// Gather proofs
	proofsCommitments := make([]*ProofCommitment, 3)
	for i := 0; i < 3; i++ {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Gather received messages for each party
	parties := make([]*Phase4Input, 3)
	for i := 0; i < 3; i++ {
		zeroReceived2 := make([]*Phase2to4ZeroTransmit, 0)
		zeroReceived3 := make([]*Phase3to4ZeroTransmit, 0)
		mulReceived := make([]*Phase3to4MulTransmit, 0)

		for j := 0; j < 3; j++ {
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

		parties[i] = &Phase4Input{
			PolyPoint:         phase2Out[i].PolyPoint,
			ProofsCommitments: proofsCommitments,
			ZeroKept:          phase3Out[i].ZeroKeep,
			ZeroReceived2:     zeroReceived2,
			ZeroReceived3:     zeroReceived3,
			MulKept:           phase3Out[i].MulKeep,
			MulReceived:       mulReceived,
		}
	}

	// Phase 4
	partyResults := make([]*Phase4Input, 3)
	var publicKey group.Point
	for i := 0; i < 3; i++ {
		party, err := Phase4(data[i], parties[i])
		if err != nil {
			t.Fatalf("Phase4 party %d failed: %v", i+1, err)
		}
		if i == 0 {
			publicKey = party.PublicKey
		} else {
			if !dkls23.PointEqual(party.PublicKey, publicKey) {
				t.Errorf("Party %d has different public key", i+1)
			}
		}
		partyResults[i] = parties[i]
	}

	t.Logf("DKG 2-of-3 successful, public key generated")
}

func TestFixedPolynomials(t *testing.T) {
	// Test with fixed polynomial values to verify correctness
	params := Parameters{Threshold: 2, ShareCount: 2}
	sessionID := []byte("test-fixed-poly-pad")

	// Define fragments directly:
	// p1(1) = 1, p1(2) = 3
	// p2(1) = 2, p2(2) = 4
	// So p(1) = 3, p(2) = 7, which means p(x) = 2x + 1
	// p(0) = 1, so expected public key = 1 * G

	one := dkls23.NewScalar()
	one.SetBytes([]byte{1})
	two := dkls23.NewScalar()
	two.SetBytes([]byte{2})
	three := dkls23.NewScalar()
	three.SetBytes([]byte{3})
	four := dkls23.NewScalar()
	four.SetBytes([]byte{4})

	fragments1 := []group.Scalar{one, two}    // p(1) = 3
	fragments2 := []group.Scalar{three, four} // p(2) = 7

	// Phase 2 (using Step3 directly for fixed polynomial test)
	polyPoint1, proof1, err := Step3(1, sessionID, fragments1)
	if err != nil {
		t.Fatalf("Step3 party 1 failed: %v", err)
	}
	polyPoint2, proof2, err := Step3(2, sessionID, fragments2)
	if err != nil {
		t.Fatalf("Step3 party 2 failed: %v", err)
	}

	proofsCommitments := []*ProofCommitment{proof1, proof2}

	// Step 5: Compute public key
	pk1, err := Step5(&params, 1, sessionID, proofsCommitments)
	if err != nil {
		t.Fatalf("Step5 party 1 failed: %v", err)
	}
	pk2, err := Step5(&params, 2, sessionID, proofsCommitments)
	if err != nil {
		t.Fatalf("Step5 party 2 failed: %v", err)
	}

	// Verify both parties get the same public key
	if !dkls23.PointEqual(pk1, pk2) {
		t.Error("Parties have different public keys")
	}

	// Verify the public key is correct
	// p(1) = 3, p(2) = 7
	// Using Lagrange: p(0) = 3 * (2/(2-1)) + 7 * (1/(1-2)) = 6 - 7 = -1
	// Wait, let me recalculate:
	// L_1(0) = (0-2)/(1-2) = -2/-1 = 2
	// L_2(0) = (0-1)/(2-1) = -1/1 = -1
	// p(0) = 3 * 2 + 7 * (-1) = 6 - 7 = -1
	negOne := dkls23.ScalarNeg(one)
	expectedPK := dkls23.ScalarBaseMult(negOne)

	if !dkls23.PointEqual(pk1, expectedPK) {
		t.Error("Public key does not match expected value")
	}

	t.Logf("Fixed polynomial test passed: polyPoint1=%v, polyPoint2=%v", polyPoint1, polyPoint2)
}
