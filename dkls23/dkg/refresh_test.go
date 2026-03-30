package dkg

import (
	"fmt"
	"testing"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runDKG2of2 executes a full 2-of-2 DKG and returns the resulting parties
// together with the session data used during key generation.
func runDKG2of2(t *testing.T) (party1, party2 *sign.Party, sessionData1, sessionData2 *SessionData) {
	t.Helper()

	params := Parameters{Threshold: 2, ShareCount: 2}
	sessionID := []byte("test-refresh-dkg-2of2-pad")

	sessionData1 = &SessionData{Parameters: params, PartyIndex: 1, SessionID: sessionID}
	sessionData2 = &SessionData{Parameters: params, PartyIndex: 2, SessionID: sessionID}

	// Phase 1
	out1_1, err := Phase1(sessionData1)
	if err != nil {
		t.Fatalf("Phase1 party 1: %v", err)
	}
	out1_2, err := Phase1(sessionData2)
	if err != nil {
		t.Fatalf("Phase1 party 2: %v", err)
	}

	fragments1 := []group.Scalar{out1_1.PolyPoints[0], out1_2.PolyPoints[0]}
	fragments2 := []group.Scalar{out1_1.PolyPoints[1], out1_2.PolyPoints[1]}

	// Phase 2
	out2_1, err := Phase2(sessionData1, fragments1)
	if err != nil {
		t.Fatalf("Phase2 party 1: %v", err)
	}
	out2_2, err := Phase2(sessionData2, fragments2)
	if err != nil {
		t.Fatalf("Phase2 party 2: %v", err)
	}

	// Phase 3
	out3_1, err := Phase3(sessionData1, out2_1.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 1: %v", err)
	}
	out3_2, err := Phase3(sessionData2, out2_2.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 2: %v", err)
	}

	proofsCommitments := []*ProofCommitment{out2_1.ProofCommitment, out2_2.ProofCommitment}

	// Phase 4
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

	party1, err = Phase4(sessionData1, input1)
	if err != nil {
		t.Fatalf("Phase4 party 1: %v", err)
	}
	party2, err = Phase4(sessionData2, input2)
	if err != nil {
		t.Fatalf("Phase4 party 2: %v", err)
	}

	if !dkls23.PointEqual(party1.PublicKey, party2.PublicKey) {
		t.Fatal("DKG 2-of-2 produced different public keys")
	}

	return party1, party2, sessionData1, sessionData2
}

// runDKG2of3 executes a full 2-of-3 DKG and returns the resulting parties
// together with the session data used during key generation.
func runDKG2of3(t *testing.T) (parties []*sign.Party, sessionDatas []*SessionData) {
	t.Helper()

	params := Parameters{Threshold: 2, ShareCount: 3}
	sessionID := []byte("test-refresh-dkg-2of3-pad")

	sessionDatas = make([]*SessionData, 3)
	for i := range 3 {
		sessionDatas[i] = &SessionData{Parameters: params, PartyIndex: uint8(i + 1), SessionID: sessionID}
	}

	// Phase 1
	phase1Out := make([]*Phase1Output, 3)
	for i := range 3 {
		var err error
		phase1Out[i], err = Phase1(sessionDatas[i])
		if err != nil {
			t.Fatalf("Phase1 party %d: %v", i+1, err)
		}
	}

	// Gather fragments for each party.
	fragments := make([][]group.Scalar, 3)
	for i := range 3 {
		fragments[i] = make([]group.Scalar, 3)
		for j := range 3 {
			fragments[i][j] = phase1Out[j].PolyPoints[i]
		}
	}

	// Phase 2
	phase2Out := make([]*Phase2Output, 3)
	for i := range 3 {
		var err error
		phase2Out[i], err = Phase2(sessionDatas[i], fragments[i])
		if err != nil {
			t.Fatalf("Phase2 party %d: %v", i+1, err)
		}
	}

	// Phase 3
	phase3Out := make([]*Phase3Output, 3)
	for i := range 3 {
		var err error
		phase3Out[i], err = Phase3(sessionDatas[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("Phase3 party %d: %v", i+1, err)
		}
	}

	proofsCommitments := make([]*ProofCommitment, 3)
	for i := range 3 {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Phase 4 -- route messages the same way as TestDKG2of3.
	parties = make([]*sign.Party, 3)
	for i := range 3 {
		zeroReceived2 := make([]*Phase2to4ZeroTransmit, 0)
		zeroReceived3 := make([]*Phase3to4ZeroTransmit, 0)
		mulReceived := make([]*Phase3to4MulTransmit, 0)

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

		input := &Phase4Input{
			PolyPoint:         phase2Out[i].PolyPoint,
			ProofsCommitments: proofsCommitments,
			ZeroKept:          phase3Out[i].ZeroKeep,
			ZeroReceived2:     zeroReceived2,
			ZeroReceived3:     zeroReceived3,
			MulKept:           phase3Out[i].MulKeep,
			MulReceived:       mulReceived,
		}

		var err error
		parties[i], err = Phase4(sessionDatas[i], input)
		if err != nil {
			t.Fatalf("Phase4 party %d: %v", i+1, err)
		}
	}

	for i := 1; i < 3; i++ {
		if !dkls23.PointEqual(parties[0].PublicKey, parties[i].PublicKey) {
			t.Fatalf("DKG 2-of-3: party %d has different public key", i+1)
		}
	}

	return parties, sessionDatas
}

// runRefresh2of2 executes the full refresh protocol for a 2-of-2 setup and
// returns the new parties with refreshed key shares and re-initialized
// MtA/OT correlations.
func runRefresh2of2(t *testing.T, party1, party2 *sign.Party, data1, data2 *SessionData) (newParty1, newParty2 *sign.Party) {
	t.Helper()

	// Fresh session data with a new session ID.
	params := data1.Parameters
	refreshSessionID := []byte("refresh-2of2-" + t.Name())
	rd1 := &SessionData{Parameters: params, PartyIndex: 1, SessionID: refreshSessionID}
	rd2 := &SessionData{Parameters: params, PartyIndex: 2, SessionID: refreshSessionID}

	// Refresh Phase 1
	rOut1, err := RefreshPhase1(rd1)
	if err != nil {
		t.Fatalf("RefreshPhase1 party 1: %v", err)
	}
	rOut2, err := RefreshPhase1(rd2)
	if err != nil {
		t.Fatalf("RefreshPhase1 party 2: %v", err)
	}

	// Exchange deltas: party 1 receives delta from party 2 and vice versa.
	receivedDeltas1 := map[uint8]group.Scalar{2: rOut2.Deltas[1]}
	receivedDeltas2 := map[uint8]group.Scalar{1: rOut1.Deltas[2]}

	// Verify deltas via Feldman VSS.
	if err := RefreshVerifyDelta(rOut2.Deltas[1], 1, rOut2.Commitments); err != nil {
		t.Fatalf("RefreshVerifyDelta party 1 from party 2: %v", err)
	}
	if err := RefreshVerifyDelta(rOut1.Deltas[2], 2, rOut1.Commitments); err != nil {
		t.Fatalf("RefreshVerifyDelta party 2 from party 1: %v", err)
	}

	// Build all commitments maps.
	allCommitments1 := map[uint8][]group.Point{1: rOut1.Commitments, 2: rOut2.Commitments}
	allCommitments2 := map[uint8][]group.Point{1: rOut1.Commitments, 2: rOut2.Commitments}

	// Refresh Phase 2
	out2_1, err := RefreshPhase2(rd1, rOut1.Keep, party1.KeyShare, receivedDeltas1, allCommitments1)
	if err != nil {
		t.Fatalf("RefreshPhase2 party 1: %v", err)
	}
	out2_2, err := RefreshPhase2(rd2, rOut2.Keep, party2.KeyShare, receivedDeltas2, allCommitments2)
	if err != nil {
		t.Fatalf("RefreshPhase2 party 2: %v", err)
	}

	// Phase 3
	out3_1, err := Phase3(rd1, out2_1.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 1: %v", err)
	}
	out3_2, err := Phase3(rd2, out2_2.ZeroKeep)
	if err != nil {
		t.Fatalf("Phase3 party 2: %v", err)
	}

	proofsCommitments := []*ProofCommitment{out2_1.ProofCommitment, out2_2.ProofCommitment}

	// Phase 4
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

	newParty1, err = Phase4(rd1, input1)
	if err != nil {
		t.Fatalf("Phase4 party 1: %v", err)
	}
	newParty2, err = Phase4(rd2, input2)
	if err != nil {
		t.Fatalf("Phase4 party 2: %v", err)
	}

	return newParty1, newParty2
}

// runRefresh2of3 executes the full refresh protocol for a 2-of-3 setup and
// returns the new parties with refreshed key shares and re-initialized
// MtA/OT correlations.
func runRefresh2of3(t *testing.T, parties []*sign.Party, datas []*SessionData) (newParties []*sign.Party) {
	t.Helper()

	n := len(parties)
	params := datas[0].Parameters
	refreshSessionID := []byte("refresh-2of3-" + t.Name())

	rDatas := make([]*SessionData, n)
	for i := range n {
		rDatas[i] = &SessionData{Parameters: params, PartyIndex: uint8(i + 1), SessionID: refreshSessionID}
	}

	// Refresh Phase 1
	rOuts := make([]*RefreshPhase1Output, n)
	for i := range n {
		var err error
		rOuts[i], err = RefreshPhase1(rDatas[i])
		if err != nil {
			t.Fatalf("RefreshPhase1 party %d: %v", i+1, err)
		}
	}

	// Exchange deltas: for each party, collect deltas sent TO that party.
	receivedDeltas := make([]map[uint8]group.Scalar, n)
	for i := range n {
		receivedDeltas[i] = make(map[uint8]group.Scalar)
		for j := range n {
			if i == j {
				continue
			}
			// Party j sent a delta for party i (indexed by party i's 1-based index).
			receivedDeltas[i][uint8(j+1)] = rOuts[j].Deltas[uint8(i+1)]
		}
	}

	// Verify deltas via Feldman VSS.
	for i := range n {
		for j := range n {
			if i == j {
				continue
			}
			if err := RefreshVerifyDelta(rOuts[j].Deltas[uint8(i+1)], uint8(i+1), rOuts[j].Commitments); err != nil {
				t.Fatalf("RefreshVerifyDelta party %d from party %d: %v", i+1, j+1, err)
			}
		}
	}

	// Build all commitments maps.
	allCommitmentsMaps := make([]map[uint8][]group.Point, n)
	for i := range n {
		allCommitmentsMaps[i] = make(map[uint8][]group.Point)
		for j := range n {
			allCommitmentsMaps[i][uint8(j+1)] = rOuts[j].Commitments
		}
	}

	// Refresh Phase 2
	phase2Out := make([]*Phase2Output, n)
	for i := range n {
		var err error
		phase2Out[i], err = RefreshPhase2(rDatas[i], rOuts[i].Keep, parties[i].KeyShare, receivedDeltas[i], allCommitmentsMaps[i])
		if err != nil {
			t.Fatalf("RefreshPhase2 party %d: %v", i+1, err)
		}
	}

	// Phase 3
	phase3Out := make([]*Phase3Output, n)
	for i := range n {
		var err error
		phase3Out[i], err = Phase3(rDatas[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("Phase3 party %d: %v", i+1, err)
		}
	}

	proofsCommitments := make([]*ProofCommitment, n)
	for i := range n {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Phase 4 -- same message routing as runDKG2of3.
	newParties = make([]*sign.Party, n)
	for i := range n {
		zeroReceived2 := make([]*Phase2to4ZeroTransmit, 0)
		zeroReceived3 := make([]*Phase3to4ZeroTransmit, 0)
		mulReceived := make([]*Phase3to4MulTransmit, 0)

		for j := range n {
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

		input := &Phase4Input{
			PolyPoint:         phase2Out[i].PolyPoint,
			ProofsCommitments: proofsCommitments,
			ZeroKept:          phase3Out[i].ZeroKeep,
			ZeroReceived2:     zeroReceived2,
			ZeroReceived3:     zeroReceived3,
			MulKept:           phase3Out[i].MulKeep,
			MulReceived:       mulReceived,
		}

		var err error
		newParties[i], err = Phase4(rDatas[i], input)
		if err != nil {
			t.Fatalf("Phase4 party %d: %v", i+1, err)
		}
	}

	return newParties
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDKLs23RefreshBasic_2of2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	party1, party2, data1, data2 := runDKG2of2(t)
	originalPK := party1.PublicKey

	newParty1, newParty2 := runRefresh2of2(t, party1, party2, data1, data2)

	// Both refreshed parties must agree on the public key.
	if !dkls23.PointEqual(newParty1.PublicKey, newParty2.PublicKey) {
		t.Fatal("refreshed parties have different public keys")
	}

	// The refreshed public key must equal the original.
	if err := VerifyRefreshedPublicKey(originalPK, newParty1.PublicKey); err != nil {
		t.Fatalf("public key not preserved after refresh: %v", err)
	}

	t.Logf("2-of-2 refresh: public key preserved")
}

func TestDKLs23RefreshBasic_2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	parties, datas := runDKG2of3(t)
	originalPK := parties[0].PublicKey

	newParties := runRefresh2of3(t, parties, datas)

	for i := range newParties {
		if err := VerifyRefreshedPublicKey(originalPK, newParties[i].PublicKey); err != nil {
			t.Fatalf("party %d: public key not preserved after refresh: %v", i+1, err)
		}
	}

	t.Logf("2-of-3 refresh: public key preserved across all parties")
}

func TestDKLs23RefreshPreservesPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	parties, datas := runDKG2of3(t)
	originalPK := parties[0].PublicKey

	newParties := runRefresh2of3(t, parties, datas)

	// All refreshed parties must have the same public key.
	for i := 1; i < len(newParties); i++ {
		if !dkls23.PointEqual(newParties[0].PublicKey, newParties[i].PublicKey) {
			t.Fatalf("refreshed party %d public key differs from party 1", i+1)
		}
	}

	// The public key must equal the pre-refresh original.
	if !dkls23.PointEqual(originalPK, newParties[0].PublicKey) {
		t.Fatal("refreshed public key does not match original")
	}

	t.Logf("all %d refreshed parties share the original public key", len(newParties))
}

func TestDKLs23RefreshChangesKeyShares(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	party1, party2, data1, data2 := runDKG2of2(t)
	oldShare1 := dkls23.NewScalar().Set(party1.KeyShare)
	oldShare2 := dkls23.NewScalar().Set(party2.KeyShare)

	newParty1, newParty2 := runRefresh2of2(t, party1, party2, data1, data2)

	// The key shares MUST have changed.
	if dkls23.ScalarEqual(oldShare1, newParty1.KeyShare) {
		t.Error("party 1 key share unchanged after refresh")
	}
	if dkls23.ScalarEqual(oldShare2, newParty2.KeyShare) {
		t.Error("party 2 key share unchanged after refresh")
	}

	// But the public key is still the same.
	if !dkls23.PointEqual(party1.PublicKey, newParty1.PublicKey) {
		t.Error("public key changed after refresh")
	}

	t.Logf("key shares changed; public key preserved")
}

func TestDKLs23RefreshMultipleRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	party1, party2, data1, data2 := runDKG2of2(t)
	originalPK := party1.PublicKey

	// First refresh.
	p1, p2 := runRefresh2of2(t, party1, party2, data1, data2)
	if err := VerifyRefreshedPublicKey(originalPK, p1.PublicKey); err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if err := VerifyRefreshedPublicKey(originalPK, p2.PublicKey); err != nil {
		t.Fatalf("round 1 party 2: %v", err)
	}

	// Second refresh (using the parties from the first refresh).
	p1b, p2b := runRefresh2of2(t, p1, p2, data1, data2)
	if err := VerifyRefreshedPublicKey(originalPK, p1b.PublicKey); err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if err := VerifyRefreshedPublicKey(originalPK, p2b.PublicKey); err != nil {
		t.Fatalf("round 2 party 2: %v", err)
	}

	t.Logf("public key preserved across 2 refresh rounds")
}

func TestDKLs23RefreshPhase1Validation(t *testing.T) {
	// This test validates that RefreshPhase1 rejects invalid SessionData.
	// No OT operations needed, so it runs fast.

	tests := []struct {
		name string
		data *SessionData
	}{
		{
			name: "threshold too low",
			data: &SessionData{
				Parameters: Parameters{Threshold: 1, ShareCount: 2},
				PartyIndex: 1,
				SessionID:  []byte("bad-session-padded"),
			},
		},
		{
			name: "share count less than threshold",
			data: &SessionData{
				Parameters: Parameters{Threshold: 3, ShareCount: 2},
				PartyIndex: 1,
				SessionID:  []byte("bad-session-padded"),
			},
		},
		{
			name: "party index zero",
			data: &SessionData{
				Parameters: Parameters{Threshold: 2, ShareCount: 3},
				PartyIndex: 0,
				SessionID:  []byte("bad-session-padded"),
			},
		},
		{
			name: "party index exceeds share count",
			data: &SessionData{
				Parameters: Parameters{Threshold: 2, ShareCount: 3},
				PartyIndex: 4,
				SessionID:  []byte("bad-session-padded"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RefreshPhase1(tc.data)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestDKLs23RefreshPhase2WrongDeltaCount(t *testing.T) {
	// RefreshPhase2 must reject an incorrect number of deltas.
	// No OT operations needed for RefreshPhase1 or the error path.

	params := Parameters{Threshold: 2, ShareCount: 3}
	sessionID := []byte("test-delta-count-pad")
	data := &SessionData{Parameters: params, PartyIndex: 1, SessionID: sessionID}

	rOut, err := RefreshPhase1(data)
	if err != nil {
		t.Fatalf("RefreshPhase1: %v", err)
	}

	// A valid existing key share.
	existingShare, err := dkls23.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar: %v", err)
	}

	// 2-of-3 means we expect exactly 2 received deltas (from parties 2 and 3).
	// Provide only 1.
	tooFew := map[uint8]group.Scalar{
		2: rOut.Deltas[2],
	}

	allCommitments := map[uint8][]group.Point{
		1: rOut.Commitments,
		2: rOut.Commitments,
		3: rOut.Commitments,
	}

	_, err = RefreshPhase2(data, rOut.Keep, existingShare, tooFew, allCommitments)
	if err == nil {
		t.Fatal("expected error for too few deltas, got nil")
	}
	t.Logf("too few deltas: %v", err)

	// Provide 3 (too many).
	extra, err := dkls23.RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar: %v", err)
	}
	tooMany := map[uint8]group.Scalar{
		2: rOut.Deltas[2],
		3: rOut.Deltas[3],
		4: extra,
	}

	// Need a fresh keep because the first call to RefreshPhase2 did not
	// proceed (errored before zeroing). Generate another phase1 output.
	rOut2, err := RefreshPhase1(data)
	if err != nil {
		t.Fatalf("RefreshPhase1 (second): %v", err)
	}

	allCommitments2 := map[uint8][]group.Point{
		1: rOut2.Commitments,
		2: rOut2.Commitments,
		3: rOut2.Commitments,
	}

	_, err = RefreshPhase2(data, rOut2.Keep, existingShare, tooMany, allCommitments2)
	if err == nil {
		t.Fatal("expected error for too many deltas, got nil")
	}
	t.Logf("too many deltas: %v", err)

	// Verify the error message contains expected/got counts.
	expected := fmt.Sprintf("expected %d deltas, got %d", 2, 3)
	if err.Error() != expected {
		t.Errorf("unexpected error message: got %q, want %q", err.Error(), expected)
	}
}

func TestDKLs23RefreshFeldmanVSSFailure(t *testing.T) {
	// No OT operations needed for this test.
	params := Parameters{Threshold: 2, ShareCount: 2}
	sessionID := []byte("test-refresh-vss-pad")
	data1 := &SessionData{Parameters: params, PartyIndex: 1, SessionID: sessionID}
	data2 := &SessionData{Parameters: params, PartyIndex: 2, SessionID: sessionID}

	rOut1, err := RefreshPhase1(data1)
	if err != nil {
		t.Fatal(err)
	}
	rOut2, err := RefreshPhase1(data2)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with a delta: add a random scalar.
	tamper, err := dkls23.RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	tamperedDelta := dkls23.ScalarAdd(rOut2.Deltas[1], tamper)

	// Verification should fail for the tampered delta.
	err = RefreshVerifyDelta(tamperedDelta, 1, rOut2.Commitments)
	if err == nil {
		t.Fatal("expected Feldman VSS error for tampered refresh delta, got nil")
	}

	// Verification should pass for the honest delta.
	err = RefreshVerifyDelta(rOut2.Deltas[1], 1, rOut2.Commitments)
	if err != nil {
		t.Fatalf("honest delta failed Feldman VSS: %v", err)
	}

	// Also test cheating detection: tamper with commitments[0] to be non-identity.
	cheatingCommitments := make([]group.Point, len(rOut2.Commitments))
	copy(cheatingCommitments, rOut2.Commitments)
	cheatingCommitments[0] = dkls23.ScalarBaseMult(tamper) // non-identity

	allCommitments := map[uint8][]group.Point{
		1: rOut1.Commitments,
		2: cheatingCommitments,
	}

	receivedDeltas := map[uint8]group.Scalar{2: rOut2.Deltas[1]}
	_, err = RefreshPhase2(data1, rOut1.Keep, tamper, receivedDeltas, allCommitments)
	if err == nil {
		t.Fatal("expected cheating detection error, got nil")
	}
}
