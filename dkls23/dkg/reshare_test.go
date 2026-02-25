package dkg

import (
	"fmt"
	"testing"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// runFullDKG runs a complete DKG (Phase1 through Phase4) for the given
// parameters and returns the resulting parties.
func runFullDKG(t *testing.T, threshold, shareCount uint8) []*sign.Party {
	t.Helper()

	n := int(shareCount)
	params := Parameters{Threshold: threshold, ShareCount: shareCount}
	sessionID := []byte(fmt.Sprintf("test-dkg-%dof%d", threshold, shareCount))

	data := make([]*SessionData, n)
	for i := range n {
		data[i] = &SessionData{
			Parameters: params,
			PartyIndex: uint8(i + 1),
			SessionID:  sessionID,
		}
	}

	// Phase 1
	phase1Out := make([]*Phase1Output, n)
	for i := range n {
		var err error
		phase1Out[i], err = Phase1(data[i])
		if err != nil {
			t.Fatalf("Phase1 party %d failed: %v", i+1, err)
		}
	}

	// Gather fragments for each party: party i receives p_j(i+1) from all j.
	fragments := make([][]group.Scalar, n)
	for i := range n {
		fragments[i] = make([]group.Scalar, n)
		for j := range n {
			fragments[i][j] = phase1Out[j].PolyPoints[i]
		}
	}

	// Phase 2
	phase2Out := make([]*Phase2Output, n)
	for i := range n {
		var err error
		phase2Out[i], err = Phase2(data[i], fragments[i])
		if err != nil {
			t.Fatalf("Phase2 party %d failed: %v", i+1, err)
		}
	}

	// Phase 3
	phase3Out := make([]*Phase3Output, n)
	for i := range n {
		var err error
		phase3Out[i], err = Phase3(data[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("Phase3 party %d failed: %v", i+1, err)
		}
	}

	// Collect proof commitments
	proofsCommitments := make([]*ProofCommitment, n)
	for i := range n {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Gather Phase4 inputs
	parties := make([]*sign.Party, n)
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
		parties[i], err = Phase4(data[i], input)
		if err != nil {
			t.Fatalf("Phase4 party %d failed: %v", i+1, err)
		}
	}

	// Verify all parties agree on the public key.
	for i := 1; i < n; i++ {
		if !dkls23.PointEqual(parties[0].PublicKey, parties[i].PublicKey) {
			t.Fatalf("DKG: party 1 and party %d have different public keys", i+1)
		}
	}

	return parties
}

// runReshare executes the full reshare protocol: old committee distributes
// sub-shares, new committee collects them and runs Phase2-4 to produce new
// parties. It verifies the public key is preserved and zeroes old keeps.
func runReshare(
	t *testing.T,
	oldParties []*sign.Party,
	oldMemberIndices []uint8,
	newThreshold, newShareCount uint8,
	newMemberIndices []uint8,
	expectedPublicKey group.Point,
) []*sign.Party {
	t.Helper()

	numOld := len(oldMemberIndices)
	numNew := int(newShareCount)

	// Stage A: Old committee distributes.
	outputs := make([]*ReshareOldMemberOutput, numOld)
	keeps := make([]*ReshareOldMemberKeep, numOld)

	for i, party := range oldParties {
		var err error
		outputs[i], keeps[i], err = ReshareOldMemberDistribute(
			party, oldMemberIndices, newThreshold, newMemberIndices,
		)
		if err != nil {
			t.Fatalf("ReshareOldMemberDistribute party %d failed: %v", party.Index, err)
		}
	}

	// Stage B: New committee collects and runs DKG Phase2-4.
	newSessionID := []byte(fmt.Sprintf("reshare-%dof%d", newThreshold, newShareCount))
	newParams := Parameters{Threshold: newThreshold, ShareCount: newShareCount}

	newData := make([]*SessionData, numNew)
	for i := range numNew {
		newData[i] = &SessionData{
			Parameters: newParams,
			PartyIndex: newMemberIndices[i],
			SessionID:  newSessionID,
		}
	}

	// For each new member, verify sub-shares via Feldman VSS, then collect.
	newKeyShares := make([]group.Scalar, numNew)
	for i, newIdx := range newMemberIndices {
		subShares := make(map[uint8]group.Scalar, numOld)
		for j, out := range outputs {
			// Verify each sub-share against sender's Feldman VSS commitments.
			if err := ReshareNewMemberVerifyShare(out.Shares[newIdx], newIdx, out.Commitments); err != nil {
				t.Fatalf("Feldman VSS failed for new member %d from old member %d: %v",
					newIdx, oldMemberIndices[j], err)
			}
			subShares[oldMemberIndices[j]] = out.Shares[newIdx]
		}

		var err error
		newKeyShares[i], err = ReshareNewMemberCollect(subShares, numOld)
		if err != nil {
			t.Fatalf("ReshareNewMemberCollect new member %d failed: %v", newIdx, err)
		}
	}

	// Phase 2 among new members: pass the reshared key share as sole fragment.
	phase2Out := make([]*Phase2Output, numNew)
	for i := range numNew {
		var err error
		phase2Out[i], err = Phase2(newData[i], []group.Scalar{newKeyShares[i]})
		if err != nil {
			t.Fatalf("Phase2 new member %d failed: %v", newMemberIndices[i], err)
		}
	}

	// Phase 3 among new members.
	phase3Out := make([]*Phase3Output, numNew)
	for i := range numNew {
		var err error
		phase3Out[i], err = Phase3(newData[i], phase2Out[i].ZeroKeep)
		if err != nil {
			t.Fatalf("Phase3 new member %d failed: %v", newMemberIndices[i], err)
		}
	}

	// Collect proof commitments from new members.
	proofsCommitments := make([]*ProofCommitment, numNew)
	for i := range numNew {
		proofsCommitments[i] = phase2Out[i].ProofCommitment
	}

	// Phase 4 among new members.
	newParties := make([]*sign.Party, numNew)
	for i := range numNew {
		zeroReceived2 := make([]*Phase2to4ZeroTransmit, 0)
		zeroReceived3 := make([]*Phase3to4ZeroTransmit, 0)
		mulReceived := make([]*Phase3to4MulTransmit, 0)

		for j := range numNew {
			if i == j {
				continue
			}
			for _, msg := range phase2Out[j].ZeroTransmit {
				if msg.Receiver == newMemberIndices[i] {
					zeroReceived2 = append(zeroReceived2, msg)
				}
			}
			for _, msg := range phase3Out[j].ZeroTransmit {
				if msg.Receiver == newMemberIndices[i] {
					zeroReceived3 = append(zeroReceived3, msg)
				}
			}
			for _, msg := range phase3Out[j].MulTransmit {
				if msg.Receiver == newMemberIndices[i] {
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
		newParties[i], err = Phase4(newData[i], input)
		if err != nil {
			t.Fatalf("Phase4 new member %d failed: %v", newMemberIndices[i], err)
		}
	}

	// Verify all new parties agree on the public key.
	for i := 1; i < numNew; i++ {
		if !dkls23.PointEqual(newParties[0].PublicKey, newParties[i].PublicKey) {
			t.Fatalf("reshare: new party %d and new party %d have different public keys",
				newMemberIndices[0], newMemberIndices[i])
		}
	}

	// Verify the public key matches the original.
	if err := VerifyRefreshedPublicKey(expectedPublicKey, newParties[0].PublicKey); err != nil {
		t.Fatalf("reshare: public key not preserved: %v", err)
	}

	// Zero old keeps.
	for _, k := range keeps {
		k.Zero()
	}

	return newParties
}

// selectParties returns a subset of parties matching the given indices.
func selectParties(allParties []*sign.Party, indices []uint8) []*sign.Party {
	selected := make([]*sign.Party, 0, len(indices))
	for _, idx := range indices {
		for _, p := range allParties {
			if p.Index == idx {
				selected = append(selected, p)
				break
			}
		}
	}
	return selected
}

func TestDKLs23ReshareBasic_2of2_to_2of2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-2 DKG.
	oldParties := runFullDKG(t, 2, 2)
	expectedPK := oldParties[0].PublicKey

	// Reshare: all old members participate, new 2-of-2 committee.
	oldIndices := []uint8{1, 2}
	newIndices := []uint8{1, 2}
	newParties := runReshare(t, oldParties, oldIndices, 2, 2, newIndices, expectedPK)

	// Verify new parties have correct parameters.
	for _, p := range newParties {
		if p.Threshold != 2 {
			t.Errorf("new party %d: threshold = %d, want 2", p.Index, p.Threshold)
		}
		if p.Total != 2 {
			t.Errorf("new party %d: total = %d, want 2", p.Index, p.Total)
		}
	}

	t.Log("reshare 2-of-2 to 2-of-2 successful")
}

func TestDKLs23ReshareBasic_2of3_to_2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-3 DKG.
	oldParties := runFullDKG(t, 2, 3)
	expectedPK := oldParties[0].PublicKey

	// Reshare: all 3 old members participate, new 2-of-3 committee.
	oldIndices := []uint8{1, 2, 3}
	newIndices := []uint8{1, 2, 3}
	newParties := runReshare(t, oldParties, oldIndices, 2, 3, newIndices, expectedPK)

	// Verify public key is preserved across all new parties.
	for _, p := range newParties {
		if err := VerifyRefreshedPublicKey(expectedPK, p.PublicKey); err != nil {
			t.Errorf("new party %d: %v", p.Index, err)
		}
	}

	// Verify key shares differ from old shares (the polynomial changed).
	for i, np := range newParties {
		if dkls23.ScalarEqual(np.KeyShare, oldParties[i].KeyShare) {
			t.Errorf("new party %d key share unchanged after reshare", np.Index)
		}
	}

	t.Log("reshare 2-of-3 to 2-of-3 successful, public key preserved")
}

func TestDKLs23ReshareThresholdIncrease_2of3_to_3of5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-3 DKG.
	oldParties := runFullDKG(t, 2, 3)
	expectedPK := oldParties[0].PublicKey

	// Reshare: all 3 old members, upgrade to 3-of-5.
	oldIndices := []uint8{1, 2, 3}
	newIndices := []uint8{1, 2, 3, 4, 5}
	newParties := runReshare(t, oldParties, oldIndices, 3, 5, newIndices, expectedPK)

	// Verify new parties have upgraded parameters.
	for _, p := range newParties {
		if p.Threshold != 3 {
			t.Errorf("new party %d: threshold = %d, want 3", p.Index, p.Threshold)
		}
		if p.Total != 5 {
			t.Errorf("new party %d: total = %d, want 5", p.Index, p.Total)
		}
	}

	t.Log("reshare 2-of-3 to 3-of-5 successful, threshold upgraded")
}

func TestDKLs23ReshareMinimumOldMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-3 DKG.
	oldParties := runFullDKG(t, 2, 3)
	expectedPK := oldParties[0].PublicKey

	// Reshare: use exactly t_old=2 old members (parties 1 and 2).
	oldIndices := []uint8{1, 2}
	selectedOld := selectParties(oldParties, oldIndices)

	newIndices := []uint8{1, 2, 3}
	newParties := runReshare(t, selectedOld, oldIndices, 2, 3, newIndices, expectedPK)

	// Verify the public key is preserved even with minimum quorum.
	for _, p := range newParties {
		if err := VerifyRefreshedPublicKey(expectedPK, p.PublicKey); err != nil {
			t.Errorf("new party %d: %v", p.Index, err)
		}
	}

	t.Log("reshare with minimum old members (t_old=2) successful")
}

func TestDKLs23ReshareInsufficientOldMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-3 DKG.
	oldParties := runFullDKG(t, 2, 3)

	// Attempt reshare with only 1 old member (below t_old=2).
	oldIndices := []uint8{1}
	party := oldParties[0] // party with index 1
	newIndices := []uint8{1, 2}

	_, _, err := ReshareOldMemberDistribute(party, oldIndices, 2, newIndices)
	if err == nil {
		t.Fatal("expected error for insufficient old members, got nil")
	}

	t.Logf("correctly rejected insufficient old members: %v", err)
}

func TestDKLs23ReshareDuplicateOldMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-3 DKG.
	oldParties := runFullDKG(t, 2, 3)

	// Attempt reshare with duplicate in old member indices.
	oldIndices := []uint8{1, 1}
	party := oldParties[0] // party with index 1
	newIndices := []uint8{1, 2}

	_, _, err := ReshareOldMemberDistribute(party, oldIndices, 2, newIndices)
	if err == nil {
		t.Fatal("expected error for duplicate old member index, got nil")
	}

	t.Logf("correctly rejected duplicate old members: %v", err)
}

func TestDKLs23ReshareNewThresholdTooLow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-2 DKG.
	oldParties := runFullDKG(t, 2, 2)

	// Attempt reshare with newThreshold=1 (below minimum of 2).
	oldIndices := []uint8{1, 2}
	newIndices := []uint8{1, 2}

	_, _, err := ReshareOldMemberDistribute(oldParties[0], oldIndices, 1, newIndices)
	if err == nil {
		t.Fatal("expected error for new threshold too low, got nil")
	}

	t.Logf("correctly rejected new threshold of 1: %v", err)
}

func TestDKLs23ReshareWrongSubShareCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	// Run initial 2-of-2 DKG.
	oldParties := runFullDKG(t, 2, 2)

	// Produce real sub-shares from both old members.
	oldIndices := []uint8{1, 2}
	newIndices := []uint8{1, 2}

	out1, keep1, err := ReshareOldMemberDistribute(oldParties[0], oldIndices, 2, newIndices)
	if err != nil {
		t.Fatalf("distribute party 1 failed: %v", err)
	}
	defer keep1.Zero()

	_, keep2, err := ReshareOldMemberDistribute(oldParties[1], oldIndices, 2, newIndices)
	if err != nil {
		t.Fatalf("distribute party 2 failed: %v", err)
	}
	defer keep2.Zero()

	// Only give sub-shares from one old member but claim numOldMembers=2.
	partialShares := map[uint8]group.Scalar{
		oldIndices[0]: out1.Shares[newIndices[0]],
	}

	_, err = ReshareNewMemberCollect(partialShares, 2)
	if err == nil {
		t.Fatal("expected error for wrong sub-share count, got nil")
	}

	t.Logf("correctly rejected wrong sub-share count: %v", err)
}

func TestDKLs23ReshareFeldmanVSSFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	oldParties := runFullDKG(t, 2, 2)

	oldIndices := []uint8{1, 2}
	newIndices := []uint8{1, 2}

	out1, keep1, err := ReshareOldMemberDistribute(oldParties[0], oldIndices, 2, newIndices)
	if err != nil {
		t.Fatalf("distribute party 1 failed: %v", err)
	}
	defer keep1.Zero()

	// Tamper with the sub-share for new member 1: add a random scalar.
	tamper, err := dkls23.RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	tamperedShare := dkls23.ScalarAdd(out1.Shares[1], tamper)

	// Verification should fail for the tampered share.
	err = ReshareNewMemberVerifyShare(tamperedShare, 1, out1.Commitments)
	if err == nil {
		t.Fatal("expected Feldman VSS error for tampered sub-share, got nil")
	}

	// Verification should pass for the honest share.
	err = ReshareNewMemberVerifyShare(out1.Shares[1], 1, out1.Commitments)
	if err != nil {
		t.Fatalf("honest share failed Feldman VSS: %v", err)
	}

	t.Logf("correctly rejected tampered sub-share: %v", err)
}

func TestDKLs23ReshareNewMemberIndexZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	oldParties := runFullDKG(t, 2, 2)

	oldIndices := []uint8{1, 2}
	newIndices := []uint8{0, 1} // index 0 is invalid

	_, _, err := ReshareOldMemberDistribute(oldParties[0], oldIndices, 2, newIndices)
	if err == nil {
		t.Fatal("expected error for new member index 0, got nil")
	}

	t.Logf("correctly rejected new member index 0: %v", err)
}

func TestDKLs23ReshareDuplicateNewMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive OT-based test in short mode")
	}

	oldParties := runFullDKG(t, 2, 2)

	oldIndices := []uint8{1, 2}
	newIndices := []uint8{1, 1} // duplicate new member index

	_, _, err := ReshareOldMemberDistribute(oldParties[0], oldIndices, 2, newIndices)
	if err == nil {
		t.Fatal("expected error for duplicate new member index, got nil")
	}

	t.Logf("correctly rejected duplicate new member index: %v", err)
}
