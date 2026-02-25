package frost

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

// runReshare performs a complete reshare protocol from an old committee (using
// fOld) to a new committee (using fNew). It creates newMemberCount new members
// with IDs 1..newMemberCount, runs the full reshare flow, zeroes old member
// state, verifies group key preservation, and returns the new key shares.
func runReshare(t *testing.T, fOld *FROST, fNew *FROST, oldShares []*KeyShare, newMemberCount int) []*KeyShare {
	t.Helper()

	// Collect old member IDs from existing shares.
	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	// Step 1: Create old member reshare state.
	oldMembers := make([]*ReshareOldMember, len(oldShares))
	for i, ks := range oldShares {
		rom, err := fOld.NewReshareOldMember(rand.Reader, ks, oldMemberIDs, fNew.threshold)
		if err != nil {
			t.Fatalf("NewReshareOldMember for member %d: %v", i, err)
		}
		oldMembers[i] = rom
	}

	// Step 2: Broadcast commitments.
	broadcasts := make([]*ReshareRound1Data, len(oldMembers))
	for i, rom := range oldMembers {
		broadcasts[i] = rom.Round1Broadcast()
	}

	// Step 3: Create new member IDs using fNew.scalarFromInt.
	newMemberIDs := make([]group.Scalar, newMemberCount)
	for i := range newMemberCount {
		newMemberIDs[i] = fNew.scalarFromInt(i + 1)
	}

	// Step 4: For each new member, create state, receive shares, finalize.
	expectedGroupKey := oldShares[0].GroupKey
	newShares := make([]*KeyShare, newMemberCount)

	for i, newID := range newMemberIDs {
		rnm, err := fNew.NewReshareNewMember(newID)
		if err != nil {
			t.Fatalf("NewReshareNewMember for member %d: %v", i+1, err)
		}

		// Receive a share from every old member.
		for j, rom := range oldMembers {
			privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
			if err != nil {
				t.Fatalf("ReshareOldMemberSendShare for member %d to new member %d: %v", j+1, i+1, err)
			}
			err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcasts[j].Commitments)
			if err != nil {
				t.Fatalf("new member %d failed to receive share from old member %d: %v", i+1, j+1, err)
			}
		}

		ks, err := fNew.ReshareFinalize(rnm, broadcasts, expectedGroupKey)
		if err != nil {
			t.Fatalf("ReshareFinalize for new member %d: %v", i+1, err)
		}
		newShares[i] = ks
	}

	// Step 5: Zero old members.
	for _, rom := range oldMembers {
		rom.Zero()
	}

	// Step 6: Verify all new shares have the same GroupKey.
	for i := 1; i < newMemberCount; i++ {
		if !newShares[i].GroupKey.Equal(newShares[0].GroupKey) {
			t.Fatal("new shares have different group keys")
		}
	}

	// Verify the group key was preserved from the original DKG.
	if !newShares[0].GroupKey.Equal(expectedGroupKey) {
		t.Fatal("group key not preserved after reshare")
	}

	return newShares
}

func TestReshareBasic_2of3_to_2of3(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)
	originalGroupKey := oldShares[0].GroupKey

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	newShares := runReshare(t, fOld, fNew, oldShares, 3)

	// Verify group key preservation.
	if !newShares[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after reshare")
	}

	// Sign with the new committee and verify against the original group key.
	t.Run("SignAfterReshare", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[:2], []byte("message after 2of3 to 2of3 reshare"))
	})
}

func TestReshareThresholdIncrease_2of3_to_3of5(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)
	originalGroupKey := oldShares[0].GroupKey

	fNew, err := New(g, 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	newShares := runReshare(t, fOld, fNew, oldShares, 5)

	if !newShares[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after threshold increase reshare")
	}

	t.Run("SignWithNewThreshold", func(t *testing.T) {
		// Need 3 signers now (new threshold).
		signAndVerify(t, fNew, newShares[:3], []byte("message after threshold increase"))
	})

	t.Run("SignWithAllNewMembers", func(t *testing.T) {
		signAndVerify(t, fNew, newShares, []byte("all 5 members signing"))
	})
}

func TestReshareThresholdDecrease_3of5_to_2of3(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 5)
	originalGroupKey := oldShares[0].GroupKey

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	newShares := runReshare(t, fOld, fNew, oldShares, 3)

	if !newShares[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after threshold decrease reshare")
	}

	t.Run("SignWithNewThreshold", func(t *testing.T) {
		// Need only 2 signers now (new threshold).
		signAndVerify(t, fNew, newShares[:2], []byte("message after threshold decrease"))
	})

	t.Run("SignWithAllNewMembers", func(t *testing.T) {
		signAndVerify(t, fNew, newShares, []byte("all 3 new members signing"))
	})
}

func TestReshareMinimumOldMembers(t *testing.T) {
	g := &bjj.BJJ{}

	// 2-of-3 DKG, then reshare using exactly 2 old members (the minimum).
	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)
	originalGroupKey := oldShares[0].GroupKey

	// Use only the first 2 shares (exactly threshold).
	subset := oldShares[:2]

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	newShares := runReshare(t, fOld, fNew, subset, 3)

	if !newShares[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed when using minimum old members")
	}

	t.Run("SignAfterMinimumReshare", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[:2], []byte("signed after minimum-member reshare"))
	})
}

func TestReshareInsufficientOldMembers(t *testing.T) {
	g := &bjj.BJJ{}

	// 2-of-3 DKG: need at least 2 old members.
	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	// Try with only 1 old member (below threshold).
	singleShare := oldShares[:1]
	oldMemberIDs := []group.Scalar{singleShare[0].ID}

	_, err = fOld.NewReshareOldMember(rand.Reader, singleShare[0], oldMemberIDs, 2)
	if err == nil {
		t.Fatal("expected error when using fewer than threshold old members")
	}
}

func TestReshareGroupKeyMismatch(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Run the reshare protocol up to finalize, but pass a wrong group key.
	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	oldMembers := make([]*ReshareOldMember, len(oldShares))
	for i, ks := range oldShares {
		rom, err := fOld.NewReshareOldMember(rand.Reader, ks, oldMemberIDs, fNew.threshold)
		if err != nil {
			t.Fatal(err)
		}
		oldMembers[i] = rom
	}

	broadcasts := make([]*ReshareRound1Data, len(oldMembers))
	for i, rom := range oldMembers {
		broadcasts[i] = rom.Round1Broadcast()
	}

	newID := fNew.scalarFromInt(1)
	rnm, err := fNew.NewReshareNewMember(newID)
	if err != nil {
		t.Fatalf("NewReshareNewMember failed: %v", err)
	}

	for j, rom := range oldMembers {
		privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
		if err != nil {
			t.Fatalf("ReshareOldMemberSendShare failed: %v", err)
		}
		err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcasts[j].Commitments)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create a wrong group key (just the generator point).
	wrongGroupKey := g.NewPoint().ScalarMult(fNew.scalarFromInt(42), g.Generator())

	_, err = fNew.ReshareFinalize(rnm, broadcasts, wrongGroupKey)
	if err == nil {
		t.Fatal("expected error when expectedGroupKey does not match")
	}

	// Clean up old members.
	for _, rom := range oldMembers {
		rom.Zero()
	}
}

func TestReshareDisjointCommittees(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)
	originalGroupKey := oldShares[0].GroupKey

	// New committee with completely different IDs (100, 101, 102).
	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	oldMembers := make([]*ReshareOldMember, len(oldShares))
	for i, ks := range oldShares {
		rom, err := fOld.NewReshareOldMember(rand.Reader, ks, oldMemberIDs, fNew.threshold)
		if err != nil {
			t.Fatal(err)
		}
		oldMembers[i] = rom
	}

	broadcasts := make([]*ReshareRound1Data, len(oldMembers))
	for i, rom := range oldMembers {
		broadcasts[i] = rom.Round1Broadcast()
	}

	// Disjoint IDs: 100, 101, 102.
	disjointIDs := []group.Scalar{
		fNew.scalarFromInt(100),
		fNew.scalarFromInt(101),
		fNew.scalarFromInt(102),
	}

	newShares := make([]*KeyShare, 3)
	for i, newID := range disjointIDs {
		rnm, err := fNew.NewReshareNewMember(newID)
		if err != nil {
			t.Fatalf("NewReshareNewMember for member %d: %v", i, err)
		}
		for j, rom := range oldMembers {
			privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
			if err != nil {
				t.Fatalf("ReshareOldMemberSendShare from member %d to new member %d: %v", j, i, err)
			}
			err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcasts[j].Commitments)
			if err != nil {
				t.Fatalf("new member %d failed to receive share from old member %d: %v", i, j, err)
			}
		}

		ks, err := fNew.ReshareFinalize(rnm, broadcasts, originalGroupKey)
		if err != nil {
			t.Fatalf("ReshareFinalize for disjoint member %d: %v", i, err)
		}
		newShares[i] = ks
	}

	for _, rom := range oldMembers {
		rom.Zero()
	}

	// Verify group key preserved.
	for i := range newShares {
		if !newShares[i].GroupKey.Equal(originalGroupKey) {
			t.Fatal("group key not preserved with disjoint committees")
		}
	}

	// Sign with disjoint committee.
	t.Run("SignWithDisjointCommittee", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[:2], []byte("disjoint committee signing"))
	})
}

func TestReshareOverlappingCommittees(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)
	originalGroupKey := oldShares[0].GroupKey

	// New committee: members 1 and 2 overlap, member 3 is new (ID=4).
	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	oldMembers := make([]*ReshareOldMember, len(oldShares))
	for i, ks := range oldShares {
		rom, err := fOld.NewReshareOldMember(rand.Reader, ks, oldMemberIDs, fNew.threshold)
		if err != nil {
			t.Fatal(err)
		}
		oldMembers[i] = rom
	}

	broadcasts := make([]*ReshareRound1Data, len(oldMembers))
	for i, rom := range oldMembers {
		broadcasts[i] = rom.Round1Broadcast()
	}

	// Overlapping: IDs 1, 2 (same as old), and 4 (new).
	overlapIDs := []group.Scalar{
		fNew.scalarFromInt(1),
		fNew.scalarFromInt(2),
		fNew.scalarFromInt(4),
	}

	newShares := make([]*KeyShare, 3)
	for i, newID := range overlapIDs {
		rnm, err := fNew.NewReshareNewMember(newID)
		if err != nil {
			t.Fatalf("NewReshareNewMember for member %d: %v", i, err)
		}
		for j, rom := range oldMembers {
			privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
			if err != nil {
				t.Fatalf("ReshareOldMemberSendShare from member %d to new member %d: %v", j, i, err)
			}
			err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcasts[j].Commitments)
			if err != nil {
				t.Fatalf("overlapping member %d failed to receive share from old member %d: %v", i, j, err)
			}
		}

		ks, err := fNew.ReshareFinalize(rnm, broadcasts, originalGroupKey)
		if err != nil {
			t.Fatalf("ReshareFinalize for overlapping member %d: %v", i, err)
		}
		newShares[i] = ks
	}

	for _, rom := range oldMembers {
		rom.Zero()
	}

	// Verify group key preserved.
	for i := range newShares {
		if !newShares[i].GroupKey.Equal(originalGroupKey) {
			t.Fatal("group key not preserved with overlapping committees")
		}
	}

	t.Run("SignWithOverlappingCommittee", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[:2], []byte("overlapping committee signing"))
	})

	t.Run("SignWithNewMemberIncluded", func(t *testing.T) {
		// Sign using the new member (ID=4) and one overlapping member.
		signers := []*KeyShare{newShares[0], newShares[2]}
		signAndVerify(t, fNew, signers, []byte("new member included signing"))
	})
}

func TestReshareChainedTransfers(t *testing.T) {
	g := &bjj.BJJ{}

	// Phase A: Initial DKG (2-of-3).
	fA, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sharesA := runDKG(t, fA, 3)
	originalGroupKey := sharesA[0].GroupKey

	// Phase B: Reshare A -> B (2-of-3 -> 2-of-3).
	fB, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sharesB := runReshare(t, fA, fB, sharesA, 3)

	if !sharesB[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after first reshare")
	}

	// Phase C: Reshare B -> C (2-of-3 -> 2-of-3).
	fC, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sharesC := runReshare(t, fB, fC, sharesB, 3)

	if !sharesC[0].GroupKey.Equal(originalGroupKey) {
		t.Fatal("group key changed after second reshare")
	}

	// Sign with the final committee and verify against the original key.
	t.Run("SignAfterChainedReshare", func(t *testing.T) {
		signAndVerify(t, fC, sharesC[:2], []byte("chained reshare signing"))
	})

	// Verify cross-committee: signature from C verifies with original group key.
	t.Run("VerifyGroupKeyPreservedAcrossChain", func(t *testing.T) {
		sig := signAndVerify(t, fC, sharesC[:2], []byte("cross-verify message"))
		if !fA.Verify([]byte("cross-verify message"), sig, originalGroupKey) {
			t.Fatal("signature from final committee does not verify with original FROST instance")
		}
	})
}

func TestReshareSignAfterReshare(t *testing.T) {
	g := &bjj.BJJ{}

	// Full flow: DKG -> Sign -> Reshare -> Sign with new committee.
	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	// Sign before reshare.
	t.Run("SignBeforeReshare", func(t *testing.T) {
		signAndVerify(t, fOld, oldShares[:2], []byte("pre-reshare message"))
	})

	// Reshare to new 2-of-3 committee.
	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	newShares := runReshare(t, fOld, fNew, oldShares, 3)

	// Sign after reshare with various subsets of the new committee.
	t.Run("SignWithFirstTwo", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[:2], []byte("post-reshare first two"))
	})

	t.Run("SignWithLastTwo", func(t *testing.T) {
		signAndVerify(t, fNew, newShares[1:], []byte("post-reshare last two"))
	})

	t.Run("SignWithAllThree", func(t *testing.T) {
		signAndVerify(t, fNew, newShares, []byte("post-reshare all three"))
	})

	// Verify the new signature verifies against the original group key with the old instance.
	t.Run("CrossVerify", func(t *testing.T) {
		sig := signAndVerify(t, fNew, newShares[:2], []byte("cross-instance verify"))
		if !fOld.Verify([]byte("cross-instance verify"), sig, oldShares[0].GroupKey) {
			t.Fatal("new committee signature does not verify with old FROST instance")
		}
	})
}

func TestReshareFeldmanVSSFailure(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	// Create old member reshare state.
	rom, err := fOld.NewReshareOldMember(rand.Reader, oldShares[0], oldMemberIDs, fNew.threshold)
	if err != nil {
		t.Fatal(err)
	}
	defer rom.Zero()

	newID := fNew.scalarFromInt(1)
	rnm, err := fNew.NewReshareNewMember(newID)
	if err != nil {
		t.Fatalf("NewReshareNewMember failed: %v", err)
	}

	// Get an honest share and its commitments.
	privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
	if err != nil {
		t.Fatalf("ReshareOldMemberSendShare failed: %v", err)
	}

	// Tamper with the share: add a random scalar.
	tamper, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privData.Share = g.NewScalar().Add(privData.Share, tamper)

	// Verification should fail.
	err = fNew.ReshareNewMemberReceiveShare(rnm, privData, rom.Round1Broadcast().Commitments)
	if err == nil {
		t.Fatal("expected Feldman VSS error for tampered reshare share, got nil")
	}
}

func TestReshareDuplicateSender(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	rom, err := fOld.NewReshareOldMember(rand.Reader, oldShares[0], oldMemberIDs, fNew.threshold)
	if err != nil {
		t.Fatal(err)
	}
	defer rom.Zero()

	newID := fNew.scalarFromInt(1)
	rnm, err := fNew.NewReshareNewMember(newID)
	if err != nil {
		t.Fatalf("NewReshareNewMember failed: %v", err)
	}

	// Send the same share twice.
	privData, err := fOld.ReshareOldMemberSendShare(rom, newID)
	if err != nil {
		t.Fatalf("ReshareOldMemberSendShare failed: %v", err)
	}
	broadcast := rom.Round1Broadcast()

	err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcast.Commitments)
	if err != nil {
		t.Fatalf("first share should be accepted: %v", err)
	}

	// Second share from same sender should be rejected.
	err = fNew.ReshareNewMemberReceiveShare(rnm, privData, broadcast.Commitments)
	if err == nil {
		t.Fatal("expected error for duplicate sender, got nil")
	}
}

func TestReshareZeroNewMemberID(t *testing.T) {
	g := &bjj.BJJ{}

	fNew, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	// New member with ID=0 must be rejected.
	zeroID := g.NewScalar()
	_, err = fNew.NewReshareNewMember(zeroID)
	if err == nil {
		t.Fatal("expected error for zero new member ID, got nil")
	}
}

func TestReshareZeroRecipientID(t *testing.T) {
	g := &bjj.BJJ{}

	fOld, err := New(g, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	oldShares := runDKG(t, fOld, 3)

	oldMemberIDs := make([]group.Scalar, len(oldShares))
	for i, ks := range oldShares {
		oldMemberIDs[i] = ks.ID
	}

	rom, err := fOld.NewReshareOldMember(rand.Reader, oldShares[0], oldMemberIDs, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer rom.Zero()

	// Sending a share to ID=0 must be rejected.
	zeroID := g.NewScalar()
	_, err = fOld.ReshareOldMemberSendShare(rom, zeroID)
	if err == nil {
		t.Fatal("expected error for zero recipient ID, got nil")
	}
}
