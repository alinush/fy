package frost

import (
	"errors"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// ReshareOldMember holds the state for an old committee member during reshare.
// The member's secret share is Lagrange-weighted and split into a new polynomial
// of degree newThreshold-1, so the sum of all old members' constant terms
// reconstructs the original group secret.
type ReshareOldMember struct {
	id           group.Scalar
	coefficients []group.Scalar // coefficients[0] = lambda_i * s_i
	commitments  []group.Point
}

// ReshareNewMember holds the state for a new committee member during reshare.
// It accumulates verified shares from old committee members and finalizes
// into a new [KeyShare] once all shares are collected.
type ReshareNewMember struct {
	id             group.Scalar
	receivedShares map[string]group.Scalar
}

// ReshareRound1Data is the public data broadcast by an old committee member.
// All new members use this to verify received shares via Feldman VSS and to
// confirm group key preservation.
type ReshareRound1Data struct {
	ID          group.Scalar
	Commitments []group.Point
}

// ReshareRound1PrivateData is the private share sent from an old committee
// member to a new committee member. This data must be transmitted over a
// secure, authenticated channel.
type ReshareRound1PrivateData struct {
	FromID group.Scalar
	ToID   group.Scalar
	Share  group.Scalar
}

// NewReshareOldMember creates a reshare state for an old committee member.
// The caller must be the OLD FROST instance (old threshold/total).
//
// The oldMemberIDs slice lists all old members participating in the reshare;
// at least f.threshold must cooperate. The newThreshold parameter specifies
// the threshold for the new committee.
//
// The method computes the Lagrange coefficient for this member within the
// cooperating set, weights the secret key share, and generates a fresh
// polynomial of degree newThreshold-1 whose constant term is lambda_i * s_i.
func (f *FROST) NewReshareOldMember(r io.Reader, share *KeyShare, oldMemberIDs []group.Scalar, newThreshold int) (*ReshareOldMember, error) {
	if share.ID.IsZero() {
		return nil, errors.New("share ID must be non-zero")
	}
	if len(oldMemberIDs) < f.threshold {
		return nil, fmt.Errorf("need at least %d old members, got %d", f.threshold, len(oldMemberIDs))
	}
	if newThreshold < 2 {
		return nil, errors.New("new threshold must be at least 2")
	}

	// Check for duplicate IDs.
	seen := make(map[string]bool, len(oldMemberIDs))
	for _, id := range oldMemberIDs {
		key := string(id.Bytes())
		if seen[key] {
			return nil, errors.New("duplicate ID in old member list")
		}
		seen[key] = true
	}

	// Verify share.ID is present in oldMemberIDs.
	if !seen[string(share.ID.Bytes())] {
		return nil, errors.New("share ID not found in old member list")
	}

	// Compute Lagrange coefficient for this member within the cooperating set.
	lambda, err := f.lagrangeCoefficientFromIDs(share.ID, oldMemberIDs)
	if err != nil {
		return nil, fmt.Errorf("lagrange coefficient: %w", err)
	}

	// Build polynomial: coefficients[0] = lambda_i * s_i
	coeffs := make([]group.Scalar, newThreshold)
	coeffs[0] = f.group.NewScalar().Mul(lambda, share.SecretKey)

	// Zero the intermediate Lagrange coefficient to prevent memory residue.
	lambda.Zero()

	// Random coefficients for degrees 1..newThreshold-1.
	for i := 1; i < newThreshold; i++ {
		c, err := f.group.RandomScalar(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}

	// Compute commitments: C_i = coefficients[i] * G
	commits := make([]group.Point, newThreshold)
	for i, c := range coeffs {
		commits[i] = f.group.NewPoint().ScalarMult(c, f.group.Generator())
	}

	return &ReshareOldMember{
		id:           share.ID,
		coefficients: coeffs,
		commitments:  commits,
	}, nil
}

// Round1Broadcast returns the public data that this old member must broadcast
// to all new committee members.
func (rom *ReshareOldMember) Round1Broadcast() *ReshareRound1Data {
	return &ReshareRound1Data{
		ID:          rom.id,
		Commitments: rom.commitments,
	}
}

// ReshareOldMemberSendShare computes the private share that old member rom
// must send to the specified new committee member. The caller must be the
// OLD FROST instance.
func (f *FROST) ReshareOldMemberSendShare(rom *ReshareOldMember, newMemberID group.Scalar) (*ReshareRound1PrivateData, error) {
	if newMemberID.IsZero() {
		return nil, errors.New("new member ID must be non-zero")
	}
	share := f.evalPolynomial(rom.coefficients, newMemberID)
	return &ReshareRound1PrivateData{
		FromID: rom.id,
		ToID:   newMemberID,
		Share:  share,
	}, nil
}

// NewReshareNewMember creates a reshare state for a new committee member.
// The caller must be the NEW FROST instance (new threshold/total).
func (f *FROST) NewReshareNewMember(id group.Scalar) (*ReshareNewMember, error) {
	if id.IsZero() {
		return nil, errors.New("new member ID must be non-zero")
	}
	return &ReshareNewMember{
		id:             id,
		receivedShares: make(map[string]group.Scalar),
	}, nil
}

// ReshareNewMemberReceiveShare verifies a received share from an old member
// using Feldman VSS and stores it. The caller must be the NEW FROST instance.
//
// The verification checks: share * G == sum(Commitment[i] * recipientID^i).
//
// Session binding: each reshare run generates fresh random polynomial
// coefficients and commitments. A share replayed from a previous run will
// fail Feldman VSS verification against the current run's commitments.
func (f *FROST) ReshareNewMemberReceiveShare(rnm *ReshareNewMember, data *ReshareRound1PrivateData, senderCommitments []group.Point) error {
	// Feldman VSS verification: share * G == sum(Commitment[i] * recipientID^i)
	lhs := f.group.NewPoint().ScalarMult(data.Share, f.group.Generator())

	rhs := f.group.NewPoint()
	xPower := f.scalarFromInt(1)

	for _, commit := range senderCommitments {
		term := f.group.NewPoint().ScalarMult(xPower, commit)
		rhs = f.group.NewPoint().Add(rhs, term)
		xPower = f.group.NewScalar().Mul(xPower, data.ToID)
	}

	if !lhs.Equal(rhs) {
		return errors.New("invalid reshare share from old member")
	}

	key := string(data.FromID.Bytes())
	if _, exists := rnm.receivedShares[key]; exists {
		return errors.New("duplicate reshare share from old member")
	}
	rnm.receivedShares[key] = data.Share
	return nil
}

// ReshareFinalize completes the reshare protocol for new member rnm.
// The caller must be the NEW FROST instance.
//
// It verifies that the sum of all old members' Commitments[0] equals the
// expectedGroupKey (group key preservation), then computes the new secret
// share as the sum of all received partial shares.
func (f *FROST) ReshareFinalize(rnm *ReshareNewMember, allBroadcasts []*ReshareRound1Data, expectedGroupKey group.Point) (*KeyShare, error) {
	// Verify group key preservation: sum(Commitments[0]) == expectedGroupKey.
	commitSum := f.group.NewPoint()
	for _, b := range allBroadcasts {
		if len(b.Commitments) == 0 {
			return nil, errors.New("old member broadcast has no commitments")
		}
		commitSum = f.group.NewPoint().Add(commitSum, b.Commitments[0])
	}
	if !commitSum.Equal(expectedGroupKey) {
		return nil, errors.New("group key not preserved: sum of commitments[0] does not match expected group key")
	}

	// Verify we received shares from exactly the set of old members who broadcast.
	if len(rnm.receivedShares) != len(allBroadcasts) {
		return nil, fmt.Errorf("expected %d shares from old members, got %d", len(allBroadcasts), len(rnm.receivedShares))
	}
	for _, b := range allBroadcasts {
		if _, ok := rnm.receivedShares[string(b.ID.Bytes())]; !ok {
			return nil, errors.New("missing share from old member who broadcast commitments")
		}
	}

	// Compute new secret key: sum of all received shares.
	// Each old member already weighted their polynomial constant term by lambda_i,
	// so the sum yields a valid Shamir share of the original group secret.
	newSecret := f.group.NewScalar()
	for _, share := range rnm.receivedShares {
		newSecret = f.group.NewScalar().Add(newSecret, share)
	}

	newPublicKey := f.group.NewPoint().ScalarMult(newSecret, f.group.Generator())

	// Zero received shares to prevent memory residue.
	for key := range rnm.receivedShares {
		rnm.receivedShares[key].Zero()
	}
	rnm.receivedShares = nil

	return &KeyShare{
		ID:        rnm.id,
		SecretKey: newSecret,
		PublicKey: newPublicKey,
		GroupKey:  expectedGroupKey,
	}, nil
}

// Zero securely erases all secret material from the old member's reshare state.
// Callers MUST call this after all shares have been sent to new members.
// Unlike [FROST.RefreshFinalize] which auto-zeroes, the reshare protocol
// requires explicit cleanup because old and new members are separate roles.
func (rom *ReshareOldMember) Zero() {
	for i := range rom.coefficients {
		rom.coefficients[i].Zero()
	}
	rom.coefficients = nil
}

// Zero securely erases all secret material held by the reshare new member.
// Call this after [FROST.ReshareFinalize] to clean up accumulated shares.
func (rnm *ReshareNewMember) Zero() {
	for key := range rnm.receivedShares {
		rnm.receivedShares[key].Zero()
	}
	rnm.receivedShares = nil
}
