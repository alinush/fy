package golden

import (
	"encoding/binary"
	"fmt"

	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/group"
)

// DkgOutputToKeyShare converts a GOLDEN DKG output into a FROST KeyShare.
// The returned KeyShare is compatible with the existing FROST signing protocol.
//
// The outerGroup parameter should be the outer (commitment/VSS) group, matching
// the group used for the DKG polynomial and VSS commitments.
//
// The nodeID encoding uses big-endian uint32 at bytes [28:32] of a 32-byte
// buffer, matching frost.scalarFromInt's encoding.
//
// Callers must ensure that nodeIDs are unique across all participants in a
// signing group. Duplicate nodeIDs would produce identical Lagrange coefficients,
// causing signature share aggregation to fail or produce invalid signatures.
//
// Returns an error if nodeID is out of the valid range [1, MaxNodeID].
func DkgOutputToKeyShare(outerGroup group.Group, nodeID int, output *DkgOutput) (*frost.KeyShare, error) {
	if output == nil {
		return nil, fmt.Errorf("golden: DkgOutputToKeyShare: nil DkgOutput")
	}
	if nodeID < 1 || nodeID > MaxNodeID {
		return nil, fmt.Errorf("golden: DkgOutputToKeyShare: nodeID %d out of range [1, %d]", nodeID, MaxNodeID)
	}

	// Encode ID the same way frost.scalarFromInt does.
	idScalar := outerGroup.NewScalar()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(nodeID))
	if _, err := idScalar.SetBytes(buf); err != nil {
		return nil, fmt.Errorf("golden: DkgOutputToKeyShare: invalid nodeID encoding: %w", err)
	}

	// Deep-copy all fields to avoid shared references between the DkgOutput
	// and the returned KeyShare. This ensures that zeroing the DkgOutput
	// does not invalidate the KeyShare (and vice versa).
	secretCopy := outerGroup.NewScalar().Set(output.SecretShare)
	return &frost.KeyShare{
		ID:        idScalar,
		SecretKey: secretCopy,
		PublicKey: outerGroup.NewPoint().Set(output.PublicKeyShares[nodeID]),
		GroupKey:  outerGroup.NewPoint().Set(output.PublicKey),
	}, nil
}

// DkgOutputToDerivedKeyShare converts a DerivedOutput into a FROST KeyShare
// for use with threshold signing on the derived group.
//
// The g parameter must be the derived group (e.g., bjj.BJJ) matching the
// DerivedOutput.Group. The nodeID encoding uses the same big-endian uint32
// convention as DkgOutputToKeyShare.
func DkgOutputToDerivedKeyShare(g group.Group, nodeID int, derived *DerivedOutput) (*frost.KeyShare, error) {
	if derived == nil {
		return nil, fmt.Errorf("golden: DkgOutputToDerivedKeyShare: nil DerivedOutput")
	}
	if nodeID < 1 || nodeID > MaxNodeID {
		return nil, fmt.Errorf("golden: DkgOutputToDerivedKeyShare: nodeID %d out of range [1, %d]", nodeID, MaxNodeID)
	}

	// Encode ID the same way frost.scalarFromInt does.
	idScalar := g.NewScalar()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(nodeID))
	if _, err := idScalar.SetBytes(buf); err != nil {
		return nil, fmt.Errorf("golden: DkgOutputToDerivedKeyShare: invalid nodeID encoding: %w", err)
	}

	// Deep-copy all fields to avoid shared references between the DerivedOutput
	// and the returned KeyShare (see DkgOutputToKeyShare for rationale).
	secretCopy := g.NewScalar().Set(derived.SecretShare)
	return &frost.KeyShare{
		ID:        idScalar,
		SecretKey: secretCopy,
		PublicKey: g.NewPoint().Set(derived.PublicKeyShares[nodeID]),
		GroupKey:  g.NewPoint().Set(derived.PublicKey),
	}, nil
}

// NewPiggybackSession creates a PiggybackNonceState from a GOLDEN DKG output.
// This is a convenience wrapper that converts the DKG output to a FROST KeyShare
// and then creates a piggyback state from it.
//
// The outerGroup parameter should be the outer (commitment/VSS) group.
// Returns an error if nodeID is out of the valid range [1, MaxNodeID].
func NewPiggybackSession(outerGroup group.Group, nodeID int, output *DkgOutput) (*frost.PiggybackNonceState, error) {
	ks, err := DkgOutputToKeyShare(outerGroup, nodeID, output)
	if err != nil {
		return nil, fmt.Errorf("golden: NewPiggybackSession: %w", err)
	}
	return frost.NewPiggybackState(ks), nil
}

// NewDerivedPiggybackSession creates a PiggybackNonceState from a GOLDEN
// DerivedOutput for use with threshold signing on a derived group.
//
// The g parameter must be the derived group (e.g., bjj.BJJ) matching the
// DerivedOutput.Group. Returns an error if nodeID is out of range [1, MaxNodeID].
func NewDerivedPiggybackSession(g group.Group, nodeID int, derived *DerivedOutput) (*frost.PiggybackNonceState, error) {
	ks, err := DkgOutputToDerivedKeyShare(g, nodeID, derived)
	if err != nil {
		return nil, fmt.Errorf("golden: NewDerivedPiggybackSession: %w", err)
	}
	return frost.NewPiggybackState(ks), nil
}
