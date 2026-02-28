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

	return &frost.KeyShare{
		ID:        idScalar,
		SecretKey: output.SecretShare,
		PublicKey: output.PublicKeyShares[nodeID],
		GroupKey:  output.PublicKey,
	}, nil
}
