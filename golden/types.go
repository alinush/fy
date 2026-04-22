package golden

import (
	"errors"

	"github.com/f3rmion/fy/group"
)

const (
	// MaxNodeID is the maximum allowed NodeID value.
	// NodeIDs are encoded as uint32 in scalar representations, so this prevents overflow.
	MaxNodeID = 1<<31 - 1 // math.MaxInt32

	// lhlAlphaDomain is the domain separator for deriving the LHL combination
	// coefficient alpha in the eVRF pad construction.
	lhlAlphaDomain = "golden-lhl-alpha"

	// pvssBatchDomain is the domain separator for the Fiat-Shamir challenge
	// used to fold the N per-player VSS consistency checks in PVSSVerify into
	// a single randomized linear combination.
	pvssBatchDomain = "golden-pvss-batch-v1"
)

// SessionID uniquely identifies a DKG session.
type SessionID [32]byte

// NodeID identifies a participant in the DKG protocol.
// Must be >= 1.
type NodeID = int

// DkgConfig holds parameters for a GOLDEN DKG session.
type DkgConfig struct {
	// N is the total number of participants.
	N int
	// T is the threshold (minimum signers for FROST, must be >= 2 for FROST compatibility).
	T int
	// SessionID uniquely identifies this DKG session.
	SessionID SessionID
	// DerivedGroups lists additional groups for which Shamir shares should
	// be derived from the same polynomial. Coefficients are reduced mod each
	// group's scalar field order via SetBytes. For example, [bjj.BJJ, secp256k1.Secp256k1]
	// would produce BJJ and secp256k1 key shares alongside the primary BN254 G1 output.
	//
	// The slice index is used as the key for parallel arrays throughout the protocol:
	// Round0Msg.DerivedCurves[i], DkgDealing.DerivedPrivateShares[i], and
	// DkgOutput.DerivedOutputs[i] all correspond to DerivedGroups[i].
	DerivedGroups []group.Group
}

// Participant holds a node's identity and key material.
type Participant struct {
	ID NodeID
	SK group.Scalar // inner-curve secret key
	PK group.Point  // inner-curve public key = SK * G_inner
}

// Ciphertext is an encrypted share from dealer to recipient.
type Ciphertext struct {
	// RCommitment is the pad commitment: pad * G_outer.
	RCommitment group.Point
	// EncryptedShare is z = pad + share in Fr.
	EncryptedShare group.Scalar
}

// DerivedCurveData holds broadcast data for a single derived curve.
// The pad for each ciphertext is the BN254 pad reduced mod the derived group order.
type DerivedCurveData struct {
	VSSCommitments []group.Point       // derived-group commitments to reduced coefficients
	Ciphertexts    map[int]*Ciphertext // keyed by recipient NodeID
}

// DerivedOutput holds DKG output for a single derived curve.
type DerivedOutput struct {
	Group           group.Group
	PublicKey       group.Point
	PublicKeyShares map[int]group.Point
	SecretShare     group.Scalar
}

// Round0Msg is the broadcast message from a dealer in the non-interactive DKG.
// VSSCommitments[0] = omega * G_outer serves as the PK contribution for the group key.
type Round0Msg struct {
	SessionID      SessionID
	From           NodeID
	RandomMsg      [32]byte
	VSSCommitments []group.Point       // outer-group commitments to polynomial coefficients
	Ciphertexts    map[int]*Ciphertext // keyed by recipient NodeID
	IdentityProof  *IdentityProof      // Schnorr proof of inner-curve PK ownership
	EVRFProofs     map[int][]byte      // keyed by recipient NodeID, serialized PLONK proofs
	// DerivedCurves holds per-derived-group VSS commitments and ciphertexts.
	// Parallel to config.DerivedGroups; nil when no derived groups are configured.
	DerivedCurves []*DerivedCurveData
}

// DkgDealing bundles a broadcast message with the dealer's own private share.
type DkgDealing struct {
	Message      *Round0Msg
	PrivateShare group.Scalar // dealer's own Shamir share (Fr)
	// DerivedPrivateShares holds the dealer's own shares for each derived group.
	// Parallel to config.DerivedGroups; nil when no derived groups are configured.
	DerivedPrivateShares []group.Scalar
}

// Zero zeroes local secret material in DkgDealing (PrivateShare,
// DerivedPrivateShares, and RandomMsg). Broadcast data in Round0Msg
// (ciphertext encrypted shares, VSS commitments) is not zeroed since
// it is public on the wire. Callers should invoke this after Complete() returns.
func (d *DkgDealing) Zero() {
	if d.PrivateShare != nil {
		d.PrivateShare.Zero()
	}
	for _, s := range d.DerivedPrivateShares {
		if s != nil {
			s.Zero()
		}
	}
	// Zero the random nonce used in session data derivation.
	if d.Message != nil {
		for i := range d.Message.RandomMsg {
			d.Message.RandomMsg[i] = 0
		}
	}
}

// DkgOutput is the result of a completed DKG for one participant.
type DkgOutput struct {
	// PublicKey is the group public key (sum of all VSSCommitments[0]).
	PublicKey group.Point
	// PublicKeyShares maps NodeID -> individual public key share for all participants.
	PublicKeyShares map[int]group.Point
	// SecretShare is this participant's aggregated secret share (Fr).
	SecretShare group.Scalar
	// DerivedOutputs holds outputs for each derived group.
	// Parallel to config.DerivedGroups; nil when no derived groups are configured.
	DerivedOutputs []*DerivedOutput
}

// Sentinel errors for the GOLDEN DKG protocol.
var (
	ErrInvalidNodeID                 = errors.New("golden: NodeID must be in [1, MaxNodeID]")
	ErrInvalidConfig                 = errors.New("golden: invalid DKG config (need T >= 2, N >= T)")
	ErrDuplicateNodeID               = errors.New("golden: duplicate NodeID")
	ErrPeerCountMismatch             = errors.New("golden: peer count must equal N-1")
	ErrSessionIDMismatch             = errors.New("golden: session ID mismatch")
	ErrIdentityPoint                 = errors.New("golden: point is identity")
	ErrCiphertextVerification        = errors.New("golden: ciphertext verification failed")
	ErrDegenerateDH                  = errors.New("golden: degenerate DH shared secret (identity point)")
	ErrIdentityProofFailed           = errors.New("golden: identity proof verification failed")
	ErrEVRFProofFailed               = errors.New("golden: eVRF proof verification failed")
	ErrHashToCurveFailed             = errors.New("golden: hash-to-curve failed after max iterations")
	ErrInvalidVSSLength              = errors.New("golden: VSS commitments length does not match threshold")
	ErrMissingCiphertext             = errors.New("golden: missing ciphertext for expected recipient")
	ErrMissingEVRFProof              = errors.New("golden: missing eVRF proof for expected recipient")
	ErrDealerSelfCiphertext          = errors.New("golden: dealer included ciphertext for self")
	ErrIdentityRCommitment           = errors.New("golden: R commitment is identity point")
	ErrDuplicateDealing              = errors.New("golden: duplicate dealing from same dealer")
	ErrUnknownDealer                 = errors.New("golden: dealing from unknown participant")
	ErrSelfDealing                   = errors.New("golden: received own dealing in peer dealings")
	ErrProofTooLarge                 = errors.New("golden: proof exceeds maximum size")
	ErrNodeIDExceedsN                = errors.New("golden: NodeID exceeds N")
	ErrExtraCiphertexts              = errors.New("golden: unexpected extra ciphertexts in dealing")
	ErrExtraEVRFProofs               = errors.New("golden: unexpected extra eVRF proofs in dealing")
	ErrNilIdentityProof              = errors.New("golden: nil identity proof in dealing")
	ErrNilCiphertext                 = errors.New("golden: nil ciphertext entry in dealing")
	ErrNilSuite                      = errors.New("golden: nil CurveSuite")
	ErrDerivedCurveCountMismatch     = errors.New("golden: derived curve count does not match config")
	ErrDerivedCiphertextVerification = errors.New("golden: derived curve ciphertext verification failed")
)

// Zero zeroes the secret material in DkgOutput, including all derived shares.
// Callers should invoke this after converting to FROST KeyShares.
func (o *DkgOutput) Zero() {
	if o.SecretShare != nil {
		o.SecretShare.Zero()
	}
	for _, d := range o.DerivedOutputs {
		if d != nil && d.SecretShare != nil {
			d.SecretShare.Zero()
		}
	}
}
