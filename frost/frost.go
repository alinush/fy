package frost

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/f3rmion/fy/group"
)

// MaxParticipants is the maximum number of participants supported.
// This limits resource usage (Poseidon sponge rounds, commitment encoding)
// while supporting any practical threshold signing configuration.
const MaxParticipants = 100

// Errors returned by the FROST protocol.
var (
	ErrInvalidCommitment = errors.New("invalid or empty commitment list")
)

// FROST holds the cryptographic group and threshold parameters for the
// FROST signature scheme. Create instances using [New] or [NewWithHasher].
type FROST struct {
	group     group.Group
	hasher    Hasher
	threshold int // t - minimum signers needed
	total     int // n - total participants
}

// KeyShare represents a participant's share of the distributed secret key.
// KeyShares are produced by the DKG protocol via [FROST.Finalize] and are
// used for signing operations.
type KeyShare struct {
	// ID is the unique identifier for this participant (1 to n).
	ID group.Scalar

	// SecretKey is this participant's share of the group secret key.
	// This value must be kept private.
	SecretKey group.Scalar

	// PublicKey is the public key corresponding to this participant's secret share.
	PublicKey group.Point

	// GroupKey is the combined group public key. This is the same for all
	// participants and is used to verify signatures.
	GroupKey group.Point
}

// Signature represents a Schnorr signature produced by the FROST protocol.
// It can be verified against the group public key using [FROST.Verify].
type Signature struct {
	// R is the commitment point (nonce point).
	R group.Point

	// Z is the response scalar.
	Z group.Scalar
}

// New creates a FROST instance with the given group and threshold parameters.
// It uses SHA-256 as the default hash function. Use [NewWithHasher] for
// alternative hash configurations such as Blake2b for Ledger compatibility.
//
// The threshold parameter specifies the minimum number of signers required (t)
// to produce a valid signature. It must be at least 2.
//
// The total parameter specifies the total number of participants (n) in the
// scheme. It must be greater than or equal to threshold.
func New(g group.Group, threshold, total int) (*FROST, error) {
	return NewWithHasher(g, threshold, total, &SHA256Hasher{})
}

// NewWithHasher creates a FROST instance with a custom hash function.
// Use this constructor for Ledger/iden3 compatibility with [Blake2bHasher]
// or other custom hash implementations.
//
// The total parameter must not exceed [MaxParticipants] (100).
//
// Example for Ledger compatibility:
//
//	f, err := frost.NewWithHasher(g, 2, 3, frost.NewBlake2bHasher())
func NewWithHasher(g group.Group, threshold, total int, hasher Hasher) (*FROST, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if total < threshold {
		return nil, errors.New("total must be >= threshold")
	}
	if total > MaxParticipants {
		return nil, fmt.Errorf("total participants %d exceeds maximum %d", total, MaxParticipants)
	}

	return &FROST{
		group:     g,
		hasher:    hasher,
		threshold: threshold,
		total:     total,
	}, nil
}

// scalarFromInt creates a scalar from a non-negative integer value.
// Supports values up to 2^32-1 (encoded as big-endian in a 32-byte buffer).
// Panics if n is negative (programmer error).
func (f *FROST) scalarFromInt(n int) group.Scalar {
	if n < 0 {
		panic("scalarFromInt: negative value")
	}
	s := f.group.NewScalar()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(n))
	// Values in [0, 2^32-1] are always within group order; panic indicates a bug.
	if _, err := s.SetBytes(buf); err != nil {
		panic("scalarFromInt: SetBytes failed for small integer: " + err.Error())
	}
	return s
}

// lagrangeCoefficientFromIDs computes the Lagrange basis polynomial
// evaluated at zero for participant myID within the set allIDs.
// Returns lambda_i = product(x_j) / product(x_j - x_i) for j != i.
func (f *FROST) lagrangeCoefficientFromIDs(myID group.Scalar, allIDs []group.Scalar) (group.Scalar, error) {
	num := f.scalarFromInt(1)
	den := f.scalarFromInt(1)

	for _, id := range allIDs {
		if id.Equal(myID) {
			continue
		}
		// num *= id
		num = f.group.NewScalar().Mul(num, id)
		// den *= (id - myID)
		diff := f.group.NewScalar().Sub(id, myID)
		den = f.group.NewScalar().Mul(den, diff)
	}

	denInv, err := f.group.NewScalar().Invert(den)
	if err != nil {
		return nil, errors.New("lagrange coefficient: zero denominator (duplicate IDs?)")
	}
	return f.group.NewScalar().Mul(num, denInv), nil
}

// evalPolynomial evaluates a polynomial at point x using Horner's method.
// The polynomial is represented by its coefficients [a0, a1, ..., an]
// where p(x) = a0 + a1*x + a2*x^2 + ... + an*x^n.
func (f *FROST) evalPolynomial(coeffs []group.Scalar, x group.Scalar) group.Scalar {
	result := f.group.NewScalar().Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = f.group.NewScalar().Mul(result, x)
		result = f.group.NewScalar().Add(result, coeffs[i])
	}
	return result
}
