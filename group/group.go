package group

import (
	"io"
)

// Scalar represents an element of the scalar field associated with a
// cryptographic group. Scalars are integers modulo the group order and
// are used as exponents in scalar multiplication.
//
// All arithmetic methods use a mutable receiver pattern: they modify
// the receiver, store the result in it, and return it. This allows for
// efficient method chaining while minimizing memory allocations.
//
// Implementations must ensure all operations produce results in the
// valid range [0, order).
type Scalar interface {
	// Add sets the receiver to a+b and returns it.
	Add(a, b Scalar) Scalar
	// Sub sets the receiver to a-b and returns it.
	Sub(a, b Scalar) Scalar
	// Mul sets the receiver to a*b and returns it.
	Mul(a, b Scalar) Scalar
	// Negate sets the receiver to -a and returns it.
	Negate(a Scalar) Scalar
	// Invert sets the receiver to a^{-1} and returns it.
	// Returns an error if a is zero.
	Invert(a Scalar) (Scalar, error)
	// Set sets the receiver to a and returns it.
	Set(a Scalar) Scalar
	// Bytes returns the canonical byte representation of the scalar.
	Bytes() []byte
	// SetBytes sets the receiver from a byte slice and returns it.
	// Returns an error if the data is invalid or out of range.
	SetBytes(data []byte) (Scalar, error)
	// Equal reports whether the receiver equals b.
	Equal(b Scalar) bool
	// IsZero reports whether the receiver is zero.
	IsZero() bool
	// Zero sets the receiver to zero and securely erases the previous value
	// from the underlying memory. Use this instead of Set(NewScalar()) when
	// zeroing secret scalars (nonces, key shares) to prevent memory residue.
	Zero()
}

// Point represents an element of a cryptographic group, typically a point
// on an elliptic curve. Points support addition, subtraction, negation,
// and scalar multiplication.
//
// Like [Scalar], all arithmetic methods use a mutable receiver pattern
// for efficiency.
//
// The identity element (zero point, point at infinity) is the additive
// identity: P + Identity = P for all points P.
type Point interface {
	// Add sets the receiver to a+b and returns it.
	Add(a, b Point) Point
	// Sub sets the receiver to a-b and returns it.
	Sub(a, b Point) Point
	// Negate sets the receiver to -a and returns it.
	Negate(a Point) Point
	// ScalarMult sets the receiver to s*p and returns it.
	ScalarMult(s Scalar, p Point) Point
	// Set sets the receiver to a and returns it.
	Set(a Point) Point
	// Bytes returns the canonical byte representation of the point.
	Bytes() []byte
	// SetBytes sets the receiver from a byte slice and returns it.
	// Returns an error if the data is invalid or out of range.
	SetBytes(data []byte) (Point, error)
	// Equal reports whether the receiver equals b.
	Equal(b Point) bool
	// IsIdentity reports whether the receiver is the identity element.
	IsIdentity() bool
	// Zero sets the receiver to the identity element and securely erases the
	// previous coordinate values from underlying memory. Use this when zeroing
	// intermediate curve points that held secret-derived data (e.g., DH shared
	// secrets) to prevent memory residue.
	Zero()
}

// Group defines a cryptographic group suitable for use with FROST threshold
// signatures. It provides factory methods for creating scalars and points,
// access to the group's generator, and utility functions for random scalar
// generation and hashing.
//
// A Group implementation encapsulates all curve-specific details, allowing
// the FROST implementation to be generic over different elliptic curves.
//
// Example usage:
//
//	g := &bjj.BJJ{}  // or any other Group implementation
//	scalar, _ := g.RandomScalar(rand.Reader)
//	point := g.NewPoint().ScalarMult(scalar, g.Generator())
type Group interface {
	// NewScalar returns a new zero scalar.
	NewScalar() Scalar
	// NewPoint returns a new identity point.
	NewPoint() Point
	// Generator returns the group's base point.
	Generator() Point
	// RandomScalar returns a cryptographically random scalar.
	RandomScalar(r io.Reader) (Scalar, error)
	// HashToScalar hashes the input data to a scalar.
	HashToScalar(data ...[]byte) (Scalar, error)
	// Order returns the group order as a byte slice.
	Order() []byte
}
