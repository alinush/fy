// Package secp256k1 implements the secp256k1 elliptic curve for use with FROST
// threshold signatures. This curve is used by Bitcoin, Ethereum, and other
// blockchain systems.
//
// The implementation wraps github.com/decred/dcrd/dcrec/secp256k1/v4 which
// provides constant-time, well-tested implementations of secp256k1 operations.
package secp256k1

import (
	"crypto/sha256"
	"errors"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/f3rmion/fy/group"
)

// Scalar represents an element of the secp256k1 scalar field.
// It implements [group.Scalar] using dcrd's constant-time ModNScalar.
//
// All arithmetic operations automatically reduce results modulo the
// curve order to maintain valid scalar values.
type Scalar struct {
	inner secp256k1.ModNScalar
}

// newScalar creates a new scalar initialized to zero.
func newScalar() *Scalar {
	return &Scalar{}
}

// Add sets s to a + b (mod n) and returns s.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Add2(&aScalar.inner, &bScalar.inner)
	return s
}

// Sub sets s to a - b (mod n) and returns s.
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	// a - b = a + (-b)
	var negB secp256k1.ModNScalar
	negB.NegateVal(&bScalar.inner)
	s.inner.Add2(&aScalar.inner, &negB)
	return s
}

// Mul sets s to a * b (mod n) and returns s.
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Mul2(&aScalar.inner, &bScalar.inner)
	return s
}

// Negate sets s to -a (mod n) and returns s.
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.NegateVal(&aScalar.inner)
	return s
}

// Invert sets s to a^(-1) (mod n) and returns s.
// Returns an error if a is zero, as zero has no multiplicative inverse.
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := a.(*Scalar)
	if aScalar.inner.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.InverseValNonConst(&aScalar.inner)
	return s, nil
}

// Set copies the value of a into s and returns s.
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Set(&aScalar.inner)
	return s
}

// Bytes returns the scalar as a 32-byte big-endian representation.
func (s *Scalar) Bytes() []byte {
	var bytes [32]byte
	s.inner.PutBytes(&bytes)
	return bytes[:]
}

// SetBytes sets s from a big-endian byte slice and returns s.
// The value is reduced modulo the curve order.
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	// Pad or truncate to 32 bytes
	var bytes [32]byte
	if len(data) >= 32 {
		copy(bytes[:], data[:32])
	} else {
		copy(bytes[32-len(data):], data)
	}
	// SetBytes returns overflow flag but we want to reduce mod n
	s.inner.SetBytes(&bytes)
	return s, nil
}

// Equal reports whether s and b represent the same scalar value.
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := b.(*Scalar)
	return s.inner.Equals(&bScalar.inner)
}

// IsZero reports whether s is the zero scalar.
func (s *Scalar) IsZero() bool {
	return s.inner.IsZero()
}

// Point represents a point on the secp256k1 curve.
// It implements [group.Point] using dcrd's JacobianPoint for efficient
// point arithmetic.
//
// The identity element is the point at infinity.
type Point struct {
	inner secp256k1.JacobianPoint
}

// newPoint creates a new point initialized to the identity (point at infinity).
func newPoint() *Point {
	var p Point
	// JacobianPoint zero value is the identity
	return &p
}

// Add sets p to a + b and returns p.
func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	secp256k1.AddNonConst(&aPoint.inner, &bPoint.inner, &p.inner)
	return p
}

// Sub sets p to a - b and returns p.
func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	// a - b = a + (-b)
	var negB secp256k1.JacobianPoint
	negB.Set(&bPoint.inner)
	negB.Y.Negate(1)
	negB.Y.Normalize()
	secp256k1.AddNonConst(&aPoint.inner, &negB, &p.inner)
	return p
}

// Negate sets p to -a and returns p.
func (p *Point) Negate(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Set(&aPoint.inner)
	p.inner.Y.Negate(1)
	p.inner.Y.Normalize()
	return p
}

// ScalarMult sets p to s * q and returns p.
func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := s.(*Scalar)
	qPoint := q.(*Point)
	secp256k1.ScalarMultNonConst(&scalar.inner, &qPoint.inner, &p.inner)
	return p
}

// Set copies the value of a into p and returns p.
func (p *Point) Set(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Set(&aPoint.inner)
	return p
}

// Bytes returns the compressed point encoding (33 bytes: prefix || x).
// The prefix is 0x02 for even y, 0x03 for odd y.
// Returns 33 zero bytes for the identity point.
func (p *Point) Bytes() []byte {
	if p.IsIdentity() {
		return make([]byte, 33)
	}
	// Convert to affine and get public key bytes
	p.inner.ToAffine()
	pk := secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y)
	return pk.SerializeCompressed()
}

// SetBytes sets p from point bytes and returns p.
// Accepts both 33-byte compressed and 65-byte uncompressed formats.
// Returns an error if the data does not represent a valid curve point.
func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if len(data) == 33 && data[0] == 0 {
		// All zeros = identity point
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			p.inner = secp256k1.JacobianPoint{}
			return p, nil
		}
	}

	pk, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	pk.AsJacobian(&p.inner)
	return p, nil
}

// UncompressedBytes returns the 65-byte uncompressed point encoding.
// Format: 0x04 || x (32 bytes) || y (32 bytes).
// Returns 65 zero bytes for the identity point.
func (p *Point) UncompressedBytes() []byte {
	if p.IsIdentity() {
		return make([]byte, 65)
	}
	p.inner.ToAffine()
	pk := secp256k1.NewPublicKey(&p.inner.X, &p.inner.Y)
	return pk.SerializeUncompressed()
}

// Equal reports whether p and b represent the same curve point.
func (p *Point) Equal(b group.Point) bool {
	bPoint := b.(*Point)
	// Convert both to affine for comparison
	var pAffine, bAffine secp256k1.JacobianPoint
	pAffine.Set(&p.inner)
	bAffine.Set(&bPoint.inner)
	pAffine.ToAffine()
	bAffine.ToAffine()

	// Handle identity points
	pIsIdentity := pAffine.X.IsZero() && pAffine.Y.IsZero()
	bIsIdentity := bAffine.X.IsZero() && bAffine.Y.IsZero()
	if pIsIdentity && bIsIdentity {
		return true
	}
	if pIsIdentity != bIsIdentity {
		return false
	}

	return pAffine.X.Equals(&bAffine.X) && pAffine.Y.Equals(&bAffine.Y)
}

// IsIdentity reports whether p is the identity element (point at infinity).
func (p *Point) IsIdentity() bool {
	// In Jacobian coordinates, identity has Z=0
	return p.inner.Z.IsZero()
}

// Secp256k1 implements [group.Group] for the secp256k1 curve.
//
// Secp256k1 is a zero-sized type that provides access to secp256k1 curve
// operations. Create an instance with New() or &Secp256k1{}.
type Secp256k1 struct{}

// New creates a new Secp256k1 group instance.
func New() *Secp256k1 {
	return &Secp256k1{}
}

// NewScalar returns a new scalar initialized to zero.
func (g *Secp256k1) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint returns a new point initialized to the identity element.
func (g *Secp256k1) NewPoint() group.Point {
	return newPoint()
}

// Generator returns the standard base point G for the secp256k1 curve.
func (g *Secp256k1) Generator() group.Point {
	// secp256k1 generator point (compressed)
	// 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	genBytes := []byte{
		0x02,
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}
	pk, _ := secp256k1.ParsePubKey(genBytes)
	var p Point
	pk.AsJacobian(&p.inner)
	return &p
}

// RandomScalar generates a cryptographically random scalar using the
// provided random source. The result is uniformly distributed in
// [1, n-1] where n is the curve order.
func (g *Secp256k1) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		s := newScalar()
		// SetBytes returns overflow (value >= n), we want to retry in that case
		// to get uniform distribution
		overflow := s.inner.SetBytes(&buf)
		if overflow == 0 && !s.inner.IsZero() {
			return s, nil
		}
	}
}

// HashToScalar hashes the provided data to a scalar using SHA-256.
// Multiple byte slices are concatenated before hashing.
// The result is reduced modulo the curve order.
func (g *Secp256k1) HashToScalar(data ...[]byte) (group.Scalar, error) {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)

	s := newScalar()
	var bytes [32]byte
	copy(bytes[:], hash)
	s.inner.SetBytes(&bytes)
	return s, nil
}

// Order returns the order of the secp256k1 curve as a big-endian byte slice.
// This is the order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
func (g *Secp256k1) Order() []byte {
	// secp256k1 curve order
	return []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}
}
