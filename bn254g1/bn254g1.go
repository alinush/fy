// Package bn254g1 implements the BN254 G1 elliptic curve group for use with
// FROST threshold signatures and other cryptographic protocols.
//
// The BN254 curve (also known as alt_bn128) is widely used in Ethereum and
// zero-knowledge proof systems. This implementation wraps gnark-crypto's
// BN254 G1 types, using fr.Element for scalars and G1Affine/G1Jac for points.
//
// The scalar field order r is approximately 2^254, and the group is of
// prime order (cofactor 1), so every non-identity point is in the correct
// subgroup.
package bn254g1

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/f3rmion/fy/group"
)

// Scalar represents an element of the BN254 scalar field (Fr).
// It implements [group.Scalar] using gnark-crypto's fr.Element which
// stores values in Montgomery form as [4]uint64.
//
// All arithmetic operations automatically reduce results modulo the
// field order to maintain valid scalar values.
type Scalar struct {
	inner fr.Element
}

// newScalar creates a new scalar initialized to zero.
func newScalar() *Scalar {
	return &Scalar{}
}

// assertScalar asserts that s is a *Scalar.
// Panics with a descriptive message if s is a different group.Scalar implementation.
// This is by design: mixing scalar types from different groups is a programming error.
func assertScalar(s group.Scalar) *Scalar {
	v, ok := s.(*Scalar)
	if !ok {
		panic(fmt.Sprintf("bn254g1: expected *bn254g1.Scalar, got %T (do not mix group implementations)", s))
	}
	return v
}

// assertPoint asserts that p is a *Point.
// Panics with a descriptive message if p is a different group.Point implementation.
// This is by design: mixing point types from different groups is a programming error.
func assertPoint(p group.Point) *Point {
	v, ok := p.(*Point)
	if !ok {
		panic(fmt.Sprintf("bn254g1: expected *bn254g1.Point, got %T (do not mix group implementations)", p))
	}
	return v
}

// Add sets s to a + b (mod r) and returns s.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Add(&aScalar.inner, &bScalar.inner)
	return s
}

// Sub sets s to a - b (mod r) and returns s.
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Sub(&aScalar.inner, &bScalar.inner)
	return s
}

// Mul sets s to a * b (mod r) and returns s.
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Mul(&aScalar.inner, &bScalar.inner)
	return s
}

// Negate sets s to -a (mod r) and returns s.
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	s.inner.Neg(&aScalar.inner)
	return s
}

// Invert sets s to a^(-1) (mod r) and returns s.
// Returns an error if a is zero, as zero has no multiplicative inverse.
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := assertScalar(a)
	if aScalar.inner.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.Inverse(&aScalar.inner)
	return s, nil
}

// Set copies the value of a into s and returns s.
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	s.inner.Set(&aScalar.inner)
	return s
}

// Bytes returns the scalar as a 32-byte big-endian representation.
// Uses fr.Element.Marshal() which returns the canonical big-endian form.
func (s *Scalar) Bytes() []byte {
	b := s.inner.Marshal()
	return b
}

// SetBytes sets s from a big-endian byte slice and returns s.
// For inputs up to 32 bytes, the value is set via SetBytesCanonical (must be < r).
// For inputs up to 64 bytes (hash-to-field with 128-bit security margin),
// the value is reduced modulo r via big.Int.
// Returns an error if the input exceeds 64 bytes or is not a valid field element.
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	if len(data) > 64 {
		return nil, errors.New("scalar input exceeds 64 bytes")
	}
	if len(data) <= 32 {
		// Pad to 32 bytes for SetBytesCanonical
		var buf [fr.Bytes]byte
		copy(buf[32-len(data):], data)
		if err := s.inner.SetBytesCanonical(buf[:]); err != nil {
			// If canonical fails (value >= r), fall back to big.Int reduction
			n := new(big.Int).SetBytes(data)
			n.Mod(n, fr.Modulus())
			// Convert reduced value back to bytes and set canonically
			reduced := n.Bytes()
			var buf2 [fr.Bytes]byte
			copy(buf2[32-len(reduced):], reduced)
			if err2 := s.inner.SetBytesCanonical(buf2[:]); err2 != nil {
				return nil, err2
			}
		}
		return s, nil
	}
	// For 33-64 byte inputs (hash-to-field expansion), reduce mod r via big.Int
	n := new(big.Int).SetBytes(data)
	n.Mod(n, fr.Modulus())
	reduced := n.Bytes()
	var buf [fr.Bytes]byte
	copy(buf[32-len(reduced):], reduced)
	if err := s.inner.SetBytesCanonical(buf[:]); err != nil {
		return nil, err
	}
	return s, nil
}

// Equal reports whether s and b represent the same scalar value.
// fr.Element maintains canonical Montgomery form, so direct comparison works.
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := assertScalar(b)
	return s.inner == bScalar.inner
}

// IsZero reports whether s is the zero scalar.
func (s *Scalar) IsZero() bool {
	return s.inner.IsZero()
}

// Zero sets the scalar to zero, securely erasing the previous value.
// Explicitly zeros all 4 internal uint64 limbs for defense-in-depth
// before calling SetZero.
func (s *Scalar) Zero() {
	s.inner[0] = 0
	s.inner[1] = 0
	s.inner[2] = 0
	s.inner[3] = 0
	s.inner.SetZero()
}

// Point represents a point on the BN254 G1 curve.
// It implements [group.Point] by wrapping gnark-crypto's G1Affine.
//
// Points are stored in affine coordinates (X, Y). The identity element
// is the point at infinity (represented by the zero value of G1Affine).
type Point struct {
	inner bn254.G1Affine
}

// Add sets p to a + b and returns p.
// Converts to Jacobian coordinates for the addition, then back to affine.
func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := assertPoint(a)
	bPoint := assertPoint(b)
	var aJac, bJac bn254.G1Jac
	aJac.FromAffine(&aPoint.inner)
	bJac.FromAffine(&bPoint.inner)
	aJac.AddAssign(&bJac)
	p.inner.FromJacobian(&aJac)
	return p
}

// Sub sets p to a - b and returns p.
// Negates b then adds to a.
func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := assertPoint(a)
	bPoint := assertPoint(b)
	var negB bn254.G1Affine
	negB.Neg(&bPoint.inner)
	var aJac, negBJac bn254.G1Jac
	aJac.FromAffine(&aPoint.inner)
	negBJac.FromAffine(&negB)
	aJac.AddAssign(&negBJac)
	p.inner.FromJacobian(&aJac)
	return p
}

// Negate sets p to -a and returns p.
func (p *Point) Negate(a group.Point) group.Point {
	aPoint := assertPoint(a)
	p.inner.Neg(&aPoint.inner)
	return p
}

// ScalarMult sets p to s * q and returns p.
// Converts the scalar to big.Int for use with gnark-crypto's ScalarMultiplication.
func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := assertScalar(s)
	qPoint := assertPoint(q)
	bigInt := new(big.Int)
	scalar.inner.BigInt(bigInt)
	p.inner.ScalarMultiplication(&qPoint.inner, bigInt)
	return p
}

// Set copies the value of a into p and returns p.
func (p *Point) Set(a group.Point) group.Point {
	aPoint := assertPoint(a)
	p.inner = aPoint.inner
	return p
}

// Bytes returns the uncompressed point encoding as a byte slice (64 bytes: X || Y).
// Uses gnark-crypto's Marshal() which returns the uncompressed affine coordinates.
func (p *Point) Bytes() []byte {
	b := p.inner.Marshal()
	return b
}

// SetBytes sets p from a byte encoding and returns p.
// Accepts gnark-crypto's serialization formats (compressed or uncompressed).
// Returns an error if the data does not represent a valid curve point.
func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if err := p.inner.Unmarshal(data); err != nil {
		return nil, err
	}
	return p, nil
}

// Equal reports whether p and b represent the same curve point.
func (p *Point) Equal(b group.Point) bool {
	bPoint := assertPoint(b)
	return p.inner.Equal(&bPoint.inner)
}

// IsIdentity reports whether p is the identity element (point at infinity).
func (p *Point) IsIdentity() bool {
	return p.inner.IsInfinity()
}

// BN254G1 implements [group.Group] for the BN254 G1 curve.
//
// BN254G1 is a zero-sized type that provides access to BN254 G1 curve
// operations. Create an instance with &BN254G1{} or new(BN254G1).
type BN254G1 struct{}

// NewScalar returns a new scalar initialized to zero.
func (g *BN254G1) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint returns a new point initialized to the identity element
// (point at infinity). The zero value of G1Affine is the identity.
func (g *BN254G1) NewPoint() group.Point {
	var p Point
	// G1Affine zero value is the point at infinity
	return &p
}

// Generator returns the standard base point G1 for the BN254 curve.
func (g *BN254G1) Generator() group.Point {
	_, _, g1, _ := bn254.Generators()
	var p Point
	p.inner = g1
	return &p
}

// RandomScalar generates a cryptographically random scalar using the
// provided random source. The result is uniformly distributed in
// [1, r-1] where r is the scalar field order, using rejection sampling.
func (g *BN254G1) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	// With top-2-bit masking, range is [0, 2^254). Acceptance rate ~= r/2^254 ~= 87%.
	// Expected ~1.15 iterations. 1000 limit gives negligible false failure probability.
	for attempt := 0; attempt < 1000; attempt++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		// Mask top 2 bits to bring range close to ~254-bit order,
		// improving acceptance rate.
		buf[0] &= 0x3F

		s := newScalar()
		if err := s.inner.SetBytesCanonical(buf[:]); err != nil {
			continue // value >= r, reject
		}
		if s.inner.IsZero() {
			continue // reject zero
		}
		return s, nil
	}
	return nil, errors.New("RandomScalar: rejection sampling did not converge")
}

// HashToScalar hashes the provided data to a scalar using SHA-256.
// Each input is length-prefixed with a 4-byte big-endian length before hashing.
// Uses hash-to-field expansion (64 bytes) for uniform reduction (bias < 2^-128).
func (g *BN254G1) HashToScalar(data ...[]byte) (group.Scalar, error) {
	hashWith := func(counter byte) []byte {
		h := sha256.New()
		for _, d := range data {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(d)))
			h.Write(lenBuf[:])
			h.Write(d)
		}
		h.Write([]byte{counter})
		return h.Sum(nil)
	}

	expanded := make([]byte, 64)
	copy(expanded[:32], hashWith(0x00))
	copy(expanded[32:], hashWith(0x01))

	// Interpret as big-endian integer and reduce mod r
	n := new(big.Int).SetBytes(expanded)
	n.Mod(n, fr.Modulus())

	s := newScalar()
	reduced := n.Bytes()
	var buf [fr.Bytes]byte
	copy(buf[32-len(reduced):], reduced)
	if err := s.inner.SetBytesCanonical(buf[:]); err != nil {
		return nil, fmt.Errorf("bn254g1: hash to scalar failed: %w", err)
	}
	return s, nil
}

// Order returns the order of the BN254 scalar field (Fr) as a big-endian byte slice.
func (g *BN254G1) Order() []byte {
	return fr.Modulus().Bytes()
}
