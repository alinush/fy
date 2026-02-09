package bjj

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/f3rmion/fy/group"
)

// curveOrder is the Baby Jubjub subgroup order.
// This is distinct from the BN254 scalar field order (Fr).
var curveOrder *big.Int

func init() {
	curve := twistededwards.GetEdwardsCurve()
	curveOrder = new(big.Int).Set(&curve.Order)
}

// Scalar represents an element of the Baby Jubjub scalar field.
// It implements [group.Scalar] using big.Int with modular arithmetic
// over the curve's subgroup order.
//
// All arithmetic operations automatically reduce results modulo the
// curve order to maintain valid scalar values.
type Scalar struct {
	inner *big.Int
}

// newScalar creates a new scalar initialized to zero.
func newScalar() *Scalar {
	return &Scalar{inner: new(big.Int)}
}

// reduce ensures the scalar is in the range [0, curveOrder).
func (s *Scalar) reduce() {
	s.inner.Mod(s.inner, curveOrder)
}

// assertScalar asserts that s is a *Scalar.
// Panics with a descriptive message if s is a different group.Scalar implementation.
// This is by design: mixing scalar types from different groups is a programming error.
func assertScalar(s group.Scalar) *Scalar {
	v, ok := s.(*Scalar)
	if !ok {
		panic(fmt.Sprintf("bjj: expected *bjj.Scalar, got %T (do not mix group implementations)", s))
	}
	return v
}

// assertPoint asserts that p is a *Point.
// Panics with a descriptive message if p is a different group.Point implementation.
// This is by design: mixing point types from different groups is a programming error.
func assertPoint(p group.Point) *Point {
	v, ok := p.(*Point)
	if !ok {
		panic(fmt.Sprintf("bjj: expected *bjj.Point, got %T (do not mix group implementations)", p))
	}
	return v
}

// Add sets s to a + b (mod curveOrder) and returns s.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Add(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Sub sets s to a - b (mod curveOrder) and returns s.
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Sub(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Mul sets s to a * b (mod curveOrder) and returns s.
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	bScalar := assertScalar(b)
	s.inner.Mul(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Negate sets s to -a (mod curveOrder) and returns s.
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	s.inner.Neg(aScalar.inner)
	s.reduce()
	return s
}

// Invert sets s to a^(-1) (mod curveOrder) and returns s.
// Returns an error if a is zero, as zero has no multiplicative inverse.
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := assertScalar(a)
	if aScalar.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.ModInverse(aScalar.inner, curveOrder)
	return s, nil
}

// Set copies the value of a into s and returns s.
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := assertScalar(a)
	s.inner.Set(aScalar.inner)
	return s
}

// Bytes returns the scalar as a 32-byte big-endian representation.
func (s *Scalar) Bytes() []byte {
	// Ensure scalar is reduced before serialization
	s.reduce()
	bytes := s.inner.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	// Pad with leading zeros
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

// SetBytes sets s from a big-endian byte slice and returns s.
// The value is reduced modulo the curve order.
// Input must be at most 64 bytes (allowing hash-to-field with 128-bit security margin).
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	if len(data) > 64 {
		return nil, errors.New("scalar input exceeds 64 bytes")
	}
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

// Equal reports whether s and b represent the same scalar value.
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := assertScalar(b)
	s.reduce()
	bScalar.reduce()
	return s.inner.Cmp(bScalar.inner) == 0
}

// IsZero reports whether s is the zero scalar.
func (s *Scalar) IsZero() bool {
	return s.inner.Sign() == 0
}

// Point represents a point on the Baby Jubjub curve.
// It implements [group.Point] by wrapping gnark-crypto's PointAffine.
//
// Points are represented in affine coordinates (x, y) on the twisted
// Edwards curve. The identity element is (0, 1).
type Point struct {
	inner twistededwards.PointAffine
}

// Add sets p to a + b and returns p.
func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := assertPoint(a)
	bPoint := assertPoint(b)
	p.inner.Add(&aPoint.inner, &bPoint.inner)
	return p
}

// Sub sets p to a - b and returns p.
func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := assertPoint(a)
	bPoint := assertPoint(b)
	var negB twistededwards.PointAffine
	negB.Neg(&bPoint.inner)
	p.inner.Add(&aPoint.inner, &negB)
	return p
}

// Negate sets p to -a and returns p.
func (p *Point) Negate(a group.Point) group.Point {
	aPoint := assertPoint(a)
	p.inner.Neg(&aPoint.inner)
	return p
}

// ScalarMult sets p to s * q and returns p.
func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := assertScalar(s)
	qPoint := assertPoint(q)
	p.inner.ScalarMultiplication(&qPoint.inner, scalar.inner)
	return p
}

// Set copies the value of a into p and returns p.
func (p *Point) Set(a group.Point) group.Point {
	aPoint := assertPoint(a)
	p.inner.Set(&aPoint.inner)
	return p
}

// Bytes returns the compressed point encoding as a byte slice.
func (p *Point) Bytes() []byte {
	bytes := p.inner.Bytes()
	return bytes[:]
}

// SetBytes sets p from a compressed point encoding and returns p.
// Returns an error if the data does not represent a valid curve point
// or if the point is not in the prime-order subgroup.
func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if err := p.inner.Unmarshal(data); err != nil {
		return nil, err
	}
	if !p.IsInSubgroup() {
		return nil, errors.New("point is not in the prime-order subgroup")
	}
	return p, nil
}

// UncompressedBytes returns the 64-byte uncompressed point encoding (X || Y).
// This format is compatible with iden3 and Ledger applications.
// Each coordinate is encoded as a 32-byte big-endian integer.
func (p *Point) UncompressedBytes() []byte {
	result := make([]byte, 64)
	xBytes := p.inner.X.Bytes()
	yBytes := p.inner.Y.Bytes()
	copy(result[0:32], xBytes[:])
	copy(result[32:64], yBytes[:])
	return result
}

// SetUncompressedBytes sets p from a 64-byte uncompressed encoding (X || Y).
// This format is compatible with iden3 and Ledger applications.
// Returns an error if the data is not 64 bytes or does not represent a
// valid curve point.
func (p *Point) SetUncompressedBytes(data []byte) error {
	if len(data) != 64 {
		return errors.New("uncompressed point must be 64 bytes")
	}
	p.inner.X.SetBytes(data[0:32])
	p.inner.Y.SetBytes(data[32:64])
	// Verify the point is on the curve
	if !p.inner.IsOnCurve() {
		return errors.New("point is not on curve")
	}
	// Verify the point is in the prime-order subgroup
	if !p.IsInSubgroup() {
		return errors.New("point is not in the prime-order subgroup")
	}
	return nil
}

// Equal reports whether p and b represent the same curve point.
func (p *Point) Equal(b group.Point) bool {
	bPoint := assertPoint(b)
	return p.inner.Equal(&bPoint.inner)
}

// IsIdentity reports whether p is the identity element (0, 1).
func (p *Point) IsIdentity() bool {
	return p.inner.IsZero()
}

// IsInSubgroup reports whether p is in the prime-order subgroup.
// BJJ has cofactor 8, so low-order points exist on the curve
// that are not in the expected subgroup. This checks order * P == identity.
func (p *Point) IsInSubgroup() bool {
	var check twistededwards.PointAffine
	check.ScalarMultiplication(&p.inner, curveOrder)
	return check.IsZero()
}

// BJJ implements [group.Group] for the Baby Jubjub curve.
//
// BJJ is a zero-sized type that provides access to Baby Jubjub curve
// operations. Create an instance with &BJJ{} or new(BJJ).
type BJJ struct{}

// NewScalar returns a new scalar initialized to zero.
func (g *BJJ) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint returns a new point initialized to the identity element (0, 1).
func (g *BJJ) NewPoint() group.Point {
	var p Point
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	return &p
}

// Generator returns the standard base point for the Baby Jubjub curve.
func (g *BJJ) Generator() group.Point {
	var p Point
	p.inner = twistededwards.GetEdwardsCurve().Base
	return &p
}

// RandomScalar generates a cryptographically random scalar using the
// provided random source. The result is uniformly distributed in
// [1, curveOrder-1] using rejection sampling.
func (g *BJJ) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	// For BJJ (~96.9% rejection rate at 32 bytes over 251-bit order), expected ~32 iterations.
	// 1000 limit gives negligible false failure probability.
	for attempt := 0; attempt < 1000; attempt++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(buf[:])
		if n.Cmp(curveOrder) >= 0 || n.Sign() == 0 {
			continue // reject and retry
		}
		return &Scalar{inner: n}, nil
	}
	return nil, errors.New("RandomScalar: rejection sampling did not converge")
}

// HashToScalar hashes the provided data to a scalar using SHA-256.
// Each input is length-prefixed with a 4-byte big-endian length before hashing.
// Uses hash-to-field expansion (64 bytes) for uniform reduction (bias < 2^-128).
func (g *BJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
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

	s := newScalar()
	s.inner.SetBytes(expanded)
	s.reduce()
	return s, nil
}

// Order returns the order of the Baby Jubjub curve's prime-order subgroup
// as a big-endian byte slice.
func (g *BJJ) Order() []byte {
	return curveOrder.Bytes()
}
