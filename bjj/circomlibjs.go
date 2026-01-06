package bjj

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/f3rmion/fy/group"
)

// This file implements Baby JubJub with circomlibjs-compatible parameters.
// Twisted Edwards curve: A*x^2 + y^2 = 1 + D*x^2*y^2
// A = 168700
// D = 168696
// This matches the parameters used by @railgun-community/circomlibjs.

var (
	// Field modulus (BN254 base field)
	fieldP, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Curve parameters (circomlibjs)
	curveA = big.NewInt(168700)
	curveD = big.NewInt(168696)

	// Subgroup order (same as gnark-crypto, this is the prime-order subgroup)
	circSubOrder, _ = new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	// Base8 generator (circomlibjs)
	circBase8X, _ = new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	circBase8Y, _ = new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	// Inverse of 8 modulo suborder (for DivBy8 operation)
	circInv8 = new(big.Int).ModInverse(big.NewInt(8), circSubOrder)
)

// CircomScalar represents a scalar in the circomlibjs-compatible Baby JubJub field.
type CircomScalar struct {
	inner *big.Int
}

func newCircomScalar() *CircomScalar {
	return &CircomScalar{inner: new(big.Int)}
}

func (s *CircomScalar) reduce() {
	s.inner.Mod(s.inner, circSubOrder)
}

func (s *CircomScalar) Add(a, b group.Scalar) group.Scalar {
	as := a.(*CircomScalar)
	bs := b.(*CircomScalar)
	s.inner.Add(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Sub(a, b group.Scalar) group.Scalar {
	as := a.(*CircomScalar)
	bs := b.(*CircomScalar)
	s.inner.Sub(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Mul(a, b group.Scalar) group.Scalar {
	as := a.(*CircomScalar)
	bs := b.(*CircomScalar)
	s.inner.Mul(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Negate(a group.Scalar) group.Scalar {
	as := a.(*CircomScalar)
	s.inner.Neg(as.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Invert(a group.Scalar) (group.Scalar, error) {
	as := a.(*CircomScalar)
	if as.inner.Sign() == 0 {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.ModInverse(as.inner, circSubOrder)
	return s, nil
}

func (s *CircomScalar) Set(a group.Scalar) group.Scalar {
	as := a.(*CircomScalar)
	s.inner.Set(as.inner)
	return s
}

func (s *CircomScalar) Bytes() []byte {
	bytes := s.inner.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

func (s *CircomScalar) SetBytes(data []byte) (group.Scalar, error) {
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

func (s *CircomScalar) Equal(b group.Scalar) bool {
	bs := b.(*CircomScalar)
	return s.inner.Cmp(bs.inner) == 0
}

func (s *CircomScalar) IsZero() bool {
	return s.inner.Sign() == 0
}

// CircomPoint represents a point on the circomlibjs Baby JubJub curve.
type CircomPoint struct {
	x, y *big.Int
}

func newCircomPoint() *CircomPoint {
	return &CircomPoint{
		x: new(big.Int),
		y: big.NewInt(1), // Identity is (0, 1)
	}
}

// fieldAdd computes (a + b) mod p
func fieldAdd(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, fieldP)
}

// fieldSub computes (a - b) mod p
func fieldSub(a, b *big.Int) *big.Int {
	result := new(big.Int).Sub(a, b)
	return result.Mod(result, fieldP)
}

// fieldMul computes (a * b) mod p
func fieldMul(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	return result.Mod(result, fieldP)
}

// fieldInv computes a^(-1) mod p
func fieldInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, fieldP)
}

// Add sets p to a + b using the twisted Edwards addition formula.
// For a*x^2 + y^2 = 1 + d*x^2*y^2:
// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
// y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
func (p *CircomPoint) Add(a, b group.Point) group.Point {
	ap := a.(*CircomPoint)
	bp := b.(*CircomPoint)

	x1, y1 := ap.x, ap.y
	x2, y2 := bp.x, bp.y

	// x1*x2*y1*y2
	x1x2 := fieldMul(x1, x2)
	y1y2 := fieldMul(y1, y2)
	x1x2y1y2 := fieldMul(x1x2, y1y2)
	dx1x2y1y2 := fieldMul(curveD, x1x2y1y2)

	// x3 numerator: x1*y2 + y1*x2
	x1y2 := fieldMul(x1, y2)
	y1x2 := fieldMul(y1, x2)
	x3num := fieldAdd(x1y2, y1x2)

	// x3 denominator: 1 + d*x1*x2*y1*y2
	x3den := fieldAdd(big.NewInt(1), dx1x2y1y2)

	// y3 numerator: y1*y2 - a*x1*x2
	ax1x2 := fieldMul(curveA, x1x2)
	y3num := fieldSub(y1y2, ax1x2)

	// y3 denominator: 1 - d*x1*x2*y1*y2
	y3den := fieldSub(big.NewInt(1), dx1x2y1y2)

	// x3 = x3num / x3den
	p.x = fieldMul(x3num, fieldInv(x3den))
	// y3 = y3num / y3den
	p.y = fieldMul(y3num, fieldInv(y3den))

	return p
}

func (p *CircomPoint) Sub(a, b group.Point) group.Point {
	bp := b.(*CircomPoint)
	negB := newCircomPoint()
	negB.x = new(big.Int).Neg(bp.x)
	negB.x.Mod(negB.x, fieldP)
	negB.y = new(big.Int).Set(bp.y)
	return p.Add(a, negB)
}

func (p *CircomPoint) Negate(a group.Point) group.Point {
	ap := a.(*CircomPoint)
	p.x = new(big.Int).Neg(ap.x)
	p.x.Mod(p.x, fieldP)
	p.y = new(big.Int).Set(ap.y)
	return p
}

// ScalarMult computes s * q using double-and-add.
func (p *CircomPoint) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := s.(*CircomScalar)
	qp := q.(*CircomPoint)

	// Start with identity
	result := newCircomPoint()
	result.x = big.NewInt(0)
	result.y = big.NewInt(1)

	// Copy q for doubling
	temp := newCircomPoint()
	temp.x = new(big.Int).Set(qp.x)
	temp.y = new(big.Int).Set(qp.y)

	n := new(big.Int).Set(scalar.inner)

	for n.Sign() > 0 {
		if n.Bit(0) == 1 {
			result.Add(result, temp)
		}
		temp.Add(temp, temp) // Double
		n.Rsh(n, 1)
	}

	p.x = result.x
	p.y = result.y
	return p
}

func (p *CircomPoint) Set(a group.Point) group.Point {
	ap := a.(*CircomPoint)
	p.x = new(big.Int).Set(ap.x)
	p.y = new(big.Int).Set(ap.y)
	return p
}

// Bytes returns the uncompressed point encoding (X || Y).
func (p *CircomPoint) Bytes() []byte {
	return p.UncompressedBytes()
}

// SetBytes sets p from point bytes.
func (p *CircomPoint) SetBytes(data []byte) (group.Point, error) {
	if len(data) == 64 {
		return p.SetUncompressedBytes(data)
	}
	return nil, errors.New("unsupported point encoding")
}

// UncompressedBytes returns the 64-byte uncompressed encoding (X || Y).
func (p *CircomPoint) UncompressedBytes() []byte {
	result := make([]byte, 64)
	xBytes := p.x.Bytes()
	yBytes := p.y.Bytes()
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result
}

// SetUncompressedBytes sets p from a 64-byte uncompressed encoding.
func (p *CircomPoint) SetUncompressedBytes(data []byte) (group.Point, error) {
	if len(data) != 64 {
		return nil, errors.New("uncompressed point must be 64 bytes")
	}
	p.x = new(big.Int).SetBytes(data[0:32])
	p.y = new(big.Int).SetBytes(data[32:64])

	// Verify point is on curve
	if !p.isOnCurve() {
		return nil, errors.New("point is not on curve")
	}
	return p, nil
}

// isOnCurve checks if the point is on the twisted Edwards curve.
func (p *CircomPoint) isOnCurve() bool {
	// A*x^2 + y^2 = 1 + D*x^2*y^2
	x2 := fieldMul(p.x, p.x)
	y2 := fieldMul(p.y, p.y)
	x2y2 := fieldMul(x2, y2)

	lhs := fieldAdd(fieldMul(curveA, x2), y2)
	rhs := fieldAdd(big.NewInt(1), fieldMul(curveD, x2y2))

	return lhs.Cmp(rhs) == 0
}

func (p *CircomPoint) Equal(b group.Point) bool {
	bp := b.(*CircomPoint)
	return p.x.Cmp(bp.x) == 0 && p.y.Cmp(bp.y) == 0
}

func (p *CircomPoint) IsIdentity() bool {
	return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0
}

// DivBy8 computes P * inv(8, subOrder).
func (p *CircomPoint) DivBy8() *CircomPoint {
	s := newCircomScalar()
	s.inner = new(big.Int).Set(circInv8)

	result := newCircomPoint()
	result.ScalarMult(s, p)
	return result
}

// CircomBJJ implements [group.Group] for the circomlibjs-compatible Baby JubJub curve.
type CircomBJJ struct{}

func NewCircomBJJ() *CircomBJJ {
	return &CircomBJJ{}
}

func (g *CircomBJJ) NewScalar() group.Scalar {
	return newCircomScalar()
}

func (g *CircomBJJ) NewPoint() group.Point {
	return newCircomPoint()
}

// Generator returns the Base8 generator (circomlibjs-compatible).
func (g *CircomBJJ) Generator() group.Point {
	p := newCircomPoint()
	p.x = new(big.Int).Set(circBase8X)
	p.y = new(big.Int).Set(circBase8Y)
	return p
}

func (g *CircomBJJ) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	s := newCircomScalar()
	s.inner.SetBytes(buf[:])
	s.reduce()
	return s, nil
}

func (g *CircomBJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)

	s := newCircomScalar()
	s.inner.SetBytes(hash)
	s.reduce()
	return s, nil
}

func (g *CircomBJJ) Order() []byte {
	return circSubOrder.Bytes()
}
