package bjj

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	// fieldP is the Baby JubJub base field modulus, which equals the BN254 scalar field (Fr).
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

// assertCircomScalar asserts that s is a *CircomScalar.
// Panics with a descriptive message if s is a different group.Scalar implementation.
// This is by design: mixing scalar types from different groups is a programming error.
func assertCircomScalar(s group.Scalar) *CircomScalar {
	v, ok := s.(*CircomScalar)
	if !ok {
		panic(fmt.Sprintf("circombjj: expected *bjj.CircomScalar, got %T (do not mix group implementations)", s))
	}
	return v
}

// assertCircomPoint asserts that p is a *CircomPoint.
// Panics with a descriptive message if p is a different group.Point implementation.
// This is by design: mixing point types from different groups is a programming error.
func assertCircomPoint(p group.Point) *CircomPoint {
	v, ok := p.(*CircomPoint)
	if !ok {
		panic(fmt.Sprintf("circombjj: expected *bjj.CircomPoint, got %T (do not mix group implementations)", p))
	}
	return v
}

func (s *CircomScalar) Add(a, b group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	bs := assertCircomScalar(b)
	s.inner.Add(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Sub(a, b group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	bs := assertCircomScalar(b)
	s.inner.Sub(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Mul(a, b group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	bs := assertCircomScalar(b)
	s.inner.Mul(as.inner, bs.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Negate(a group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	s.inner.Neg(as.inner)
	s.reduce()
	return s
}

func (s *CircomScalar) Invert(a group.Scalar) (group.Scalar, error) {
	as := assertCircomScalar(a)
	if as.inner.Sign() == 0 {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.ModInverse(as.inner, circSubOrder)
	return s, nil
}

func (s *CircomScalar) Set(a group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	s.inner.Set(as.inner)
	return s
}

func (s *CircomScalar) Bytes() []byte {
	// Ensure scalar is reduced before serialization
	s.reduce()
	bytes := s.inner.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

func (s *CircomScalar) SetBytes(data []byte) (group.Scalar, error) {
	if len(data) > 64 {
		return nil, errors.New("scalar input exceeds 64 bytes")
	}
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

func (s *CircomScalar) Equal(b group.Scalar) bool {
	bs := assertCircomScalar(b)
	s.reduce()
	// Reduce b into a temporary to avoid mutating the argument.
	bReduced := new(big.Int).Mod(bs.inner, circSubOrder)
	return s.inner.Cmp(bReduced) == 0
}

func (s *CircomScalar) IsZero() bool {
	s.reduce()
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

// fieldInv computes a^(-1) mod p.
// Panics if a is zero. In the twisted Edwards addition formula, the denominators
// (1 + d*x1*x2*y1*y2) and (1 - d*x1*x2*y1*y2) are guaranteed non-zero for
// valid curve points when a*d is not a square in the field, which holds for
// the Baby JubJub parameters (a=168700, d=168696). A zero input here would
// indicate a bug in the caller, not a runtime condition.
func fieldInv(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		panic("fieldInv: cannot invert zero")
	}
	return new(big.Int).ModInverse(a, fieldP)
}

// Add sets p to a + b using the twisted Edwards addition formula.
// For a*x^2 + y^2 = 1 + d*x^2*y^2:
// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
// y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
func (p *CircomPoint) Add(a, b group.Point) group.Point {
	ap := assertCircomPoint(a)
	bp := assertCircomPoint(b)

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
	bp := assertCircomPoint(b)
	negB := newCircomPoint()
	negB.x = new(big.Int).Neg(bp.x)
	negB.x.Mod(negB.x, fieldP)
	negB.y = new(big.Int).Set(bp.y)
	return p.Add(a, negB)
}

func (p *CircomPoint) Negate(a group.Point) group.Point {
	ap := assertCircomPoint(a)
	p.x = new(big.Int).Neg(ap.x)
	p.x.Mod(p.x, fieldP)
	p.y = new(big.Int).Set(ap.y)
	return p
}

// ScalarMult computes s * q using a Montgomery ladder with fixed iteration count.
// The loop always executes circSubOrder.BitLen() iterations (251 for BJJ) regardless
// of the scalar value, preventing timing leaks from variable iteration count.
//
// WARNING: This is NOT safe for secret scalars. The if/else branch on scalar bits
// leaks through branch prediction side channels, and math/big operations have
// data-dependent timing. For secret scalar multiplication, use bjj.Point.ScalarMult
// (which delegates to gnark-crypto's constant-time implementation) instead.
// This function is used only for public scalar operations (DivBy8, IsInSubgroup).
func (p *CircomPoint) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := assertCircomScalar(s)
	qp := assertCircomPoint(q)

	// Montgomery ladder: constant-time scalar multiplication
	// R0 = identity, R1 = q
	r0 := newCircomPoint()
	r0.x = big.NewInt(0)
	r0.y = big.NewInt(1)

	r1 := newCircomPoint()
	r1.x = new(big.Int).Set(qp.x)
	r1.y = new(big.Int).Set(qp.y)

	n := new(big.Int).Mod(scalar.inner, circSubOrder)
	// Use fixed bit-width to prevent timing leaks from variable iteration count.
	// circSubOrder.BitLen() is constant (251 bits for BJJ subgroup order).
	fixedBits := circSubOrder.BitLen()

	// Process bits from most significant to least significant
	for i := fixedBits - 1; i >= 0; i-- {
		if n.Bit(i) == 0 {
			r1.Add(r0, r1)
			r0.Add(r0, r0)
		} else {
			r0.Add(r0, r1)
			r1.Add(r1, r1)
		}
	}

	p.x = r0.x
	p.y = r0.y
	return p
}

func (p *CircomPoint) Set(a group.Point) group.Point {
	ap := assertCircomPoint(a)
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
	// Verify point is in prime-order subgroup
	if !p.IsInSubgroup() {
		return nil, errors.New("point is not in the prime-order subgroup")
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
	bp := assertCircomPoint(b)
	return p.x.Cmp(bp.x) == 0 && p.y.Cmp(bp.y) == 0
}

func (p *CircomPoint) IsIdentity() bool {
	return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0
}

// IsInSubgroup reports whether p is in the prime-order subgroup.
// Checks order * P == identity.
func (p *CircomPoint) IsInSubgroup() bool {
	s := newCircomScalar()
	s.inner = new(big.Int).Set(circSubOrder)
	result := newCircomPoint()
	result.ScalarMult(s, p)
	return result.IsIdentity()
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
	// For BJJ (~97.6% rejection rate at 32 bytes over 251-bit order), expected ~42 iterations.
	// 1000 limit gives negligible false failure probability.
	for attempt := 0; attempt < 1000; attempt++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(buf[:])
		if n.Cmp(circSubOrder) >= 0 || n.Sign() == 0 {
			continue // reject and retry
		}
		return &CircomScalar{inner: n}, nil
	}
	return nil, errors.New("RandomScalar: rejection sampling did not converge")
}

func (g *CircomBJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
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

	s := newCircomScalar()
	s.inner.SetBytes(expanded)
	s.reduce()
	return s, nil
}

func (g *CircomBJJ) Order() []byte {
	return circSubOrder.Bytes()
}
