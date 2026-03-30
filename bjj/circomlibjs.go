package bjj

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/f3rmion/fy/group"
)

// SECURITY NOTE: Scalar operations use math/big which is NOT constant-time.
// This means Add, Sub, Mul, Negate, Invert, Equal, and IsZero have
// data-dependent timing. For protocols requiring constant-time scalar
// arithmetic (e.g., threshold signing over BJJ), consider using
// gnark-crypto's fr.Element directly, which provides constant-time
// Montgomery arithmetic. The point operations (ScalarMult) delegate to
// gnark-crypto and ARE constant-time.

// This file implements Baby JubJub with circomlibjs-compatible parameters.
// Twisted Edwards curve: A*x^2 + y^2 = 1 + D*x^2*y^2
// A = 168700
// D = 168696
// This matches the parameters used by @railgun-community/circomlibjs.

var (
	// fieldP is the Baby JubJub base field modulus, which equals the BN254 scalar field (Fr).
	fieldP *big.Int

	// Curve parameters (circomlibjs)
	curveA = big.NewInt(168700)
	curveD = big.NewInt(168696)

	// Subgroup order (same as gnark-crypto, this is the prime-order subgroup)
	circSubOrder *big.Int

	// Base8 generator (circomlibjs)
	circBase8X *big.Int
	circBase8Y *big.Int

	// Inverse of 8 modulo suborder (for DivBy8 operation)
	circInv8 *big.Int

	// sqrtNegA is sqrt(-A) mod fieldP, used for the coordinate isomorphism
	// between circomlibjs (A=168700, D=168696) and gnark-crypto (a=-1)
	// parameterizations of Baby JubJub. The isomorphism is:
	//   x_gnark = u_circom * sqrtNegA,  y_gnark = v_circom
	sqrtNegA    *big.Int
	sqrtNegAInv *big.Int
)

// Compile-time interface checks.
var (
	_ group.Group  = (*CircomBJJ)(nil)
	_ group.Scalar = (*CircomScalar)(nil)
	_ group.Point  = (*CircomPoint)(nil)
)

func init() {
	var ok bool
	fieldP, ok = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	if !ok {
		panic("circomlibjs: invalid field modulus constant")
	}
	circSubOrder, ok = new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	if !ok {
		panic("circomlibjs: invalid subgroup order constant")
	}
	circBase8X, ok = new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	if !ok {
		panic("circomlibjs: invalid Base8 X coordinate constant")
	}
	circBase8Y, ok = new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)
	if !ok {
		panic("circomlibjs: invalid Base8 Y coordinate constant")
	}
	circInv8 = new(big.Int).ModInverse(big.NewInt(8), circSubOrder)

	// Compute sqrt(-A) mod fieldP for the coordinate isomorphism.
	negA := new(big.Int).Sub(fieldP, curveA)
	sqrtNegA = new(big.Int).ModSqrt(negA, fieldP)
	if sqrtNegA == nil {
		panic("circomlibjs: sqrt(-A) does not exist mod fieldP")
	}
	sqrtNegAInv = new(big.Int).ModInverse(sqrtNegA, fieldP)
}

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
	// Reduce into a temporary before zero-check and inversion.
	// Without reduction, a value equal to circSubOrder would have Sign() > 0
	// but ModInverse would return nil (gcd != 1), causing a nil dereference.
	reduced := new(big.Int).Mod(as.inner, circSubOrder)
	if reduced.Sign() == 0 {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.ModInverse(reduced, circSubOrder)
	return s, nil
}

func (s *CircomScalar) Set(a group.Scalar) group.Scalar {
	as := assertCircomScalar(a)
	s.inner.Set(as.inner)
	return s
}

// Bytes returns the scalar as a 32-byte big-endian representation.
// Reduces into a temporary to avoid mutating the receiver.
func (s *CircomScalar) Bytes() []byte {
	reduced := new(big.Int).Mod(s.inner, circSubOrder)
	bytes := reduced.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

func (s *CircomScalar) SetBytes(data []byte) (group.Scalar, error) {
	if len(data) == 0 {
		return nil, errors.New("empty scalar data")
	}
	if len(data) > 64 {
		return nil, errors.New("scalar input exceeds 64 bytes")
	}
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

// Equal reports whether s and b represent the same scalar value.
// Uses constant-time comparison on the byte representations.
func (s *CircomScalar) Equal(b group.Scalar) bool {
	return subtle.ConstantTimeCompare(s.Bytes(), b.Bytes()) == 1
}

// IsZero reports whether s is the zero scalar.
// Uses constant-time comparison against a zero byte slice.
func (s *CircomScalar) IsZero() bool {
	zero := make([]byte, 32)
	return subtle.ConstantTimeCompare(s.Bytes(), zero) == 1
}

// Zero sets the scalar to zero and securely erases the previous value from
// the underlying big.Int memory. See [Scalar.Zero] for details.
func (s *CircomScalar) Zero() {
	words := s.inner.Bits()
	for i := range words {
		words[i] = 0
	}
	runtime.KeepAlive(words)
	s.inner.SetInt64(0)
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
//
// WARNING: Add uses big.Int arithmetic which is NOT constant-time.
// For operations on secret-derived points, use ScalarMult which delegates
// to gnark-crypto's constant-time implementation.
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

// ScalarMult computes s * q using gnark-crypto's constant-time implementation.
//
// The circomlibjs coordinates (A=168700, D=168696) are converted to gnark-crypto's
// (a=-1) parameterization via the isomorphism x_gnark = u_circom * sqrt(-A),
// y_gnark = v_circom. After constant-time scalar multiplication, the result
// is converted back.
func (p *CircomPoint) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := assertCircomScalar(s)
	qp := assertCircomPoint(q)

	// Convert circomlibjs → gnark-crypto coordinates via isomorphism.
	// x_gnark = u_circom * sqrt(-A), y_gnark = v_circom
	xGnark := fieldMul(qp.x, sqrtNegA)

	var gnarkPt twistededwards.PointAffine
	gnarkPt.X.SetBigInt(xGnark)
	gnarkPt.Y.SetBigInt(qp.y)

	// Constant-time scalar multiplication via gnark-crypto.
	n := new(big.Int).Mod(scalar.inner, circSubOrder)
	gnarkPt.ScalarMultiplication(&gnarkPt, n)

	// Convert gnark-crypto → circomlibjs coordinates.
	// u_circom = x_gnark / sqrt(-A), v_circom = y_gnark
	var resultX, resultY big.Int
	gnarkPt.X.BigInt(&resultX)
	gnarkPt.Y.BigInt(&resultY)

	p.x = fieldMul(&resultX, sqrtNegAInv)
	p.y = new(big.Int).Set(&resultY)

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
	// Reduce coordinates mod fieldP before comparison to ensure equivalent
	// representations (e.g., x and x + fieldP) compare as equal.
	px := new(big.Int).Mod(p.x, fieldP)
	py := new(big.Int).Mod(p.y, fieldP)
	bx := new(big.Int).Mod(bp.x, fieldP)
	by := new(big.Int).Mod(bp.y, fieldP)
	return px.Cmp(bx) == 0 && py.Cmp(by) == 0
}

func (p *CircomPoint) IsIdentity() bool {
	// Reduce coordinates mod fieldP before comparison so that equivalent
	// representations (e.g., x and x + fieldP) are correctly identified.
	px := new(big.Int).Mod(p.x, fieldP)
	py := new(big.Int).Mod(p.y, fieldP)
	return px.Sign() == 0 && py.Cmp(big.NewInt(1)) == 0
}

// Zero sets the point to the identity element (0, 1) and securely erases the
// previous coordinate values from the underlying big.Int memory.
func (p *CircomPoint) Zero() {
	xWords := p.x.Bits()
	for i := range xWords {
		xWords[i] = 0
	}
	runtime.KeepAlive(xWords)
	yWords := p.y.Bits()
	for i := range yWords {
		yWords[i] = 0
	}
	runtime.KeepAlive(yWords)
	p.x.SetInt64(0)
	p.y.SetInt64(1)
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
	// With top-5-bit masking, range is [0, 2^251). Acceptance rate ≈ order/2^251 ≈ 87%.
	// Expected ~1.15 iterations. 1000 limit gives negligible false failure probability.
	for attempt := 0; attempt < 1000; attempt++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		// Mask top 5 bits to bring range close to 251-bit order,
		// improving acceptance rate from ~2.4% to ~87%.
		buf[0] &= 0x07
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
		// Domain separator: prevent cross-curve hash collisions.
		h.Write([]byte("CircomBJJ"))
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

	n := new(big.Int).SetBytes(expanded)
	defer func() {
		words := n.Bits()
		for i := range words {
			words[i] = 0
		}
		runtime.KeepAlive(words)
		n.SetInt64(0)
	}()
	n.Mod(n, circSubOrder)

	s := newCircomScalar()
	s.inner.Set(n)
	return s, nil
}

// Order returns the order of the circomlibjs-compatible BJJ subgroup as a big-endian
// byte slice. Returns a fresh copy of the group order.
func (g *CircomBJJ) Order() []byte {
	return circSubOrder.Bytes()
}
