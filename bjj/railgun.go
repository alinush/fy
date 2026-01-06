package bjj

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/f3rmion/fy/group"
)

// Base8 is the circomlibjs Base8 generator point for Baby JubJub.
// This is the standard generator multiplied by 8 (cofactor clearing).
// Using this generator produces signatures compatible with circomlibjs eddsa.verifyPoseidon.
var base8X, base8Y *big.Int

// inv8 is the modular inverse of 8 modulo the subgroup order.
// Used to "divide" points by 8 for circomlibjs compatibility.
var inv8 *big.Int

func init() {
	base8X, _ = new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	base8Y, _ = new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	// Compute inv(8, subOrder)
	// subOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041
	eight := big.NewInt(8)
	inv8 = new(big.Int).ModInverse(eight, curveOrder)
}

// RailgunBJJ implements [group.Group] for Baby JubJub with circomlibjs-compatible Base8 generator.
// Use this for FROST signatures that need to verify with circomlibjs eddsa.verifyPoseidon.
type RailgunBJJ struct {
	base8 *Point
}

// NewRailgunBJJ creates a new RailgunBJJ group instance.
func NewRailgunBJJ() *RailgunBJJ {
	var p Point
	p.inner.X.SetBigInt(base8X)
	p.inner.Y.SetBigInt(base8Y)
	return &RailgunBJJ{base8: &p}
}

// NewScalar returns a new scalar initialized to zero.
func (g *RailgunBJJ) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint returns a new point initialized to the identity element (0, 1).
func (g *RailgunBJJ) NewPoint() group.Point {
	var p Point
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	return &p
}

// Generator returns Base8, the circomlibjs-compatible generator.
func (g *RailgunBJJ) Generator() group.Point {
	var p Point
	p.inner.X.SetBigInt(base8X)
	p.inner.Y.SetBigInt(base8Y)
	return &p
}

// RandomScalar generates a cryptographically random scalar using the
// provided random source. The result is uniformly distributed in
// [0, curveOrder).
func (g *RailgunBJJ) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	s := newScalar()
	s.inner.SetBytes(buf[:])
	s.reduce()
	return s, nil
}

// HashToScalar hashes the provided data to a scalar using SHA-256.
// Multiple byte slices are concatenated before hashing.
func (g *RailgunBJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)

	s := newScalar()
	s.inner.SetBytes(hash)
	s.reduce()
	return s, nil
}

// Order returns the order of the Baby Jubjub curve's prime-order subgroup
// as a big-endian byte slice.
func (g *RailgunBJJ) Order() []byte {
	return curveOrder.Bytes()
}

// RailgunPoint wraps a BJJ Point with additional methods for Railgun compatibility.
type RailgunPoint struct {
	Point
}

// NewRailgunPoint creates a new RailgunPoint from a BJJ Point.
func NewRailgunPoint(p *Point) *RailgunPoint {
	return &RailgunPoint{Point: *p}
}

// SetUncompressedCoordinates sets the point from X, Y coordinates.
func (p *RailgunPoint) SetUncompressedCoordinates(x, y *big.Int) error {
	p.inner.X.SetBigInt(x)
	p.inner.Y.SetBigInt(y)
	if !p.inner.IsOnCurve() {
		return errors.New("point is not on curve")
	}
	return nil
}

// Mul8 multiplies the point by 8 (cofactor).
// This is useful for converting between different EdDSA conventions.
func (p *Point) Mul8() *Point {
	var result Point
	var temp twistededwards.PointAffine

	// Double 3 times to multiply by 8
	temp.Double(&p.inner)
	temp.Double(&temp)
	result.inner.Double(&temp)

	return &result
}

// DivBy8 computes P * inv(8, subOrder), effectively "dividing" the point by 8.
// This is used to convert from FROST public keys to circomlibjs public key format.
// For a point P = sk * Base8, DivBy8(P) = (sk >> 3) * Base8 when sk is divisible by 8.
// More generally, DivBy8(P) returns Q such that 8 * Q = P.
func (p *Point) DivBy8() *Point {
	var result Point
	result.inner.ScalarMultiplication(&p.inner, inv8)
	return &result
}
