package golden

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

func TestEvaluateAtZeroIsSecret(t *testing.T) {
	g := &bjj.BJJ{}
	secret, _ := g.RandomScalar(rand.Reader)
	poly, _ := NewRandomPolynomial(g, secret, 2, rand.Reader)

	// Evaluate at zero scalar: Horner's method with x=0 only returns constant term
	zeroScalar := g.NewScalar() // zero-valued scalar
	result := poly.Evaluate(g, zeroScalar)

	if !result.Equal(secret) {
		t.Error("p(0) should equal the secret")
	}
}

func TestShareAndReconstruct(t *testing.T) {
	g := &bjj.BJJ{}
	secret, _ := g.RandomScalar(rand.Reader)
	threshold := 3 // degree = threshold - 1 = 2
	n := 5

	poly, _ := NewRandomPolynomial(g, secret, threshold-1, rand.Reader)
	shares := GenerateShares(g, poly, n)

	// Reconstruct using Lagrange interpolation with threshold shares
	// Pick shares 1, 2, 3
	ids := []int{1, 2, 3}
	reconstructed := lagrangeInterpolateAtZero(g, ids, shares)

	if !reconstructed.Equal(secret) {
		t.Error("Lagrange reconstruction should recover secret")
	}
}

// lagrangeInterpolateAtZero reconstructs f(0) from shares using Lagrange interpolation.
func lagrangeInterpolateAtZero(g group.Group, ids []int, shares map[int]group.Scalar) group.Scalar {
	result := g.NewScalar()
	// Create one scalar
	buf := make([]byte, 32)
	buf[31] = 1
	one, _ := g.NewScalar().SetBytes(buf)

	for _, i := range ids {
		xi := scalarFromInt(g, i)
		li := g.NewScalar().Set(one)

		for _, j := range ids {
			if i == j {
				continue
			}
			xj := scalarFromInt(g, j)
			// li *= xj / (xj - xi)
			// Since we evaluate at 0: li *= -xj / (xi - xj) = xj / (xj - xi)
			diff := g.NewScalar().Sub(xj, xi)
			diffInv, err := g.NewScalar().Invert(diff)
			if err != nil {
				panic("zero denominator in Lagrange interpolation")
			}
			term := g.NewScalar().Mul(xj, diffInv)
			li = g.NewScalar().Mul(li, term)
		}

		// result += li * share_i
		contribution := g.NewScalar().Mul(li, shares[i])
		result = g.NewScalar().Add(result, contribution)
	}
	return result
}

func TestInsufficientSharesFail(t *testing.T) {
	g := &bjj.BJJ{}
	secret, _ := g.RandomScalar(rand.Reader)
	threshold := 3
	n := 5

	poly, _ := NewRandomPolynomial(g, secret, threshold-1, rand.Reader)
	shares := GenerateShares(g, poly, n)

	// Try with only 2 shares (less than threshold of 3)
	ids := []int{1, 2}
	reconstructed := lagrangeInterpolateAtZero(g, ids, shares)

	// Should NOT equal secret (with overwhelming probability)
	if reconstructed.Equal(secret) {
		t.Error("reconstruction with fewer than threshold shares should fail")
	}
}
