package golden

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// Polynomial represents a polynomial over a group's scalar field.
type Polynomial struct {
	Coefficients []group.Scalar
}

// NewRandomPolynomial creates a random polynomial of the given degree with
// the specified secret as the constant term (Coefficients[0]).
func NewRandomPolynomial(g group.Group, secret group.Scalar, degree int, rng io.Reader) (*Polynomial, error) {
	coeffs := make([]group.Scalar, degree+1)
	coeffs[0] = g.NewScalar().Set(secret)
	for i := 1; i <= degree; i++ {
		c, err := g.RandomScalar(rng)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}
	return &Polynomial{Coefficients: coeffs}, nil
}

// Evaluate evaluates the polynomial at point x using Horner's method.
// p(x) = a0 + a1*x + a2*x^2 + ... + an*x^n
// Returns zero scalar if the polynomial has no coefficients.
func (p *Polynomial) Evaluate(g group.Group, x group.Scalar) group.Scalar {
	if len(p.Coefficients) == 0 {
		return g.NewScalar()
	}
	// Horner's method: start from highest degree
	n := len(p.Coefficients)
	result := g.NewScalar().Set(p.Coefficients[n-1])
	for i := n - 2; i >= 0; i-- {
		result = g.NewScalar().Mul(result, x)
		result = g.NewScalar().Add(result, p.Coefficients[i])
	}
	return result
}

// GenerateShares evaluates the polynomial at x=1,2,...,n and returns the shares.
func GenerateShares(g group.Group, poly *Polynomial, n int) (map[int]group.Scalar, error) {
	shares := make(map[int]group.Scalar, n)
	for i := 1; i <= n; i++ {
		x, err := scalarFromInt(g, i)
		if err != nil {
			return nil, fmt.Errorf("GenerateShares: index %d: %w", i, err)
		}
		shares[i] = poly.Evaluate(g, x)
	}
	return shares, nil
}

// scalarFromInt creates a scalar from a small non-negative integer.
// The integer must be in [0, MaxNodeID] range.
func scalarFromInt(g group.Group, n int) (group.Scalar, error) {
	s := g.NewScalar()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(n))
	if _, err := s.SetBytes(buf); err != nil {
		return nil, fmt.Errorf("scalarFromInt: SetBytes failed for value %d: %w", n, err)
	}
	return s, nil
}

// Zero securely zeros all polynomial coefficients and releases the slice.
func (p *Polynomial) Zero() {
	for i := range p.Coefficients {
		p.Coefficients[i].Zero()
	}
	p.Coefficients = nil
}
