package golden

import (
	"fmt"

	"github.com/f3rmion/fy/group"
)

// VSSCommit computes Feldman VSS commitments for a polynomial.
// Each commitment is A_k = a_k * G for each coefficient a_k.
// The polynomial and the commitment group must use the same scalar field
// to ensure consistent evaluation (no cross-field reduction issues).
func VSSCommit(g group.Group, poly *Polynomial) ([]group.Point, error) {
	commitments := make([]group.Point, len(poly.Coefficients))
	for i, coeff := range poly.Coefficients {
		commitments[i] = g.NewPoint().ScalarMult(coeff, g.Generator())
	}
	return commitments, nil
}

// ExpectedShareCommitment computes the expected commitment for a share at
// the given index from VSS commitments.
// Result = sum(A_k * index^k) for k = 0..len(commitments)-1.
// The index and powers are computed in the group's scalar field.
func ExpectedShareCommitment(g group.Group, commitments []group.Point, index int) (group.Point, error) {
	indexScalar, err := scalarFromInt(g, index)
	if err != nil {
		return nil, fmt.Errorf("ExpectedShareCommitment: index scalar: %w", err)
	}

	// Iterative: accumulate index^k as we go.
	result := g.NewPoint()
	indexPower, err := scalarFromInt(g, 1) // index^0 = 1
	if err != nil {
		return nil, fmt.Errorf("ExpectedShareCommitment: unit scalar: %w", err)
	}

	for _, commitment := range commitments {
		// term = indexPower * A_k
		term := g.NewPoint().ScalarMult(indexPower, commitment)
		result = g.NewPoint().Add(result, term)
		// indexPower *= index
		indexPower = g.NewScalar().Mul(indexPower, indexScalar)
	}

	return result, nil
}
