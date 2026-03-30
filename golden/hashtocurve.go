package golden

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/f3rmion/fy/bjj"
)

const (
	// h1Domain is the domain separator for the H1 hash function used in the eVRF.
	h1Domain = "golden-evrf-h1"
	// h2Domain is the domain separator for the H2 hash function used in the eVRF.
	h2Domain = "golden-evrf-h2"
	// maxHashAttempts bounds the try-and-increment loop to prevent infinite iteration.
	// Must not exceed 256 (counter is a single byte).
	maxHashAttempts = 256
)

// hashToCurveTryAndIncrement maps arbitrary data to a Baby Jubjub curve point
// using the try-and-increment method with SHA-256.
//
// WARNING: This function uses try-and-increment which is NOT constant-time.
// The number of iterations depends on the input, leaking information via
// timing. For production use cases requiring constant-time hash-to-curve,
// consider Elligator 2 (RFC 9380). This is acceptable here because the
// session data inputs are public.
//
// Algorithm:
//  1. For counter = 0, 1, 2, ...:
//     hash = SHA-256(domain || len(data[0]) || data[0] || ... || counter)
//  2. Interpret hash as an Fr element x (reduced mod r).
//  3. Compute y^2 = (1 + x^2) / (1 - d*x^2) from the twisted Edwards equation
//     with a = -1.
//  4. If y^2 is a quadratic residue, compute y = sqrt(y^2) and take the
//     canonical (lexicographically smallest) root.
//  5. Construct point (x, y), cofactor-clear by multiplying by 8.
//  6. Verify the result is non-identity and in the prime-order subgroup.
func hashToCurveTryAndIncrement(domain string, data ...[]byte) (*bjj.Point, error) {
	curve := twistededwards.GetEdwardsCurve()

	for ctr := 0; ctr < maxHashAttempts; ctr++ {
		// Hash: SHA-256(domain || len(data[0]) || data[0] || ... || counter)
		h := sha256.New()
		h.Write([]byte(domain))
		for _, d := range data {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(d)))
			h.Write(lenBuf[:])
			h.Write(d)
		}
		h.Write([]byte{byte(ctr)})
		digest := h.Sum(nil)

		// Interpret hash as an Fr element (reduced mod r).
		var x fr.Element
		x.SetBytes(digest)

		// Twisted Edwards equation with a = -1:
		//   -x^2 + y^2 = 1 + d*x^2*y^2
		//   y^2(1 - d*x^2) = 1 + x^2
		//   y^2 = (1 + x^2) / (1 - d*x^2)

		var x2, one fr.Element
		one.SetOne()
		x2.Square(&x)

		// numerator = 1 + x^2
		var num fr.Element
		num.Add(&one, &x2)

		// denominator = 1 - d*x^2
		var dx2, den fr.Element
		dx2.Mul(&curve.D, &x2)
		den.Sub(&one, &dx2)

		// If denominator is zero, this x is not valid.
		if den.IsZero() {
			continue
		}

		// y^2 = num * den^(-1)
		var denInv, y2 fr.Element
		denInv.Inverse(&den)
		y2.Mul(&num, &denInv)

		// Check if y^2 is a quadratic residue.
		if y2.Legendre() != 1 {
			continue
		}

		// Compute y = sqrt(y^2).
		var y fr.Element
		y.Sqrt(&y2)

		// Take the canonical (lexicographically smallest) root.
		// Compare y and -y in big-endian byte form; pick the smaller one.
		var negY fr.Element
		negY.Neg(&y)
		yBytes := y.Bytes()
		negYBytes := negY.Bytes()
		if compareBytesBE(yBytes[:], negYBytes[:]) > 0 {
			y.Set(&negY)
		}

		// Construct the affine point.
		var p twistededwards.PointAffine
		p.X.Set(&x)
		p.Y.Set(&y)

		// Sanity check: point must be on the curve.
		if !p.IsOnCurve() {
			continue
		}

		// Cofactor clear: multiply by 8 (BJJ cofactor).
		cofactor := big.NewInt(8)
		var p8 twistededwards.PointAffine
		p8.ScalarMultiplication(&p, cofactor)

		// The cofactor-cleared point must not be the identity.
		if p8.IsZero() {
			continue
		}

		// Verify subgroup membership: order * p8 == identity.
		var check twistededwards.PointAffine
		check.ScalarMultiplication(&p8, &curve.Order)
		if !check.IsZero() {
			continue
		}

		pt, err := bjj.NewPointFromAffine(p8)
		if err != nil {
			return nil, fmt.Errorf("golden: NewPointFromAffine: %w", err)
		}
		return pt, nil
	}

	return nil, errors.New("golden: hash-to-curve failed after maximum attempts")
}

// compareBytesBE compares two byte slices in big-endian (lexicographic) order.
// Returns -1 if a < b, 0 if a == b, +1 if a > b.
func compareBytesBE(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
