package golden

import (
	"fmt"

	"github.com/f3rmion/fy/group"
)

// extractXAsFr extracts the x-coordinate of a BJJ point and interprets it as
// a BN254 Fr scalar. Since BJJ coordinates are elements of BN254 Fr (the base
// field of BJJ equals the scalar field of BN254), this is a native injection
// with no reduction needed.
func extractXAsFr(bn254Group group.Group, bjjPoint group.Point) (group.Scalar, error) {
	// XBytes() returns the x-coordinate as 32-byte big-endian.
	// BJJ x-coordinates are in BN254 Fr, so SetBytes is exact (no reduction).
	type xByteser interface {
		XBytes() []byte
	}
	xb, ok := bjjPoint.(xByteser)
	if !ok {
		return nil, fmt.Errorf("golden: extractXAsFr: point %T does not implement XBytes()", bjjPoint)
	}
	s := bn254Group.NewScalar()
	return s.SetBytes(xb.XBytes())
}

// bjjScalarToFr converts a BJJ scalar (Z_l, ~2^251) to a BN254 Fr scalar (~2^254).
// Since l < r, this is an injection — no reduction occurs.
func bjjScalarToFr(bn254Group group.Group, bjjScalar group.Scalar) (group.Scalar, error) {
	s := bn254Group.NewScalar()
	return s.SetBytes(bjjScalar.Bytes())
}

// frToBJJScalar converts a BN254 Fr scalar (~2^254) to a BJJ scalar (Z_l, ~2^251).
// The value is reduced modulo l (the BJJ subgroup order). This is a lossy
// operation for values >= l.
func frToBJJScalar(bjjGroup group.Group, frScalar group.Scalar) (group.Scalar, error) {
	s := bjjGroup.NewScalar()
	return s.SetBytes(frScalar.Bytes())
}
