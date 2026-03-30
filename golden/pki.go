package golden

import (
	"io"

	"github.com/f3rmion/fy/group"
)

// IdentityProof is a Schnorr proof of knowledge of the secret key
// corresponding to a BJJ public key, bound to a specific session.
type IdentityProof struct {
	Commitment group.Point  // R = nonce * G
	Challenge  group.Scalar // c = HashToScalar("golden-pki-pok" || sessionID || PK || R)
	Response   group.Scalar // s = nonce - c * sk
}

// ProveIdentity creates a Schnorr proof of knowledge of sk such that pk = sk * G,
// bound to the given session ID to prevent replay across sessions.
func ProveIdentity(g group.Group, sk group.Scalar, pk group.Point, sessionID SessionID, rng io.Reader) (*IdentityProof, error) {
	nonce, err := g.RandomScalar(rng)
	if err != nil {
		return nil, err
	}

	// R = nonce * G
	R := g.NewPoint().ScalarMult(nonce, g.Generator())

	// c = HashToScalar("golden-pki-pok" || sessionID || PK || R)
	c, err := g.HashToScalar([]byte("golden-pki-pok"), sessionID[:], pk.Bytes(), R.Bytes())
	if err != nil {
		return nil, err
	}

	// s = nonce - c * sk
	csk := g.NewScalar().Mul(c, sk)
	s := g.NewScalar().Sub(nonce, csk)

	// Securely erase the nonce and intermediate.
	nonce.Zero()
	csk.Zero()

	return &IdentityProof{
		Commitment: R,
		Challenge:  c,
		Response:   s,
	}, nil
}

// VerifyIdentity verifies a Schnorr proof of knowledge for the given public key
// and session ID.
func VerifyIdentity(g group.Group, pk group.Point, sessionID SessionID, proof *IdentityProof) error {
	// R' = s * G + c * PK
	sG := g.NewPoint().ScalarMult(proof.Response, g.Generator())
	cPK := g.NewPoint().ScalarMult(proof.Challenge, pk)
	Rprime := g.NewPoint().Add(sG, cPK)

	// c' = HashToScalar("golden-pki-pok" || sessionID || PK || R')
	cprime, err := g.HashToScalar([]byte("golden-pki-pok"), sessionID[:], pk.Bytes(), Rprime.Bytes())
	if err != nil {
		return err
	}

	// This comparison is not constant-time, which is acceptable because both
	// cprime and proof.Challenge are publicly derivable from the proof transcript
	// (R, PK, sessionID). No secret information leaks through timing.
	if !cprime.Equal(proof.Challenge) {
		return ErrIdentityProofFailed
	}
	return nil
}
