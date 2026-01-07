package frost

import (
	"crypto/sha256"

	"github.com/f3rmion/fy/group"
)

// Secp256k1Hasher implements Hasher using SHA-256 with domain separation
// for secp256k1 FROST signatures.
//
// This hasher follows the FROST-secp256k1-SHA256 specification with
// domain separation prefix for each hash function.
//
// Domain separation format: prefix + tag + inputs
type Secp256k1Hasher struct {
	// Prefix is the domain separation prefix.
	// Default: "FROST-secp256k1-SHA256-v1"
	Prefix string
}

// NewSecp256k1Hasher creates a Secp256k1Hasher with the standard FROST prefix.
func NewSecp256k1Hasher() *Secp256k1Hasher {
	return &Secp256k1Hasher{
		Prefix: "FROST-secp256k1-SHA256-v1",
	}
}

func (h *Secp256k1Hasher) hash(tag string, data ...[]byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(h.Prefix))
	hasher.Write([]byte(tag))
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

// hashToScalar hashes data and converts to a scalar.
// The 32-byte output is interpreted as big-endian and reduced mod curve order.
func (h *Secp256k1Hasher) hashToScalar(g group.Group, tag string, data ...[]byte) group.Scalar {
	hash := h.hash(tag, data...)
	s := g.NewScalar()
	s.SetBytes(hash)
	return s
}

// H1 implements Hasher.H1 (binding factor computation).
// Hashes: prefix || "rho" || msg || encCommitList || signerID
func (h *Secp256k1Hasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.hashToScalar(g, "rho", msg, encCommitList, signerID)
}

// H2 implements Hasher.H2 (Schnorr challenge).
// Hashes: prefix || "chal" || R || Y || msg
func (h *Secp256k1Hasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	return h.hashToScalar(g, "chal", R, Y, msg)
}

// H3 implements Hasher.H3 (nonce generation).
// Hashes: prefix || "nonce" || seed || rho || msg
func (h *Secp256k1Hasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.hashToScalar(g, "nonce", seed, rho, msg)
}

// H4 implements Hasher.H4 (message hashing).
// Returns: SHA-256(prefix || "msg" || msg)
func (h *Secp256k1Hasher) H4(g group.Group, msg []byte) []byte {
	return h.hash("msg", msg)
}

// H5 implements Hasher.H5 (commitment list hashing).
// Returns: SHA-256(prefix || "com" || encCommitList)
func (h *Secp256k1Hasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.hash("com", encCommitList)
}
