package frost

import (
	"crypto/sha256"
	"math/big"

	"github.com/f3rmion/fy/group"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"golang.org/x/crypto/blake2b"
)

// Hasher defines the hash operations required by FROST.
// Different implementations can provide different hash functions
// and domain separation schemes.
type Hasher interface {
	// H1 computes the binding factor for a signer.
	// Inputs: message, encoded commitment list, signer ID.
	H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar

	// H2 computes the Schnorr challenge.
	// Inputs: R point, public key Y, message.
	H2(g group.Group, R, Y, msg []byte) group.Scalar

	// H3 computes a nonce from seed and additional data.
	// Inputs: seed, rho (binding factor), message.
	H3(g group.Group, seed, rho, msg []byte) group.Scalar

	// H4 hashes a message for signing.
	H4(g group.Group, msg []byte) []byte

	// H5 hashes the commitment list.
	H5(g group.Group, encCommitList []byte) []byte
}

// SHA256Hasher implements Hasher using SHA-256.
// This is the default hasher for general use.
type SHA256Hasher struct{}

func (h *SHA256Hasher) hash(data ...[]byte) []byte {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

func (h *SHA256Hasher) hashToScalar(g group.Group, data ...[]byte) group.Scalar {
	hash := h.hash(data...)
	s := g.NewScalar()
	s.SetBytes(hash)
	return s
}

// H1 implements Hasher.H1.
func (h *SHA256Hasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.hashToScalar(g, []byte("rho"), msg, encCommitList, signerID)
}

// H2 implements Hasher.H2.
func (h *SHA256Hasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	return h.hashToScalar(g, R, Y, msg)
}

// H3 implements Hasher.H3.
func (h *SHA256Hasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.hashToScalar(g, []byte("nonce"), seed, rho, msg)
}

// H4 implements Hasher.H4.
func (h *SHA256Hasher) H4(g group.Group, msg []byte) []byte {
	return h.hash([]byte("msg"), msg)
}

// H5 implements Hasher.H5.
func (h *SHA256Hasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.hash([]byte("com"), encCommitList)
}

// Blake2bHasher implements Hasher using Blake2b-512 with domain separation.
// This is compatible with Ledger/iden3 FROST implementations.
//
// Domain separation format: prefix + tag + input
// Output is interpreted as little-endian before reducing mod curve order.
type Blake2bHasher struct {
	// Prefix is the domain separation prefix.
	// Default: "FROST-EDBABYJUJUB-BLAKE512-v1"
	Prefix string
}

// NewBlake2bHasher creates a Blake2bHasher with the Ledger-compatible prefix.
func NewBlake2bHasher() *Blake2bHasher {
	return &Blake2bHasher{
		Prefix: "FROST-EDBABYJUJUB-BLAKE512-v1",
	}
}

func (h *Blake2bHasher) hash(tag string, data ...[]byte) []byte {
	hasher, _ := blake2b.New512(nil)
	hasher.Write([]byte(h.Prefix))
	hasher.Write([]byte(tag))
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

// hashToScalar hashes data and converts to a scalar.
// The 64-byte output is interpreted as little-endian before reducing mod order.
func (h *Blake2bHasher) hashToScalar(g group.Group, tag string, data ...[]byte) group.Scalar {
	hash := h.hash(tag, data...)

	// Reverse bytes for little-endian interpretation
	reversed := make([]byte, len(hash))
	for i := 0; i < len(hash); i++ {
		reversed[i] = hash[len(hash)-1-i]
	}

	s := g.NewScalar()
	s.SetBytes(reversed)
	return s
}

// H1 implements Hasher.H1 (binding factor computation).
func (h *Blake2bHasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.hashToScalar(g, "rho", msg, encCommitList, signerID)
}

// H2 implements Hasher.H2 (Schnorr challenge).
func (h *Blake2bHasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	return h.hashToScalar(g, "chal", R, Y, msg)
}

// H3 implements Hasher.H3 (nonce generation).
func (h *Blake2bHasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.hashToScalar(g, "nonce", seed, rho, msg)
}

// H4 implements Hasher.H4 (message hashing).
func (h *Blake2bHasher) H4(g group.Group, msg []byte) []byte {
	return h.hash("msg", msg)
}

// H5 implements Hasher.H5 (commitment list hashing).
func (h *Blake2bHasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.hash("com", encCommitList)
}

// PoseidonHasher implements Hasher using the Poseidon hash function.
// This is optimized for zkSNARK circuits, providing efficient in-circuit verification.
//
// Poseidon operates over the BN254 scalar field, which is the same field
// used by Baby Jubjub. Inputs are encoded as field elements for optimal
// zkSNARK constraint count.
//
// Domain separation is achieved using unique initial field element values
// for each hash function (H1-H5).
type PoseidonHasher struct {
	domainH1 *big.Int
	domainH2 *big.Int
	domainH3 *big.Int
	domainH4 *big.Int
	domainH5 *big.Int
}

// NewPoseidonHasher creates a PoseidonHasher with pre-computed domain separators.
func NewPoseidonHasher() *PoseidonHasher {
	return &PoseidonHasher{
		domainH1: hashTagToDomain("FROST-POSEIDON-H1"),
		domainH2: hashTagToDomain("FROST-POSEIDON-H2"),
		domainH3: hashTagToDomain("FROST-POSEIDON-H3"),
		domainH4: hashTagToDomain("FROST-POSEIDON-H4"),
		domainH5: hashTagToDomain("FROST-POSEIDON-H5"),
	}
}

// bn254ScalarFieldOrder is the order of the BN254 scalar field.
// All Poseidon inputs must be less than this value.
var bn254ScalarFieldOrder = func() *big.Int {
	order, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	return order
}()

// hashTagToDomain converts a domain tag string to a field element.
// Uses SHA-256 to derive a deterministic field element from the tag,
// then reduces modulo the BN254 scalar field order.
func hashTagToDomain(tag string) *big.Int {
	h := sha256.Sum256([]byte(tag))
	n := new(big.Int).SetBytes(h[:])
	return n.Mod(n, bn254ScalarFieldOrder)
}

// bytesToFieldElements splits a byte slice into 31-byte chunks and converts
// each chunk to a field element. 31 bytes ensures the value fits in the
// BN254 scalar field (< 254 bits).
func bytesToFieldElements(data []byte) []*big.Int {
	if len(data) == 0 {
		return []*big.Int{big.NewInt(0)}
	}

	const chunkSize = 31
	numChunks := (len(data) + chunkSize - 1) / chunkSize
	elements := make([]*big.Int, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		elements[i] = new(big.Int).SetBytes(data[start:end])
	}

	return elements
}

// pointBytesToFieldElements converts point bytes to field elements.
// For 64-byte uncompressed points (X || Y), returns two field elements.
// For 32-byte compressed points, reduces modulo field order and returns one element.
func pointBytesToFieldElements(data []byte) []*big.Int {
	if len(data) == 64 {
		// Uncompressed point: X || Y (32 bytes each)
		// Each coordinate is already < field order (BN254 base field)
		x := new(big.Int).SetBytes(data[0:32])
		y := new(big.Int).SetBytes(data[32:64])
		return []*big.Int{x, y}
	}
	// Compressed or other format: reduce modulo field order
	n := new(big.Int).SetBytes(data)
	n.Mod(n, bn254ScalarFieldOrder)
	return []*big.Int{n}
}

// poseidonToScalar converts a Poseidon hash output to a group scalar.
func poseidonToScalar(g group.Group, hash *big.Int) group.Scalar {
	s := g.NewScalar()
	s.SetBytes(hash.Bytes())
	return s
}

// H1 implements Hasher.H1 (binding factor computation).
// Hashes: domain_H1 || msg || encCommitList || signerID as field elements.
func (h *PoseidonHasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	elements := []*big.Int{h.domainH1}
	elements = append(elements, bytesToFieldElements(msg)...)
	elements = append(elements, bytesToFieldElements(encCommitList)...)
	elements = append(elements, new(big.Int).SetBytes(signerID))

	hash, err := poseidon.Hash(elements)
	if err != nil {
		// This should never happen with valid inputs
		panic("poseidon hash failed: " + err.Error())
	}

	return poseidonToScalar(g, hash)
}

// H2 implements Hasher.H2 (Schnorr challenge).
// Hashes: domain_H2 || R.X || R.Y || Y.X || Y.Y || msg as field elements.
func (h *PoseidonHasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	elements := []*big.Int{h.domainH2}
	elements = append(elements, pointBytesToFieldElements(R)...)
	elements = append(elements, pointBytesToFieldElements(Y)...)
	elements = append(elements, bytesToFieldElements(msg)...)

	hash, err := poseidon.Hash(elements)
	if err != nil {
		panic("poseidon hash failed: " + err.Error())
	}

	return poseidonToScalar(g, hash)
}

// H3 implements Hasher.H3 (nonce generation).
// Hashes: domain_H3 || seed || rho || msg as field elements.
func (h *PoseidonHasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	elements := []*big.Int{h.domainH3}
	elements = append(elements, bytesToFieldElements(seed)...)
	elements = append(elements, bytesToFieldElements(rho)...)
	elements = append(elements, bytesToFieldElements(msg)...)

	hash, err := poseidon.Hash(elements)
	if err != nil {
		panic("poseidon hash failed: " + err.Error())
	}

	return poseidonToScalar(g, hash)
}

// H4 implements Hasher.H4 (message hashing).
// Returns the Poseidon hash of: domain_H4 || msg as a 32-byte big-endian value.
func (h *PoseidonHasher) H4(g group.Group, msg []byte) []byte {
	elements := []*big.Int{h.domainH4}
	elements = append(elements, bytesToFieldElements(msg)...)

	hash, err := poseidon.Hash(elements)
	if err != nil {
		panic("poseidon hash failed: " + err.Error())
	}

	// Return as 32-byte big-endian
	bytes := hash.Bytes()
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		return padded
	}
	return bytes[:32]
}

// H5 implements Hasher.H5 (commitment list hashing).
// Returns the Poseidon hash of: domain_H5 || encCommitList as a 32-byte big-endian value.
func (h *PoseidonHasher) H5(g group.Group, encCommitList []byte) []byte {
	elements := []*big.Int{h.domainH5}
	elements = append(elements, bytesToFieldElements(encCommitList)...)

	hash, err := poseidon.Hash(elements)
	if err != nil {
		panic("poseidon hash failed: " + err.Error())
	}

	// Return as 32-byte big-endian
	bytes := hash.Bytes()
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		return padded
	}
	return bytes[:32]
}

// RailgunHasher implements Hasher with exact compatibility for circomlibjs eddsa.verifyPoseidon.
//
// The circomlibjs library computes the challenge as:
//
//	c = poseidon([R.x, R.y, pk.x, pk.y, msg])
//
// Where R and pk are Baby JubJub points (as uncompressed X,Y coordinates)
// and msg is a single field element (not chunked).
//
// This hasher produces signatures that can be verified by:
//
//	import { eddsa } from '@railgun-community/circomlibjs';
//	eddsa.verifyPoseidon(msg, signature, pubkey);
type RailgunHasher struct {
	// Use PoseidonHasher for H1, H3, H4, H5 which don't need circomlibjs compatibility
	inner *PoseidonHasher
}

// NewRailgunHasher creates a hasher compatible with circomlibjs eddsa.verifyPoseidon.
func NewRailgunHasher() *RailgunHasher {
	return &RailgunHasher{
		inner: NewPoseidonHasher(),
	}
}

// H1 implements Hasher.H1 (binding factor computation).
// Delegates to PoseidonHasher since this is internal to FROST.
func (h *RailgunHasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.inner.H1(g, msg, encCommitList, signerID)
}

// H2 implements Hasher.H2 (Schnorr/EdDSA challenge).
// Computes: c = poseidon([R.x, R.y, A.x, A.y, msg])
// Where A = Y / 8 (the circomlibjs-compatible public key derived from FROST group key Y).
//
// This matches circomlibjs eddsa.verifyPoseidon which uses:
//   - verification: S * Base8 = R + (c * 8) * A
//   - challenge: c = poseidon([R.x, R.y, A.x, A.y, msg])
//
// Points can be provided in either compressed (32 bytes) or uncompressed (64 bytes) format.
// Compressed points are automatically decompressed.
func (h *RailgunHasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	// Get R coordinates
	rx, ry := h.extractPointCoordinates(g, R)

	// Get Y coordinates, then divide by 8 to get A
	// circomlibjs uses A = Base8 * (sk >> 3) where FROST uses Y = Base8 * sk
	// So A = Y / 8
	ax, ay := h.extractPkCoordinatesDiv8(g, Y)

	// Message should be a 32-byte field element
	msgInt := new(big.Int).SetBytes(msg)

	// Compute challenge exactly as circomlibjs: poseidon([R.x, R.y, A.x, A.y, msg])
	hash, err := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msgInt})
	if err != nil {
		panic("poseidon hash failed: " + err.Error())
	}

	return poseidonToScalar(g, hash)
}

// extractPkCoordinatesDiv8 extracts coordinates from the FROST group key Y,
// then divides by 8 to get the circomlibjs-compatible public key A.
// This is needed because circomlibjs verification equation uses:
//
//	S * Base8 = R + (c * 8) * A
//
// Where A = Y/8 (Y is the FROST group key).
func (h *RailgunHasher) extractPkCoordinatesDiv8(g group.Group, data []byte) (*big.Int, *big.Int) {
	// First extract Y coordinates
	yx, yy := h.extractPointCoordinates(g, data)

	// Now divide Y by 8 to get A
	// We need to reconstruct the point, divide by 8, then extract coordinates
	// BJJ subgroup order
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	inv8 := new(big.Int).ModInverse(big.NewInt(8), subOrder)

	// Scalar multiplication: A = inv8 * Y
	// We need to do point scalar multiplication on the circomlibjs curve
	ax, ay := h.circomScalarMult(yx, yy, inv8)

	return ax, ay
}

// circomScalarMult performs scalar multiplication on the circomlibjs Baby JubJub curve.
// Computes s * P where P = (px, py) is a point on the curve with A=168700, D=168696.
func (h *RailgunHasher) circomScalarMult(px, py, s *big.Int) (*big.Int, *big.Int) {
	// Field modulus (BN254 base field)
	fieldP, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Curve parameters (circomlibjs)
	curveA := big.NewInt(168700)
	curveD := big.NewInt(168696)

	// Helper functions for field arithmetic
	fieldMul := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Mul(a, b)
		return result.Mod(result, fieldP)
	}
	fieldAdd := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Add(a, b)
		return result.Mod(result, fieldP)
	}
	fieldSub := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Sub(a, b)
		return result.Mod(result, fieldP)
	}
	fieldInv := func(a *big.Int) *big.Int {
		return new(big.Int).ModInverse(a, fieldP)
	}

	// Point addition on twisted Edwards curve: A*x^2 + y^2 = 1 + D*x^2*y^2
	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
	// y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
	pointAdd := func(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
		x1x2 := fieldMul(x1, x2)
		y1y2 := fieldMul(y1, y2)
		x1x2y1y2 := fieldMul(x1x2, y1y2)
		dx1x2y1y2 := fieldMul(curveD, x1x2y1y2)

		x1y2 := fieldMul(x1, y2)
		y1x2 := fieldMul(y1, x2)
		x3num := fieldAdd(x1y2, y1x2)
		x3den := fieldAdd(big.NewInt(1), dx1x2y1y2)

		ax1x2 := fieldMul(curveA, x1x2)
		y3num := fieldSub(y1y2, ax1x2)
		y3den := fieldSub(big.NewInt(1), dx1x2y1y2)

		x3 := fieldMul(x3num, fieldInv(x3den))
		y3 := fieldMul(y3num, fieldInv(y3den))
		return x3, y3
	}

	// Double-and-add scalar multiplication
	// Start with identity (0, 1)
	rx, ry := big.NewInt(0), big.NewInt(1)
	tempX, tempY := new(big.Int).Set(px), new(big.Int).Set(py)
	n := new(big.Int).Set(s)

	for n.Sign() > 0 {
		if n.Bit(0) == 1 {
			rx, ry = pointAdd(rx, ry, tempX, tempY)
		}
		tempX, tempY = pointAdd(tempX, tempY, tempX, tempY)
		n.Rsh(n, 1)
	}

	return rx, ry
}

// extractPointCoordinates extracts (X, Y) coordinates from point bytes.
// Handles both compressed (32-byte) and uncompressed (64-byte) formats.
func (h *RailgunHasher) extractPointCoordinates(g group.Group, data []byte) (*big.Int, *big.Int) {
	if len(data) == 64 {
		// Uncompressed format: X || Y
		x := new(big.Int).SetBytes(data[0:32])
		y := new(big.Int).SetBytes(data[32:64])
		return x, y
	}

	// Compressed format: decompress using the group
	p, err := g.NewPoint().SetBytes(data)
	if err != nil {
		panic("failed to decompress point: " + err.Error())
	}

	// Get uncompressed bytes using type assertion for BJJ
	// This is a bit ugly but necessary since group.Point doesn't have UncompressedBytes
	type uncompresser interface {
		UncompressedBytes() []byte
	}
	if uc, ok := p.(uncompresser); ok {
		ub := uc.UncompressedBytes()
		x := new(big.Int).SetBytes(ub[0:32])
		y := new(big.Int).SetBytes(ub[32:64])
		return x, y
	}

	// Fallback: try to get bytes and hope they're uncompressed
	pb := p.Bytes()
	if len(pb) >= 64 {
		x := new(big.Int).SetBytes(pb[0:32])
		y := new(big.Int).SetBytes(pb[32:64])
		return x, y
	}

	panic("cannot extract coordinates from point")
}

// H3 implements Hasher.H3 (nonce generation).
// Delegates to PoseidonHasher since this is internal to FROST.
func (h *RailgunHasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.inner.H3(g, seed, rho, msg)
}

// H4 implements Hasher.H4 (message hashing).
// Delegates to PoseidonHasher since this is internal to FROST.
func (h *RailgunHasher) H4(g group.Group, msg []byte) []byte {
	return h.inner.H4(g, msg)
}

// H5 implements Hasher.H5 (commitment list hashing).
// Delegates to PoseidonHasher since this is internal to FROST.
func (h *RailgunHasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.inner.H5(g, encCommitList)
}
