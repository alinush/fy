// Package railgun provides a FROST threshold signature adapter for Railgun privacy transactions.
//
// Railgun uses Baby JubJub EdDSA with Poseidon hashing for spending authorization.
// This package wraps the FROST threshold signature scheme to produce signatures
// compatible with Railgun's eddsa.verifyPoseidon verification.
//
// # Architecture
//
// The adapter provides:
//   - Threshold key generation (M-of-N spending keys on Baby JubJub)
//   - Threshold signing that produces Railgun-compatible signatures
//   - Viewing key derivation from the group public key
//
// # Usage
//
//	// Create threshold wallet with 2-of-3 signing
//	tw, err := railgun.NewThresholdWallet(2, 3)
//
//	// Run DKG to generate shares
//	shares, err := tw.GenerateShares(rand.Reader)
//
//	// Sign a transaction (threshold signing)
//	sig, err := tw.Sign(shares[:2], sighash)
//
//	// Get Railgun-compatible format
//	rx, ry, s := sig.Components()
package railgun

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/group"
	"github.com/f3rmion/fy/secp256k1"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// Signature represents a Railgun-compatible EdDSA signature.
// It consists of a nonce point R (as X, Y coordinates) and response scalar S.
type Signature struct {
	// RX is the X coordinate of the nonce point R.
	RX *big.Int
	// RY is the Y coordinate of the nonce point R.
	RY *big.Int
	// S is the response scalar.
	S *big.Int
}

// Components returns the signature components as separate values.
// This matches Railgun's expected format: [R.x, R.y, S].
func (s *Signature) Components() (*big.Int, *big.Int, *big.Int) {
	return s.RX, s.RY, s.S
}

// Bytes returns the signature as a 96-byte slice: RX (32) || RY (32) || S (32).
func (s *Signature) Bytes() []byte {
	result := make([]byte, 96)
	copyPadded(result[0:32], s.RX.Bytes())
	copyPadded(result[32:64], s.RY.Bytes())
	copyPadded(result[64:96], s.S.Bytes())
	return result
}

// copyPadded copies src into dst with left-padding to fill dst.
func copyPadded(dst, src []byte) {
	if len(src) >= len(dst) {
		copy(dst, src[len(src)-len(dst):])
	} else {
		copy(dst[len(dst)-len(src):], src)
	}
}

// FromFROSTSignature converts a FROST signature to Railgun format.
// The FROST signature must be produced using Baby JubJub group.
func FromFROSTSignature(sig *frost.Signature) (*Signature, error) {
	if sig == nil {
		return nil, errors.New("nil signature")
	}

	// Extract R point coordinates - support both CircomPoint and Point
	var uncompressed []byte
	switch p := sig.R.(type) {
	case *bjj.CircomPoint:
		uncompressed = p.UncompressedBytes()
	case *bjj.Point:
		uncompressed = p.UncompressedBytes()
	default:
		return nil, errors.New("signature R is not a Baby JubJub point")
	}

	rx := new(big.Int).SetBytes(uncompressed[0:32])
	ry := new(big.Int).SetBytes(uncompressed[32:64])

	// Extract Z scalar
	zBytes := sig.Z.Bytes()
	s := new(big.Int).SetBytes(zBytes)

	return &Signature{
		RX: rx,
		RY: ry,
		S:  s,
	}, nil
}

// ThresholdWallet manages FROST threshold signing for Railgun transactions.
// It maintains two FROST instances:
//   - shieldFROST: secp256k1 curve for Ethereum-compatible shield signatures
//   - spendingFROST: Baby JubJub curve for ZK-compatible transfer/unshield signatures
type ThresholdWallet struct {
	shieldFROST   *frost.FROST   // secp256k1 for shield operations
	shieldGroup   *secp256k1.Secp256k1
	spendingFROST *frost.FROST   // BJJ for transfer/unshield operations
	spendingGroup *bjj.CircomBJJ
	threshold     int
	total         int
}

// NewThresholdWallet creates a new threshold wallet with the specified parameters.
//
// threshold is the minimum number of signers required (M in M-of-N).
// total is the total number of participants (N in M-of-N).
//
// The wallet initializes two FROST instances:
//   - secp256k1 with Secp256k1Hasher for shield operations (Ethereum-compatible)
//   - Baby JubJub with RailgunHasher for transfer/unshield operations (ZK-compatible)
func NewThresholdWallet(threshold, total int) (*ThresholdWallet, error) {
	// secp256k1 for shield operations
	shieldG := secp256k1.New()
	shieldF, err := frost.NewWithHasher(shieldG, threshold, total, frost.NewSecp256k1Hasher())
	if err != nil {
		return nil, err
	}

	// Baby JubJub for transfer/unshield operations
	spendingG := bjj.NewCircomBJJ()
	spendingF, err := frost.NewWithHasher(spendingG, threshold, total, frost.NewRailgunHasher())
	if err != nil {
		return nil, err
	}

	return &ThresholdWallet{
		shieldFROST:   shieldF,
		shieldGroup:   shieldG,
		spendingFROST: spendingF,
		spendingGroup: spendingG,
		threshold:     threshold,
		total:         total,
	}, nil
}

// Share represents a participant's key shares for threshold signing.
// Each participant holds shares for both curves.
type Share struct {
	// ID is the participant identifier (1 to N).
	ID int
	// ShieldKeyShare is the secp256k1 FROST key share for shield operations.
	ShieldKeyShare *frost.KeyShare
	// SpendingKeyShare is the BJJ FROST key share for transfer/unshield operations.
	SpendingKeyShare *frost.KeyShare
}

// KeyShare returns the spending key share for backward compatibility.
// Deprecated: Use SpendingKeyShare directly.
func (s *Share) KeyShare() *frost.KeyShare {
	return s.SpendingKeyShare
}

// SpendingPublicKey returns the circomlibjs-compatible spending public key as (X, Y) coordinates.
// This is the FROST group key Y divided by 8, which matches the format expected by
// circomlibjs eddsa.verifyPoseidon where A = Base8 * (sk >> 3).
//
// Since FROST uses Y = Base8 * sk and circomlibjs uses A = Base8 * (sk >> 3),
// we have A = Y / 8.
//
// This is the same for all participants.
func (s *Share) SpendingPublicKey() (*big.Int, *big.Int) {
	// Get the FROST group key
	cp, ok := s.SpendingKeyShare.GroupKey.(*bjj.CircomPoint)
	if !ok {
		panic("group key must be CircomPoint for Railgun compatibility")
	}

	// Divide by 8 to get circomlibjs-compatible public key A = Y/8
	a := cp.DivBy8()
	uncompressed := a.UncompressedBytes()
	x := new(big.Int).SetBytes(uncompressed[0:32])
	y := new(big.Int).SetBytes(uncompressed[32:64])
	return x, y
}

// InternalGroupKey returns the internal FROST group key Y as (X, Y) coordinates.
// This is Y = total_sk * Base8, NOT the circomlibjs-compatible public key A = Y/8.
// Use SpendingPublicKey() for circomlibjs verification.
func (s *Share) InternalGroupKey() (*big.Int, *big.Int) {
	cp, ok := s.SpendingKeyShare.GroupKey.(*bjj.CircomPoint)
	if !ok {
		panic("group key must be CircomPoint for Railgun compatibility")
	}

	uncompressed := cp.UncompressedBytes()
	x := new(big.Int).SetBytes(uncompressed[0:32])
	y := new(big.Int).SetBytes(uncompressed[32:64])
	return x, y
}

// ShieldPublicKey returns the secp256k1 group public key for shield operations.
// This is an Ethereum-compatible public key that can be used to derive shield keys.
// Returns the compressed (33-byte) public key bytes.
func (s *Share) ShieldPublicKey() []byte {
	return s.ShieldKeyShare.GroupKey.Bytes()
}

// ShieldPublicKeyUncompressed returns the secp256k1 group public key in uncompressed format.
// Returns 65 bytes: 0x04 || X (32 bytes) || Y (32 bytes).
func (s *Share) ShieldPublicKeyUncompressed() []byte {
	p, ok := s.ShieldKeyShare.GroupKey.(*secp256k1.Point)
	if !ok {
		panic("shield group key must be secp256k1.Point")
	}
	return p.UncompressedBytes()
}

// GenerateShares runs distributed key generation for both curves.
// Returns shares for all N participants, each containing both shield (secp256k1)
// and spending (Baby JubJub) key shares.
//
// In a real deployment, this would be run as an interactive protocol
// between participants. This method simulates the full DKG for testing.
func (tw *ThresholdWallet) GenerateShares(random io.Reader) ([]*Share, error) {
	if random == nil {
		random = rand.Reader
	}

	// Run secp256k1 DKG for shield operations
	shieldKeyShares, err := tw.runDKG(tw.shieldFROST, random)
	if err != nil {
		return nil, err
	}

	// Run BJJ DKG for spending operations
	spendingKeyShares, err := tw.runDKG(tw.spendingFROST, random)
	if err != nil {
		return nil, err
	}

	// Combine into Share structs
	shares := make([]*Share, tw.total)
	for i := 0; i < tw.total; i++ {
		shares[i] = &Share{
			ID:               i + 1,
			ShieldKeyShare:   shieldKeyShares[i],
			SpendingKeyShare: spendingKeyShares[i],
		}
	}

	return shares, nil
}

// runDKG runs a single DKG protocol for the given FROST instance.
func (tw *ThresholdWallet) runDKG(f *frost.FROST, random io.Reader) ([]*frost.KeyShare, error) {
	// Create participants
	participants := make([]*frost.Participant, tw.total)
	for i := 0; i < tw.total; i++ {
		p, err := f.NewParticipant(random, i+1)
		if err != nil {
			return nil, err
		}
		participants[i] = p
	}

	// Round 1: Collect broadcasts
	broadcasts := make([]*frost.Round1Data, tw.total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	// Round 1: Exchange private shares
	for i, sender := range participants {
		for j := 0; j < tw.total; j++ {
			if i == j {
				continue
			}
			// Sender sends to recipient j+1
			privateData := f.Round1PrivateSend(sender, j+1)

			// Recipient verifies and stores
			err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
			if err != nil {
				return nil, err
			}
		}
	}

	// Finalize: Produce key shares
	keyShares := make([]*frost.KeyShare, tw.total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			return nil, err
		}
		keyShares[i] = ks
	}

	return keyShares, nil
}

// SigningSession manages a threshold signing operation.
type SigningSession struct {
	tw          *ThresholdWallet
	message     []byte
	signers     []*Share
	nonces      []*frost.SigningNonce
	commitments []*frost.SigningCommitment
}

// NewSigningSession creates a new signing session for the given message.
// signers must contain at least threshold shares.
func (tw *ThresholdWallet) NewSigningSession(signers []*Share, message []byte) (*SigningSession, error) {
	if len(signers) < tw.threshold {
		return nil, errors.New("insufficient signers for threshold")
	}

	return &SigningSession{
		tw:          tw,
		message:     message,
		signers:     signers,
		nonces:      make([]*frost.SigningNonce, len(signers)),
		commitments: make([]*frost.SigningCommitment, len(signers)),
	}, nil
}

// Round1 performs the first round of signing for all participants.
// Returns the commitments to be broadcast.
func (ss *SigningSession) Round1(random io.Reader) ([]*frost.SigningCommitment, error) {
	if random == nil {
		random = rand.Reader
	}

	for i, signer := range ss.signers {
		nonce, commitment, err := ss.tw.spendingFROST.SignRound1(random, signer.SpendingKeyShare)
		if err != nil {
			return nil, err
		}
		ss.nonces[i] = nonce
		ss.commitments[i] = commitment
	}

	return ss.commitments, nil
}

// Round2 performs the second round and produces the final signature.
func (ss *SigningSession) Round2() (*Signature, error) {
	// Collect partial signatures from all signers
	sigShares := make([]*frost.SignatureShare, len(ss.signers))

	for i, signer := range ss.signers {
		share, err := ss.tw.spendingFROST.SignRound2(signer.SpendingKeyShare, ss.nonces[i], ss.message, ss.commitments)
		if err != nil {
			return nil, err
		}
		sigShares[i] = share
	}

	// Aggregate into final signature
	frostSig, err := ss.tw.spendingFROST.Aggregate(ss.message, ss.commitments, sigShares)
	if err != nil {
		return nil, err
	}

	// Convert to Railgun format
	return FromFROSTSignature(frostSig)
}

// Sign performs threshold signing in a single call.
// This runs both rounds of the signing protocol.
func (tw *ThresholdWallet) Sign(signers []*Share, message []byte) (*Signature, error) {
	session, err := tw.NewSigningSession(signers, message)
	if err != nil {
		return nil, err
	}

	if _, err := session.Round1(rand.Reader); err != nil {
		return nil, err
	}

	return session.Round2()
}

// Verify verifies a spending signature against the group public key.
// This is for BJJ signatures used in transfer/unshield operations.
func (tw *ThresholdWallet) Verify(groupKey group.Point, message []byte, sig *Signature) bool {
	// Reconstruct FROST signature
	r := tw.spendingGroup.NewPoint().(*bjj.CircomPoint)

	// Set R from coordinates
	rBytes := make([]byte, 64)
	copyPadded(rBytes[0:32], sig.RX.Bytes())
	copyPadded(rBytes[32:64], sig.RY.Bytes())
	if _, err := r.SetUncompressedBytes(rBytes); err != nil {
		return false
	}

	z := tw.spendingGroup.NewScalar()
	z.SetBytes(sig.S.Bytes())

	frostSig := &frost.Signature{
		R: r,
		Z: z,
	}

	return tw.spendingFROST.Verify(message, frostSig, groupKey)
}

// ShieldSignature represents a secp256k1 Schnorr signature for shield operations.
// It consists of a nonce point R and response scalar Z.
type ShieldSignature struct {
	// R is the nonce point (33 bytes compressed, or 65 bytes uncompressed)
	R group.Point
	// Z is the response scalar (32 bytes)
	Z group.Scalar
}

// RBytes returns the R component as compressed bytes (33 bytes).
func (s *ShieldSignature) RBytes() []byte {
	return s.R.Bytes()
}

// ZBytes returns the Z component as bytes (32 bytes).
func (s *ShieldSignature) ZBytes() []byte {
	return s.Z.Bytes()
}

// ToEthereumSignature converts to Ethereum-compatible (r, s, v) format.
// Note: Recovery of v requires trying both possibilities.
// Returns (r, s) where r = R.X and s = Z (may need low-S normalization).
func (s *ShieldSignature) ToEthereumSignature() (r, sVal []byte) {
	// Get R as uncompressed to extract X coordinate
	p, ok := s.R.(*secp256k1.Point)
	if !ok {
		return nil, nil
	}
	uncompressed := p.UncompressedBytes()
	// r = R.X (bytes 1-32 of uncompressed, skipping 0x04 prefix)
	r = uncompressed[1:33]
	// s = Z
	sVal = s.Z.Bytes()
	return r, sVal
}

// ShieldSign performs threshold signing for shield operations using secp256k1.
// This produces a Schnorr signature that can be converted to Ethereum format.
func (tw *ThresholdWallet) ShieldSign(signers []*Share, message []byte) (*ShieldSignature, error) {
	if len(signers) < tw.threshold {
		return nil, errors.New("insufficient signers for threshold")
	}

	// Round 1: Generate nonces and commitments
	nonces := make([]*frost.SigningNonce, len(signers))
	commitments := make([]*frost.SigningCommitment, len(signers))
	for i, signer := range signers {
		n, c, err := tw.shieldFROST.SignRound1(rand.Reader, signer.ShieldKeyShare)
		if err != nil {
			return nil, err
		}
		nonces[i] = n
		commitments[i] = c
	}

	// Round 2: Generate signature shares
	sigShares := make([]*frost.SignatureShare, len(signers))
	for i, signer := range signers {
		share, err := tw.shieldFROST.SignRound2(signer.ShieldKeyShare, nonces[i], message, commitments)
		if err != nil {
			return nil, err
		}
		sigShares[i] = share
	}

	// Aggregate into final signature
	frostSig, err := tw.shieldFROST.Aggregate(message, commitments, sigShares)
	if err != nil {
		return nil, err
	}

	return &ShieldSignature{
		R: frostSig.R,
		Z: frostSig.Z,
	}, nil
}

// VerifyShield verifies a shield signature against the shield group public key.
func (tw *ThresholdWallet) VerifyShield(groupKey group.Point, message []byte, sig *ShieldSignature) bool {
	frostSig := &frost.Signature{
		R: sig.R,
		Z: sig.Z,
	}
	return tw.shieldFROST.Verify(message, frostSig, groupKey)
}

// DeriveViewingKey derives the Railgun viewing key from the group public key.
// The viewing key is deterministically derived using Poseidon hash.
//
// viewingKey = poseidon("railgun-viewing", groupKey.X, groupKey.Y) mod curve_order
//
// This allows all threshold participants to independently derive the same
// viewing key without interaction, enabling nullifier computation and
// note decryption.
func DeriveViewingKey(groupKey group.Point) ([]byte, error) {
	var uncompressed []byte
	switch p := groupKey.(type) {
	case *bjj.CircomPoint:
		uncompressed = p.UncompressedBytes()
	case *bjj.Point:
		uncompressed = p.UncompressedBytes()
	default:
		return nil, errors.New("groupKey is not a Baby JubJub point")
	}

	x := new(big.Int).SetBytes(uncompressed[0:32])
	y := new(big.Int).SetBytes(uncompressed[32:64])

	// Domain separator as field element
	domain := new(big.Int).SetBytes([]byte("railgun-viewing"))

	// Hash: poseidon(domain, x, y)
	hash, err := poseidon.Hash([]*big.Int{domain, x, y})
	if err != nil {
		return nil, err
	}

	// Return as 32-byte key
	result := make([]byte, 32)
	hashBytes := hash.Bytes()
	copy(result[32-len(hashBytes):], hashBytes)

	return result, nil
}

// DeriveMasterPublicKey computes the Railgun master public key.
// masterPubKey = poseidon(spendingPubKey.X, spendingPubKey.Y, nullifyingKey)
//
// The nullifying key is derived from the viewing key:
// nullifyingKey = poseidon(viewingKey)
func DeriveMasterPublicKey(spendingPubKey group.Point, viewingKey []byte) (*big.Int, error) {
	var uncompressed []byte
	switch p := spendingPubKey.(type) {
	case *bjj.CircomPoint:
		uncompressed = p.UncompressedBytes()
	case *bjj.Point:
		uncompressed = p.UncompressedBytes()
	default:
		return nil, errors.New("spendingPubKey is not a Baby JubJub point")
	}

	x := new(big.Int).SetBytes(uncompressed[0:32])
	y := new(big.Int).SetBytes(uncompressed[32:64])

	// Compute nullifying key = poseidon(viewingKey)
	vk := new(big.Int).SetBytes(viewingKey)
	nullifyingKey, err := poseidon.Hash([]*big.Int{vk})
	if err != nil {
		return nil, err
	}

	// Compute master public key = poseidon(x, y, nullifyingKey)
	masterPubKey, err := poseidon.Hash([]*big.Int{x, y, nullifyingKey})
	if err != nil {
		return nil, err
	}

	return masterPubKey, nil
}

// ComputeNullifier computes the nullifier for a note at the given leaf index.
// nullifier = poseidon(nullifyingKey, leafIndex)
//
// The nullifying key is derived from the viewing key:
// nullifyingKey = poseidon(viewingKey)
func ComputeNullifier(viewingKey []byte, leafIndex uint64) (*big.Int, error) {
	vk := new(big.Int).SetBytes(viewingKey)

	// Compute nullifying key = poseidon(viewingKey)
	nullifyingKey, err := poseidon.Hash([]*big.Int{vk})
	if err != nil {
		return nil, err
	}

	// Compute nullifier = poseidon(nullifyingKey, leafIndex)
	leafIdx := new(big.Int).SetUint64(leafIndex)
	nullifier, err := poseidon.Hash([]*big.Int{nullifyingKey, leafIdx})
	if err != nil {
		return nil, err
	}

	return nullifier, nil
}
