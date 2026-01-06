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
type ThresholdWallet struct {
	frost     *frost.FROST
	group     *bjj.CircomBJJ
	threshold int
	total     int
}

// NewThresholdWallet creates a new threshold wallet with the specified parameters.
//
// threshold is the minimum number of signers required (M in M-of-N).
// total is the total number of participants (N in M-of-N).
//
// The wallet uses Baby JubJub curve with the circomlibjs-compatible Base8 generator.
// Signatures produced can be verified with circomlibjs eddsa.verifyPoseidon.
func NewThresholdWallet(threshold, total int) (*ThresholdWallet, error) {
	g := bjj.NewCircomBJJ()
	f, err := frost.NewWithHasher(g, threshold, total, frost.NewRailgunHasher())
	if err != nil {
		return nil, err
	}

	return &ThresholdWallet{
		frost:     f,
		group:     g,
		threshold: threshold,
		total:     total,
	}, nil
}

// Share represents a participant's key share for threshold signing.
type Share struct {
	// ID is the participant identifier (1 to N).
	ID int
	// KeyShare is the underlying FROST key share.
	KeyShare *frost.KeyShare
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
	cp, ok := s.KeyShare.GroupKey.(*bjj.CircomPoint)
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
	cp, ok := s.KeyShare.GroupKey.(*bjj.CircomPoint)
	if !ok {
		panic("group key must be CircomPoint for Railgun compatibility")
	}

	uncompressed := cp.UncompressedBytes()
	x := new(big.Int).SetBytes(uncompressed[0:32])
	y := new(big.Int).SetBytes(uncompressed[32:64])
	return x, y
}

// GenerateShares runs distributed key generation to create key shares.
// Returns shares for all N participants.
//
// In a real deployment, this would be run as an interactive protocol
// between participants. This method simulates the full DKG for testing.
func (tw *ThresholdWallet) GenerateShares(random io.Reader) ([]*Share, error) {
	if random == nil {
		random = rand.Reader
	}

	// Create participants
	participants := make([]*frost.Participant, tw.total)
	for i := 0; i < tw.total; i++ {
		p, err := tw.frost.NewParticipant(random, i+1)
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
			privateData := tw.frost.Round1PrivateSend(sender, j+1)

			// Recipient verifies and stores
			err := tw.frost.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
			if err != nil {
				return nil, err
			}
		}
	}

	// Finalize: Produce key shares
	shares := make([]*Share, tw.total)
	for i, p := range participants {
		keyShare, err := tw.frost.Finalize(p, broadcasts)
		if err != nil {
			return nil, err
		}
		shares[i] = &Share{
			ID:       i + 1,
			KeyShare: keyShare,
		}
	}

	return shares, nil
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
		nonce, commitment, err := ss.tw.frost.SignRound1(random, signer.KeyShare)
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
		share, err := ss.tw.frost.SignRound2(signer.KeyShare, ss.nonces[i], ss.message, ss.commitments)
		if err != nil {
			return nil, err
		}
		sigShares[i] = share
	}

	// Aggregate into final signature
	frostSig, err := ss.tw.frost.Aggregate(ss.message, ss.commitments, sigShares)
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

// Verify verifies a signature against the group public key.
func (tw *ThresholdWallet) Verify(groupKey group.Point, message []byte, sig *Signature) bool {
	// Reconstruct FROST signature
	r := tw.group.NewPoint().(*bjj.CircomPoint)

	// Set R from coordinates
	rBytes := make([]byte, 64)
	copyPadded(rBytes[0:32], sig.RX.Bytes())
	copyPadded(rBytes[32:64], sig.RY.Bytes())
	if _, err := r.SetUncompressedBytes(rBytes); err != nil {
		return false
	}

	z := tw.group.NewScalar()
	z.SetBytes(sig.S.Bytes())

	frostSig := &frost.Signature{
		R: r,
		Z: z,
	}

	return tw.frost.Verify(message, frostSig, groupKey)
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
