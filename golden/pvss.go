package golden

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// PVSSConfig parameterises a Golden PVSS dealing produced by [PVSSDeal].
//
// Unlike [DkgConfig], the dealer in a PVSS is an external party whose key
// pair is not one of the N players' keys; N counts only recipients.
type PVSSConfig struct {
	// N is the number of recipients (players).
	N int
	// T is the reconstruction threshold (T >= 2, T <= N).
	T int
	// SessionID binds the transcript to a unique session and is fed into the
	// eVRF pad derivation and circuit public inputs. It is NOT serialized
	// into the transcript — verifiers pass it in out-of-band.
	SessionID SessionID
}

// PVSSTranscript is the public output of [PVSSDeal]. It contains exactly the
// fields a verifier needs to check that T-out-of-N Shamir shares of a fresh
// random secret have been correctly encrypted to N recipients.
//
// Design notes on what is NOT included, and why:
//   - No explicit SessionID: verifiers already have it from [PVSSConfig], and
//     the eVRF proofs cryptographically bind to it via their public inputs
//     (H1, H2, alpha are all derived from SessionID + RandomMsg).
//   - No dealer-ID field: the verifier is given the dealer's public key
//     out-of-band, exactly as [PVSSVerify]'s dealerPK parameter.
//   - No separate Schnorr "identity proof" of dealer-SK ownership: the eVRF
//     circuit's Step 1 already asserts that DealerPK = sk * G_bjj with sk as
//     the witness, so a valid eVRF proof implies dealer-SK knowledge. An
//     extra Schnorr would be strictly redundant.
//   - No recipient IDs or per-proof length prefixes in the wire format: the
//     order is implicit (player i ↔ array index i-1) and the PLONK proof
//     length is a constant of the compiled circuit, stored once at the start
//     of the EVRFProofs block.
type PVSSTranscript struct {
	// RandomMsg is a fresh 32-byte nonce sampled by the dealer; it is mixed
	// into the eVRF session data so pads are unique per transcript.
	RandomMsg [32]byte
	// VSSCommitments are the Feldman VSS commitments on the outer group.
	// Length is exactly T: VSSCommitments[0] = omega * G_outer is the
	// "public key" of the shared secret.
	VSSCommitments []group.Point
	// Ciphertexts[i-1] is the encrypted share for player i, 1 <= i <= N.
	Ciphertexts []*Ciphertext
	// EVRFProofs[i-1] is the eVRF PLONK proof for player i, 1 <= i <= N.
	EVRFProofs [][]byte
}

// Sentinel errors for the PVSS protocol.
var (
	ErrPVSSInvalidConfig   = errors.New("golden: invalid PVSS config (need T >= 2, N >= T, N <= MaxParticipants)")
	ErrPVSSPlayerCount     = errors.New("golden: player count does not match config.N")
	ErrPVSSDealerIsPlayer  = errors.New("golden: dealer PK matches one of the players' PKs")
	ErrPVSSProofSize       = errors.New("golden: transcript proofs differ in size")
	ErrPVSSTranscriptShape = errors.New("golden: transcript slice length does not match config")
)

// PVSSDeal samples a fresh random secret, produces T-out-of-N Shamir shares of
// it, and outputs a publicly-verifiable transcript that encrypts each share to
// the corresponding player using an eVRF-derived pad on the outer scalar
// field.
//
// The dealer is external to the N players: none of players[i].PK may equal
// dealer.PK. Players must have distinct IDs in [1, N]; each player's share is
// encrypted with a pad derived from DH(dealerSK, players[i].PK) on the inner
// curve, combined via LHL with two hash-to-curve basepoints and alpha.
//
// Secret material (polynomial coefficients, shares, pads) is zeroed before
// return; only the public transcript fields (VSSCommitments, Ciphertexts, and
// EVRFProofs) remain.
func PVSSDeal(
	suite CurveSuite,
	config *PVSSConfig,
	dealer *Participant,
	players []*Participant,
	rng io.Reader,
) (*PVSSTranscript, error) {
	if suite == nil {
		return nil, ErrNilSuite
	}
	if config == nil {
		return nil, fmt.Errorf("golden: nil PVSSConfig")
	}
	if dealer == nil || dealer.SK == nil || dealer.PK == nil {
		return nil, fmt.Errorf("golden: nil dealer or dealer keys")
	}
	if dealer.PK.IsIdentity() {
		return nil, fmt.Errorf("%w: dealer has identity public key", ErrIdentityPoint)
	}
	if config.T < 2 || config.N < config.T {
		return nil, ErrPVSSInvalidConfig
	}
	if config.N > MaxParticipants {
		return nil, fmt.Errorf("%w: N=%d exceeds maximum %d", ErrPVSSInvalidConfig, config.N, MaxParticipants)
	}
	if len(players) != config.N {
		return nil, ErrPVSSPlayerCount
	}

	outerGroup := suite.OuterGroup()

	// Validate player IDs form exactly {1,...,N} and that PKs are well-formed.
	seen := make(map[int]bool, config.N)
	for _, p := range players {
		if p == nil {
			return nil, fmt.Errorf("golden: nil player entry")
		}
		if p.ID < 1 || p.ID > config.N {
			return nil, fmt.Errorf("%w: player ID %d out of range [1, %d]", ErrInvalidNodeID, p.ID, config.N)
		}
		if seen[p.ID] {
			return nil, fmt.Errorf("%w: player ID %d", ErrDuplicateNodeID, p.ID)
		}
		seen[p.ID] = true
		if p.PK == nil || p.PK.IsIdentity() {
			return nil, fmt.Errorf("%w: player %d has nil or identity public key", ErrIdentityPoint, p.ID)
		}
		if p.PK.Equal(dealer.PK) {
			return nil, fmt.Errorf("%w: player %d", ErrPVSSDealerIsPlayer, p.ID)
		}
	}

	// Step 1: sample omega (the secret) and build the polynomial.
	omega, err := outerGroup.RandomScalar(rng)
	if err != nil {
		return nil, fmt.Errorf("golden: sampling omega: %w", err)
	}
	poly, err := NewRandomPolynomial(outerGroup, omega, config.T-1, rng)
	if err != nil {
		omega.Zero()
		return nil, fmt.Errorf("golden: creating polynomial: %w", err)
	}

	// Step 2: VSS commitments on the outer group.
	vssCommitments, err := VSSCommit(outerGroup, poly)
	if err != nil {
		poly.Zero()
		omega.Zero()
		return nil, fmt.Errorf("golden: VSS commit: %w", err)
	}

	// Step 3: compute all N shares at x=1..N.
	shares, err := GenerateShares(outerGroup, poly, config.N)
	if err != nil {
		poly.Zero()
		omega.Zero()
		return nil, fmt.Errorf("golden: generating shares: %w", err)
	}

	zeroSecrets := func() {
		poly.Zero()
		omega.Zero()
		for _, s := range shares {
			s.Zero()
		}
	}

	// Step 4: fresh per-transcript nonce.
	var randomMsg [32]byte
	if _, err := io.ReadFull(rng, randomMsg[:]); err != nil {
		zeroSecrets()
		return nil, fmt.Errorf("golden: random nonce: %w", err)
	}

	// Step 5: derive alpha once for the LHL combination in pad derivation.
	alpha, err := outerGroup.HashToScalar([]byte(lhlAlphaDomain), config.SessionID[:])
	if err != nil {
		zeroSecrets()
		return nil, fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Step 6: encrypt + prove for each player. Emit ciphertexts / proofs in
	// player-ID order so the wire format is deterministic without per-entry
	// IDs.
	ciphertexts := make([]*Ciphertext, config.N)
	evrfProofs := make([][]byte, config.N)
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}

	for _, player := range players {
		padResult, err := DerivePad(suite, dealer.SK, player.PK, sessionData, alpha)
		if err != nil {
			zeroSecrets()
			return nil, fmt.Errorf("golden: derive pad for player %d: %w", player.ID, err)
		}
		// z = pad + f(playerID) (both in Fr).
		z := outerGroup.NewScalar().Add(padResult.Pad, shares[player.ID])
		ciphertexts[player.ID-1] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}

		proof, err := suite.GenerateEVRFProof(
			dealer.SK, dealer.PK, player.PK,
			sessionData, alpha, padResult,
		)
		if err != nil {
			padResult.Pad.Zero()
			zeroSecrets()
			return nil, fmt.Errorf("golden: eVRF proof for player %d: %w", player.ID, err)
		}
		evrfProofs[player.ID-1] = proof

		padResult.Pad.Zero()
	}

	// All secrets consumed — wipe before returning the public transcript.
	zeroSecrets()

	return &PVSSTranscript{
		RandomMsg:      randomMsg,
		VSSCommitments: vssCommitments,
		Ciphertexts:    ciphertexts,
		EVRFProofs:     evrfProofs,
	}, nil
}

// PVSSVerify checks that a transcript is a valid T-out-of-N Golden PVSS
// sharing dealt by dealerPK to the given player public keys.
//
// Checks performed:
//   - Structural: VSS length == T, Ciphertexts/EVRFProofs length == N, no
//     identity points, playerPKs length == N and none identity.
//   - Algebraic VSS consistency for each player i:
//     z_i * G == R_i + sum_k(VSS[k] * i^k)
//   - eVRF PLONK proof for each player binds (dealerPK, playerPK_i, R_i) to
//     the session via H1/H2/alpha public inputs.
func PVSSVerify(
	suite CurveSuite,
	config *PVSSConfig,
	trs *PVSSTranscript,
	dealerPK group.Point,
	playerPKs []group.Point,
) error {
	if suite == nil {
		return ErrNilSuite
	}
	if config == nil {
		return fmt.Errorf("golden: nil PVSSConfig")
	}
	if trs == nil {
		return fmt.Errorf("golden: nil PVSSTranscript")
	}
	if dealerPK == nil || dealerPK.IsIdentity() {
		return fmt.Errorf("%w: dealer has nil or identity public key", ErrIdentityPoint)
	}
	if len(playerPKs) != config.N {
		return ErrPVSSPlayerCount
	}
	for i, pk := range playerPKs {
		if pk == nil || pk.IsIdentity() {
			return fmt.Errorf("%w: player %d has nil or identity public key", ErrIdentityPoint, i+1)
		}
	}

	if len(trs.VSSCommitments) != config.T {
		return ErrInvalidVSSLength
	}
	if len(trs.Ciphertexts) != config.N || len(trs.EVRFProofs) != config.N {
		return ErrPVSSTranscriptShape
	}
	if trs.VSSCommitments[0].IsIdentity() {
		return ErrIdentityPoint
	}

	outerGroup := suite.OuterGroup()

	alpha, err := outerGroup.HashToScalar([]byte(lhlAlphaDomain), config.SessionID[:])
	if err != nil {
		return fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// VSS ciphertext consistency check for each player.
	for idx, ct := range trs.Ciphertexts {
		if ct == nil {
			return fmt.Errorf("%w: player %d", ErrNilCiphertext, idx+1)
		}
		if ct.RCommitment.IsIdentity() {
			return fmt.Errorf("%w: player %d", ErrIdentityRCommitment, idx+1)
		}
		zG := outerGroup.NewPoint().ScalarMult(ct.EncryptedShare, outerGroup.Generator())
		expected, err := ExpectedShareCommitment(outerGroup, trs.VSSCommitments, idx+1)
		if err != nil {
			return fmt.Errorf("golden: share commitment for player %d: %w", idx+1, err)
		}
		rhs := outerGroup.NewPoint().Add(ct.RCommitment, expected)
		if !zG.Equal(rhs) {
			return fmt.Errorf("%w: player %d", ErrCiphertextVerification, idx+1)
		}
	}

	// eVRF proof verification for each player.
	sessionData := [][]byte{config.SessionID[:], trs.RandomMsg[:]}
	for idx, proofBytes := range trs.EVRFProofs {
		if len(proofBytes) == 0 {
			return fmt.Errorf("%w: player %d has empty proof", ErrEVRFProofFailed, idx+1)
		}
		if err := suite.VerifyEVRFProof(
			dealerPK, playerPKs[idx],
			sessionData, alpha,
			trs.Ciphertexts[idx].RCommitment,
			proofBytes,
		); err != nil {
			return fmt.Errorf("%w: player %d: %v", ErrEVRFProofFailed, idx+1, err)
		}
	}
	return nil
}

// PVSSDecryptShare re-derives the pad for (playerSK, dealerPK) and recovers
// the scalar share f(playerID). This is the per-recipient "unlock" step.
func PVSSDecryptShare(
	suite CurveSuite,
	config *PVSSConfig,
	trs *PVSSTranscript,
	playerID int,
	playerSK group.Scalar,
	dealerPK group.Point,
) (group.Scalar, error) {
	if playerID < 1 || playerID > config.N {
		return nil, fmt.Errorf("%w: player %d", ErrInvalidNodeID, playerID)
	}
	outerGroup := suite.OuterGroup()
	alpha, err := outerGroup.HashToScalar([]byte(lhlAlphaDomain), config.SessionID[:])
	if err != nil {
		return nil, err
	}
	sessionData := [][]byte{config.SessionID[:], trs.RandomMsg[:]}
	padResult, err := DerivePad(suite, playerSK, dealerPK, sessionData, alpha)
	if err != nil {
		return nil, err
	}
	ct := trs.Ciphertexts[playerID-1]
	share := outerGroup.NewScalar().Sub(ct.EncryptedShare, padResult.Pad)
	padResult.Pad.Zero()
	return share, nil
}

// compressedPoint returns the on-wire encoding of pt. Points that implement
// CompressedBytes() (e.g., BN254 G1) use it; groups whose Bytes() is already
// compressed (e.g., BJJ) fall back to Bytes().
func compressedPoint(pt group.Point) []byte {
	if cp, ok := pt.(interface{ CompressedBytes() []byte }); ok {
		return cp.CompressedBytes()
	}
	return pt.Bytes()
}

// decoder is a shared, strictly length-checked reader used by all
// deserializers in this package.
type decoder struct {
	buf []byte
	off int
}

func (d *decoder) remaining() int { return len(d.buf) - d.off }

func (d *decoder) fixed(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative fixed read: %d", n)
	}
	if d.remaining() < n {
		return nil, fmt.Errorf("short read: need %d have %d", n, d.remaining())
	}
	out := d.buf[d.off : d.off+n]
	d.off += n
	return out, nil
}

func (d *decoder) u32() (uint32, error) {
	b, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *decoder) point(g group.Group, size int) (group.Point, error) {
	b, err := d.fixed(size)
	if err != nil {
		return nil, err
	}
	pt, err := g.NewPoint().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (d *decoder) scalar(g group.Group, size int) (group.Scalar, error) {
	b, err := d.fixed(size)
	if err != nil {
		return nil, err
	}
	sc, err := g.NewScalar().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// -----------------------------------------------------------------------------
// Wire format (all big-endian integers; points are gnark-compressed 32B for
// both BN254 G1 and BJJ; scalars are 32B canonical big-endian).
//
//   RandomMsg               [32]
//   VSSCommitments          T  × 32B point
//   Ciphertexts             N  × (32B R point || 32B z scalar)
//   ProofLen                uint32    // bytes per PLONK proof (constant)
//   EVRFProofs              N  × ProofLen bytes, concatenated
//
// The N, T, scalar, and point widths are implicit from PVSSConfig and the
// suite's groups. The only runtime-variable field is ProofLen, emitted once.
// -----------------------------------------------------------------------------

// Serialize returns the canonical wire encoding of the transcript. The output
// is length-deterministic for a given (suite, N, T).
func (t *PVSSTranscript) Serialize() ([]byte, error) {
	if len(t.EVRFProofs) == 0 {
		return nil, fmt.Errorf("golden: empty EVRFProofs")
	}
	proofLen := len(t.EVRFProofs[0])
	for i, p := range t.EVRFProofs {
		if len(p) != proofLen {
			return nil, fmt.Errorf("%w: proof 0 has %d bytes, proof %d has %d", ErrPVSSProofSize, proofLen, i, len(p))
		}
	}
	pointSize := len(compressedPoint(t.VSSCommitments[0]))
	scalarSize := len(t.Ciphertexts[0].EncryptedShare.Bytes())

	total := 32 +
		len(t.VSSCommitments)*pointSize +
		len(t.Ciphertexts)*(pointSize+scalarSize) +
		4 +
		len(t.EVRFProofs)*proofLen
	out := make([]byte, 0, total)

	out = append(out, t.RandomMsg[:]...)
	for _, v := range t.VSSCommitments {
		out = append(out, compressedPoint(v)...)
	}
	for _, ct := range t.Ciphertexts {
		out = append(out, compressedPoint(ct.RCommitment)...)
		out = append(out, ct.EncryptedShare.Bytes()...)
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(proofLen))
	out = append(out, buf[:]...)
	for _, p := range t.EVRFProofs {
		out = append(out, p...)
	}
	return out, nil
}

// DeserializePVSSTranscript parses the encoding produced by Serialize into a
// transcript using the suite's outer group for points/scalars. N and T come
// from config.
func DeserializePVSSTranscript(
	data []byte,
	suite CurveSuite,
	config *PVSSConfig,
) (*PVSSTranscript, error) {
	if suite == nil {
		return nil, ErrNilSuite
	}
	if config == nil {
		return nil, fmt.Errorf("golden: nil PVSSConfig")
	}
	if config.T < 2 || config.N < config.T {
		return nil, ErrPVSSInvalidConfig
	}

	outer := suite.OuterGroup()
	pointSize := len(compressedPoint(outer.Generator()))
	scalarSize := len(outer.NewScalar().Bytes())

	d := &decoder{buf: data}
	trs := &PVSSTranscript{}

	rnd, err := d.fixed(32)
	if err != nil {
		return nil, fmt.Errorf("randomMsg: %w", err)
	}
	copy(trs.RandomMsg[:], rnd)

	trs.VSSCommitments = make([]group.Point, config.T)
	for i := range trs.VSSCommitments {
		pt, err := d.point(outer, pointSize)
		if err != nil {
			return nil, fmt.Errorf("vss[%d]: %w", i, err)
		}
		trs.VSSCommitments[i] = pt
	}

	trs.Ciphertexts = make([]*Ciphertext, config.N)
	for i := range trs.Ciphertexts {
		R, err := d.point(outer, pointSize)
		if err != nil {
			return nil, fmt.Errorf("ct[%d].R: %w", i, err)
		}
		z, err := d.scalar(outer, scalarSize)
		if err != nil {
			return nil, fmt.Errorf("ct[%d].z: %w", i, err)
		}
		trs.Ciphertexts[i] = &Ciphertext{RCommitment: R, EncryptedShare: z}
	}

	proofLen, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("proofLen: %w", err)
	}
	trs.EVRFProofs = make([][]byte, config.N)
	for i := range trs.EVRFProofs {
		p, err := d.fixed(int(proofLen))
		if err != nil {
			return nil, fmt.Errorf("proof[%d]: %w", i, err)
		}
		trs.EVRFProofs[i] = append([]byte(nil), p...)
	}
	if d.remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes: %d", d.remaining())
	}
	return trs, nil
}
