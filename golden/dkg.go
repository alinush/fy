package golden

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// CreateDealing generates a DKG dealing message for the non-interactive GOLDEN DKG.
//
// The dealer creates a random polynomial over Fr (BN254 scalar field), computes
// VSS commitments on BN254 G1, generates Shamir shares in Fr, encrypts shares
// for each peer using eVRF pads, and produces a Schnorr proof of BJJ PK ownership.
//
// The polynomial and shares are in Fr (not Z_l) to ensure consistency between
// the Shamir evaluation and the Feldman VSS commitment verification.
func CreateDealing(
	bjjGroup group.Group,
	bn254Group group.Group,
	config *DkgConfig,
	self *Participant,
	peers []*Participant,
	rng io.Reader,
) (*DkgDealing, error) {
	// Validate inputs.
	if self.ID < 1 || self.ID > MaxNodeID {
		return nil, ErrInvalidNodeID
	}
	if config.T < 2 || config.N < config.T {
		return nil, ErrInvalidConfig
	}
	if len(peers) != config.N-1 {
		return nil, ErrPeerCountMismatch
	}

	// Validate self ID is within [1, N].
	if self.ID > config.N {
		return nil, fmt.Errorf("%w: self ID %d exceeds N=%d", ErrNodeIDExceedsN, self.ID, config.N)
	}

	// Check for duplicate NodeIDs, bounds, and range [1, N].
	seen := map[int]bool{self.ID: true}
	for _, p := range peers {
		if p.ID < 1 || p.ID > MaxNodeID {
			return nil, ErrInvalidNodeID
		}
		if p.ID > config.N {
			return nil, fmt.Errorf("%w: peer ID %d exceeds N=%d", ErrNodeIDExceedsN, p.ID, config.N)
		}
		if seen[p.ID] {
			return nil, ErrDuplicateNodeID
		}
		seen[p.ID] = true
	}

	// Step 1: Sample omega in Fr, create polynomial of degree t-1 over Fr.
	omega, err := bn254Group.RandomScalar(rng)
	if err != nil {
		return nil, fmt.Errorf("golden: sampling omega: %w", err)
	}

	poly, err := NewRandomPolynomial(bn254Group, omega, config.T-1, rng)
	if err != nil {
		return nil, fmt.Errorf("golden: creating polynomial: %w", err)
	}

	// Step 2: Compute VSS commitments on BN254 G1.
	vssCommitments, err := VSSCommit(bn254Group, poly)
	if err != nil {
		return nil, fmt.Errorf("golden: VSS commit: %w", err)
	}

	// Step 3: Generate shares for all participants in Fr.
	shares := GenerateShares(bn254Group, poly, config.N)
	ownShare := shares[self.ID]

	// Step 4: Random 32-byte nonce for the session.
	var randomMsg [32]byte
	if _, err := io.ReadFull(rng, randomMsg[:]); err != nil {
		return nil, fmt.Errorf("golden: random nonce: %w", err)
	}

	// Step 5: Schnorr proof of BJJ identity (proves DH key ownership), bound to session.
	identityProof, err := ProveIdentity(bjjGroup, self.SK, self.PK, config.SessionID, rng)
	if err != nil {
		return nil, fmt.Errorf("golden: identity proof: %w", err)
	}

	// Step 6: Derive alpha for LHL combination.
	alpha, err := bn254Group.HashToScalar(
		[]byte("golden-lhl-alpha"),
		config.SessionID[:],
	)
	if err != nil {
		return nil, fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Step 7: Encrypt shares for each peer.
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}
	ciphertexts := make(map[int]*Ciphertext, len(peers))
	evrfProofs := make(map[int][]byte, len(peers))

	for _, peer := range peers {
		// Derive pad via eVRF.
		padResult, err := DerivePad(bjjGroup, bn254Group, self.SK, peer.PK, sessionData, alpha)
		if err != nil {
			return nil, fmt.Errorf("golden: derive pad for peer %d: %w", peer.ID, err)
		}

		// Encrypt: z = pad + share (both in Fr).
		peerShare := shares[peer.ID]
		z := bn254Group.NewScalar().Add(padResult.Pad, peerShare)

		ciphertexts[peer.ID] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}

		// Generate eVRF ZK proof.
		proof, err := GenerateEVRFProof(
			bjjGroup, bn254Group,
			self.SK, self.PK, peer.PK,
			sessionData, alpha, padResult,
		)
		if err != nil {
			return nil, fmt.Errorf("golden: eVRF proof for peer %d: %w", peer.ID, err)
		}
		evrfProofs[peer.ID] = proof

		// Zero pad after use.
		padResult.Pad.Zero()
	}

	// Zero polynomial coefficients and omega after use.
	poly.Zero()
	omega.Zero()

	// Zero peer shares (own share is kept).
	for id, share := range shares {
		if id != self.ID {
			share.Zero()
		}
	}

	return &DkgDealing{
		Message: &Round0Msg{
			SessionID:      config.SessionID,
			From:           self.ID,
			RandomMsg:      randomMsg,
			VSSCommitments: vssCommitments,
			Ciphertexts:    ciphertexts,
			IdentityProof:  identityProof,
			EVRFProofs:     evrfProofs,
		},
		PrivateShare: ownShare,
	}, nil
}

// VerifyDealing verifies a DKG dealing message from another participant.
func VerifyDealing(
	bjjGroup group.Group,
	bn254Group group.Group,
	config *DkgConfig,
	msg *Round0Msg,
	self *Participant,
	dealerPK group.Point,
	recipientPKs map[int]group.Point, // NodeID -> BJJ PK for all recipients (excluding dealer)
) error {
	// Check session ID.
	if msg.SessionID != config.SessionID {
		return ErrSessionIDMismatch
	}

	// Check VSSCommitments length matches threshold.
	if len(msg.VSSCommitments) != config.T {
		return ErrInvalidVSSLength
	}

	// Check PK contribution (VSSCommitments[0]) is not identity.
	if msg.VSSCommitments[0].IsIdentity() {
		return ErrIdentityPoint
	}

	// Check dealer has not included a ciphertext for themselves.
	if _, ok := msg.Ciphertexts[msg.From]; ok {
		return ErrDealerSelfCiphertext
	}

	// Verify exact recipient set: no missing and no extra ciphertexts/proofs.
	if len(msg.Ciphertexts) != len(recipientPKs) {
		return ErrExtraCiphertexts
	}
	if len(msg.EVRFProofs) != len(recipientPKs) {
		return ErrExtraEVRFProofs
	}
	for recipientID := range recipientPKs {
		if _, ok := msg.Ciphertexts[recipientID]; !ok {
			return fmt.Errorf("%w: recipient %d", ErrMissingCiphertext, recipientID)
		}
		if _, ok := msg.EVRFProofs[recipientID]; !ok {
			return fmt.Errorf("%w: recipient %d", ErrMissingEVRFProof, recipientID)
		}
	}

	// Verify identity proof (proves BJJ DH key ownership), bound to session.
	if msg.IdentityProof == nil {
		return ErrNilIdentityProof
	}
	if err := VerifyIdentity(bjjGroup, dealerPK, config.SessionID, msg.IdentityProof); err != nil {
		return fmt.Errorf("golden: identity proof: %w", err)
	}

	// Derive alpha.
	alpha, err := bn254Group.HashToScalar(
		[]byte("golden-lhl-alpha"),
		config.SessionID[:],
	)
	if err != nil {
		return fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Verify ciphertext consistency for all recipients.
	for recipientID, ct := range msg.Ciphertexts {
		// R commitment must not be identity (would mean no encryption).
		if ct.RCommitment.IsIdentity() {
			return fmt.Errorf("%w: recipient %d", ErrIdentityRCommitment, recipientID)
		}

		// z * G_bn254 should equal R + ExpectedShareCommitment(VSS, recipientID).
		zG := bn254Group.NewPoint().ScalarMult(ct.EncryptedShare, bn254Group.Generator())

		expectedShareCommit := ExpectedShareCommitment(bn254Group, msg.VSSCommitments, recipientID)
		rhs := bn254Group.NewPoint().Add(ct.RCommitment, expectedShareCommit)

		if !zG.Equal(rhs) {
			return fmt.Errorf("%w: recipient %d", ErrCiphertextVerification, recipientID)
		}
	}

	// Verify eVRF proofs for all recipients.
	sessionData := [][]byte{config.SessionID[:], msg.RandomMsg[:]}
	for recipientID, proofBytes := range msg.EVRFProofs {
		ct := msg.Ciphertexts[recipientID]
		if ct == nil {
			return fmt.Errorf("golden: no ciphertext for eVRF proof recipient %d", recipientID)
		}

		recipientPK, ok := recipientPKs[recipientID]
		if !ok {
			return fmt.Errorf("golden: no PK for eVRF proof recipient %d", recipientID)
		}

		err := VerifyEVRFProof(
			bjjGroup, bn254Group,
			dealerPK,
			recipientPK,
			sessionData, alpha,
			ct.RCommitment,
			proofBytes,
		)
		if err != nil {
			return fmt.Errorf("%w: recipient %d: %v", ErrEVRFProofFailed, recipientID, err)
		}
	}

	return nil
}

// Complete finalizes the DKG protocol for one participant, combining all dealings.
//
// The participant aggregates:
//  1. Their own share from their own polynomial (in Fr)
//  2. Decrypted shares from all peer dealings (in Fr)
//  3. The group public key from VSSCommitments[0] of all dealings
//  4. Public key shares for all participants from VSS commitments
//
// All share arithmetic is in Fr to maintain consistency with VSS.
func Complete(
	bjjGroup group.Group,
	bn254Group group.Group,
	config *DkgConfig,
	self *Participant,
	ownDealing *DkgDealing,
	peerDealings []*Round0Msg,
	peerPKs map[int]group.Point, // NodeID -> BJJ PK
) (*DkgOutput, error) {
	if len(peerDealings) != config.N-1 {
		return nil, ErrPeerCountMismatch
	}

	// Validate peer dealing set integrity.
	seenDealers := make(map[int]bool)
	for _, msg := range peerDealings {
		if msg.From == self.ID {
			return nil, ErrSelfDealing
		}
		if seenDealers[msg.From] {
			return nil, fmt.Errorf("%w: dealer %d", ErrDuplicateDealing, msg.From)
		}
		seenDealers[msg.From] = true
		if _, ok := peerPKs[msg.From]; !ok {
			return nil, fmt.Errorf("%w: dealer %d", ErrUnknownDealer, msg.From)
		}
		if msg.SessionID != config.SessionID {
			return nil, ErrSessionIDMismatch
		}
	}

	// Derive alpha.
	alpha, err := bn254Group.HashToScalar(
		[]byte("golden-lhl-alpha"),
		config.SessionID[:],
	)
	if err != nil {
		return nil, fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Start with own share (in Fr).
	secretShare := bn254Group.NewScalar().Set(ownDealing.PrivateShare)

	// Group key = sum of all VSSCommitments[0] (= omega_d * G_bn254 for each dealer).
	groupKey := bn254Group.NewPoint().Set(ownDealing.Message.VSSCommitments[0])

	// Collect all VSS commitments for computing PK shares.
	allVSSCommitments := make([][]group.Point, 0, config.N)
	allVSSCommitments = append(allVSSCommitments, ownDealing.Message.VSSCommitments)

	for _, msg := range peerDealings {
		// Add peer's PK contribution to group key.
		groupKey = bn254Group.NewPoint().Add(groupKey, msg.VSSCommitments[0])

		// Collect VSS commitments for PK share computation.
		allVSSCommitments = append(allVSSCommitments, msg.VSSCommitments)

		// Find our ciphertext.
		ct, ok := msg.Ciphertexts[self.ID]
		if !ok {
			return nil, fmt.Errorf("golden: no ciphertext for self (ID %d) in dealing from %d", self.ID, msg.From)
		}
		if ct == nil {
			return nil, fmt.Errorf("%w: from dealer %d", ErrNilCiphertext, msg.From)
		}

		// Re-derive pad.
		sessionData := [][]byte{config.SessionID[:], msg.RandomMsg[:]}
		padResult, err := DerivePad(bjjGroup, bn254Group, self.SK, peerPKs[msg.From], sessionData, alpha)
		if err != nil {
			return nil, fmt.Errorf("golden: re-derive pad from %d: %w", msg.From, err)
		}

		// Decrypt: share = z - pad (in Fr).
		decryptedShare := bn254Group.NewScalar().Sub(ct.EncryptedShare, padResult.Pad)

		// Zero pad after use.
		padResult.Pad.Zero()

		// Accumulate in Fr (same field as polynomial evaluation).
		secretShare = bn254Group.NewScalar().Add(secretShare, decryptedShare)

		// Zero decrypted share.
		decryptedShare.Zero()
	}

	// Compute public key shares for ALL participants from VSS commitments.
	// pkShare_i = sum_d(ExpectedShareCommitment(vss_d, i))
	// Note: This assumes participant IDs are contiguous from 1 to N.
	// CreateDealing enforces this by requiring all IDs to be in [1, N] with no duplicates.
	pkShares := make(map[int]group.Point, config.N)
	for i := 1; i <= config.N; i++ {
		var pkShare group.Point
		for _, vss := range allVSSCommitments {
			shareCommit := ExpectedShareCommitment(bn254Group, vss, i)
			if pkShare == nil {
				pkShare = shareCommit
			} else {
				pkShare = bn254Group.NewPoint().Add(pkShare, shareCommit)
			}
		}
		pkShares[i] = pkShare
	}

	return &DkgOutput{
		PublicKey:       groupKey,
		PublicKeyShares: pkShares,
		SecretShare:     secretShare,
	}, nil
}

// GenerateEVRFProof generates a ZK proof for the eVRF pad derivation using gnark PLONK.
// This proves that RCommitment was correctly derived from DH(sk, peerPK) without
// revealing the secret key.
func GenerateEVRFProof(
	bjjGroup group.Group,
	bn254Group group.Group,
	dealerSK group.Scalar,
	dealerPK group.Point,
	recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	padResult *PadResult,
) ([]byte, error) {
	return generateEVRFProofPLONK(
		bjjGroup, bn254Group,
		dealerSK, dealerPK, recipientPK,
		sessionData, alpha, padResult,
	)
}

// VerifyEVRFProof verifies a ZK proof for the eVRF pad derivation.
func VerifyEVRFProof(
	bjjGroup group.Group,
	bn254Group group.Group,
	dealerPK group.Point,
	recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	rCommitment group.Point,
	proofBytes []byte,
) error {
	return verifyEVRFProofPLONK(
		bjjGroup, bn254Group,
		dealerPK, recipientPK,
		sessionData, alpha,
		rCommitment, proofBytes,
	)
}

// init initializes the eVRF proof system keys lazily.
func init() {
	// PLONK keys are compiled and cached on first use.
	// See evrf_proof.go for the circuit definition and key management.
	_ = rand.Reader // ensure crypto/rand is imported
}
