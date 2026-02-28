package golden

import (
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// CreateDealing generates a DKG dealing message for the non-interactive GOLDEN DKG.
//
// The dealer creates a random polynomial over the outer-group scalar field, computes
// Feldman VSS commitments on the outer group, generates Shamir shares, encrypts shares
// for each peer using eVRF pads, and produces a Schnorr proof of inner-curve PK ownership.
//
// The polynomial and shares are in the outer-group scalar field to ensure consistency
// between the Shamir evaluation and the Feldman VSS commitment verification.
func CreateDealing(
	suite CurveSuite,
	config *DkgConfig,
	self *Participant,
	peers []*Participant,
	rng io.Reader,
) (*DkgDealing, error) {
	if suite == nil {
		return nil, ErrNilSuite
	}
	innerGroup := suite.InnerGroup()
	outerGroup := suite.OuterGroup()

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
	omega, err := outerGroup.RandomScalar(rng)
	if err != nil {
		return nil, fmt.Errorf("golden: sampling omega: %w", err)
	}

	poly, err := NewRandomPolynomial(outerGroup, omega, config.T-1, rng)
	if err != nil {
		return nil, fmt.Errorf("golden: creating polynomial: %w", err)
	}

	// Step 2: Compute VSS commitments on the outer group.
	vssCommitments, err := VSSCommit(outerGroup, poly)
	if err != nil {
		return nil, fmt.Errorf("golden: VSS commit: %w", err)
	}

	// Step 3: Generate shares for all participants in Fr.
	shares := GenerateShares(outerGroup, poly, config.N)
	ownShare := shares[self.ID]

	// Step 4: Random 32-byte nonce for the session.
	var randomMsg [32]byte
	if _, err := io.ReadFull(rng, randomMsg[:]); err != nil {
		return nil, fmt.Errorf("golden: random nonce: %w", err)
	}

	// Step 5: Schnorr proof of inner-curve identity (proves DH key ownership), bound to session.
	identityProof, err := ProveIdentity(innerGroup, self.SK, self.PK, config.SessionID, rng)
	if err != nil {
		return nil, fmt.Errorf("golden: identity proof: %w", err)
	}

	// Step 6: Derive alpha for LHL combination.
	alpha, err := outerGroup.HashToScalar(
		[]byte(lhlAlphaDomain),
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
		padResult, err := DerivePad(suite, self.SK, peer.PK, sessionData, alpha)
		if err != nil {
			return nil, fmt.Errorf("golden: derive pad for peer %d: %w", peer.ID, err)
		}

		// Encrypt: z = pad + share (both in Fr).
		peerShare := shares[peer.ID]
		z := outerGroup.NewScalar().Add(padResult.Pad, peerShare)

		ciphertexts[peer.ID] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}

		// Generate eVRF ZK proof.
		proof, err := suite.GenerateEVRFProof(
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
	suite CurveSuite,
	config *DkgConfig,
	msg *Round0Msg,
	self *Participant,
	dealerPK group.Point,
	recipientPKs map[int]group.Point, // NodeID -> inner-curve PK for all recipients (excluding dealer)
) error {
	if suite == nil {
		return ErrNilSuite
	}
	innerGroup := suite.InnerGroup()
	outerGroup := suite.OuterGroup()

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

	// Verify identity proof (proves inner-curve DH key ownership), bound to session.
	if msg.IdentityProof == nil {
		return ErrNilIdentityProof
	}
	if err := VerifyIdentity(innerGroup, dealerPK, config.SessionID, msg.IdentityProof); err != nil {
		return fmt.Errorf("golden: identity proof: %w", err)
	}

	// Derive alpha.
	alpha, err := outerGroup.HashToScalar(
		[]byte(lhlAlphaDomain),
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
		zG := outerGroup.NewPoint().ScalarMult(ct.EncryptedShare, outerGroup.Generator())

		expectedShareCommit := ExpectedShareCommitment(outerGroup, msg.VSSCommitments, recipientID)
		rhs := outerGroup.NewPoint().Add(ct.RCommitment, expectedShareCommit)

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

		err := suite.VerifyEVRFProof(
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
//  1. Their own share from their own polynomial (outer-group scalar field)
//  2. Decrypted shares from all peer dealings (outer-group scalar field)
//  3. The group public key from VSSCommitments[0] of all dealings
//  4. Public key shares for all participants from VSS commitments
//
// All share arithmetic is in the outer-group scalar field to maintain
// consistency with VSS.
func Complete(
	suite CurveSuite,
	config *DkgConfig,
	self *Participant,
	ownDealing *DkgDealing,
	peerDealings []*Round0Msg,
	peerPKs map[int]group.Point, // NodeID -> inner-curve PK
) (*DkgOutput, error) {
	if suite == nil {
		return nil, ErrNilSuite
	}
	outerGroup := suite.OuterGroup()

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
	alpha, err := outerGroup.HashToScalar(
		[]byte(lhlAlphaDomain),
		config.SessionID[:],
	)
	if err != nil {
		return nil, fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Start with own share (outer-group scalar field).
	secretShare := outerGroup.NewScalar().Set(ownDealing.PrivateShare)

	// errZeroSecret zeros secretShare and returns the formatted error.
	// Used on error paths in the loop below to prevent leaking the partial
	// secret accumulation.
	errZeroSecret := func(format string, args ...any) (*DkgOutput, error) {
		secretShare.Zero()
		return nil, fmt.Errorf(format, args...)
	}

	// Group key = sum of all VSSCommitments[0] (= omega_d * G_outer for each dealer).
	groupKey := outerGroup.NewPoint().Set(ownDealing.Message.VSSCommitments[0])

	// Collect all VSS commitments for computing PK shares.
	allVSSCommitments := make([][]group.Point, 0, config.N)
	allVSSCommitments = append(allVSSCommitments, ownDealing.Message.VSSCommitments)

	for _, msg := range peerDealings {
		// Add peer's PK contribution to group key.
		groupKey = outerGroup.NewPoint().Add(groupKey, msg.VSSCommitments[0])

		// Collect VSS commitments for PK share computation.
		allVSSCommitments = append(allVSSCommitments, msg.VSSCommitments)

		// Find our ciphertext.
		ct, ok := msg.Ciphertexts[self.ID]
		if !ok {
			return errZeroSecret("golden: no ciphertext for self (ID %d) in dealing from %d", self.ID, msg.From)
		}
		if ct == nil {
			return errZeroSecret("%s: from dealer %d", ErrNilCiphertext, msg.From)
		}

		// Re-derive pad.
		sessionData := [][]byte{config.SessionID[:], msg.RandomMsg[:]}
		padResult, err := DerivePad(suite, self.SK, peerPKs[msg.From], sessionData, alpha)
		if err != nil {
			return errZeroSecret("golden: re-derive pad from %d: %w", msg.From, err)
		}

		// Decrypt: share = z - pad (outer-group scalar field).
		decryptedShare := outerGroup.NewScalar().Sub(ct.EncryptedShare, padResult.Pad)

		// Zero pad after use.
		padResult.Pad.Zero()

		// Accumulate in the outer-group scalar field (same field as polynomial evaluation).
		secretShare = outerGroup.NewScalar().Add(secretShare, decryptedShare)

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
			shareCommit := ExpectedShareCommitment(outerGroup, vss, i)
			if pkShare == nil {
				pkShare = shareCommit
			} else {
				pkShare = outerGroup.NewPoint().Add(pkShare, shareCommit)
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
