package golden

import (
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// MaxParticipants is the upper bound on the number of participants (N) in a
// GOLDEN DKG session. This limits resource consumption (polynomial evaluation,
// VSS commitments, ciphertext generation) and prevents abuse via excessively
// large participant sets.
const MaxParticipants = 256

// CreateDealing generates a DKG dealing message for the non-interactive GOLDEN DKG.
//
// The dealer creates a random polynomial over the outer-group scalar field, computes
// Feldman VSS commitments on the outer group, generates Shamir shares, encrypts shares
// for each peer using eVRF pads, and produces a Schnorr proof of inner-curve PK ownership.
//
// The polynomial and shares are in the outer-group scalar field to ensure consistency
// between the Shamir evaluation and the Feldman VSS commitment verification.
//
// Callers must ensure peer public keys are validated on-curve and in-subgroup
// before calling CreateDealing. The function checks for identity keys but does
// not perform full subgroup membership verification.
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
	if config == nil {
		return nil, fmt.Errorf("golden: nil DkgConfig")
	}
	if self == nil {
		return nil, fmt.Errorf("golden: nil self Participant")
	}
	innerGroup := suite.InnerGroup()
	outerGroup := suite.OuterGroup()

	// Validate inputs.
	if self.ID < 1 || self.ID > MaxNodeID {
		return nil, ErrInvalidNodeID
	}
	if self.SK == nil || self.PK == nil {
		return nil, fmt.Errorf("golden: nil self secret key or public key")
	}
	if self.PK.IsIdentity() {
		return nil, fmt.Errorf("%w: self has identity public key", ErrIdentityPoint)
	}
	if config.T < 2 || config.N < config.T {
		return nil, ErrInvalidConfig
	}
	if config.N > MaxParticipants {
		return nil, fmt.Errorf("golden: N=%d exceeds maximum %d", config.N, MaxParticipants)
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

	// Validate peer public keys are not identity.
	for _, p := range peers {
		if p.PK == nil || p.PK.IsIdentity() {
			return nil, fmt.Errorf("%w: peer %d has nil or identity public key", ErrIdentityPoint, p.ID)
		}
	}

	// Step 1: Sample omega in Fr, create polynomial of degree t-1 over Fr.
	omega, err := outerGroup.RandomScalar(rng)
	if err != nil {
		return nil, fmt.Errorf("golden: sampling omega: %w", err)
	}

	poly, err := NewRandomPolynomial(outerGroup, omega, config.T-1, rng)
	if err != nil {
		omega.Zero()
		return nil, fmt.Errorf("golden: creating polynomial: %w", err)
	}

	// Step 2: Compute VSS commitments on the outer group.
	vssCommitments, err := VSSCommit(outerGroup, poly)
	if err != nil {
		poly.Zero()
		omega.Zero()
		return nil, fmt.Errorf("golden: VSS commit: %w", err)
	}

	// Step 3: Generate shares for all participants in Fr.
	shares, err := GenerateShares(outerGroup, poly, config.N)
	if err != nil {
		poly.Zero()
		omega.Zero()
		return nil, fmt.Errorf("golden: generating shares: %w", err)
	}
	ownShare := shares[self.ID]

	// zeroSecrets zeros all accumulated secret material. Called on error
	// paths and on the normal exit path (for intermediates not returned).
	hasDerived := len(config.DerivedGroups) > 0
	var padBytesCache map[int][]byte
	zeroSecrets := func() {
		poly.Zero()
		omega.Zero()
		for id, share := range shares {
			if id != self.ID {
				share.Zero()
			}
		}
		for id := range padBytesCache {
			for i := range padBytesCache[id] {
				padBytesCache[id][i] = 0
			}
		}
	}

	// Step 4: Random 32-byte nonce for the session.
	var randomMsg [32]byte
	if _, err := io.ReadFull(rng, randomMsg[:]); err != nil {
		zeroSecrets()
		return nil, fmt.Errorf("golden: random nonce: %w", err)
	}

	// Step 5: Schnorr proof of inner-curve identity (proves DH key ownership), bound to session.
	identityProof, err := ProveIdentity(innerGroup, self.SK, self.PK, config.SessionID, rng)
	if err != nil {
		zeroSecrets()
		return nil, fmt.Errorf("golden: identity proof: %w", err)
	}

	// Step 6: Derive alpha for LHL combination.
	alpha, err := outerGroup.HashToScalar(
		[]byte(lhlAlphaDomain),
		config.SessionID[:],
	)
	if err != nil {
		zeroSecrets()
		return nil, fmt.Errorf("golden: deriving alpha: %w", err)
	}

	// Step 7: Encrypt shares for each peer, caching pad bytes for derived curves.
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}
	ciphertexts := make(map[int]*Ciphertext, len(peers))
	evrfProofs := make(map[int][]byte, len(peers))

	// Cache pad bytes per peer so derived curves can re-derive their own pads
	// via SetBytes (auto-reduces mod each group's order).
	if hasDerived {
		padBytesCache = make(map[int][]byte, len(peers))
	}

	for _, peer := range peers {
		// Derive pad via eVRF.
		padResult, err := DerivePad(suite, self.SK, peer.PK, sessionData, alpha)
		if err != nil {
			zeroSecrets()
			return nil, fmt.Errorf("golden: derive pad for peer %d: %w", peer.ID, err)
		}

		// Cache pad bytes before zeroing, for derived curve encryption.
		if hasDerived {
			padBytesCache[peer.ID] = padResult.Pad.Bytes()
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
			padResult.Pad.Zero()
			zeroSecrets()
			return nil, fmt.Errorf("golden: eVRF proof for peer %d: %w", peer.ID, err)
		}
		evrfProofs[peer.ID] = proof

		// Zero pad after use.
		padResult.Pad.Zero()
	}

	// Step 8: Derived curve shares, VSS commitments, and ciphertexts.
	var derivedCurves []*DerivedCurveData
	var derivedPrivateShares []group.Scalar

	if hasDerived {
		derivedCurves = make([]*DerivedCurveData, len(config.DerivedGroups))
		derivedPrivateShares = make([]group.Scalar, len(config.DerivedGroups))

		for idx, dg := range config.DerivedGroups {
			// Derive coefficients via SetBytes (auto-reduces mod group order).
			//
			// Security: For groups with order > Fr (e.g., secp256k1 ~2^256 vs Fr ~2^254),
			// no reduction occurs; coefficients are injected exactly. For groups with
			// order < Fr (e.g., BJJ ~2^251), reduction introduces negligible statistical
			// bias ~2^-(|l| - log2(r/l)) ≈ 2^-248 for BJJ. This is cryptographically
			// negligible and does not affect the Shamir threshold property.
			derivedCoeffs := make([]group.Scalar, len(poly.Coefficients))
			for j, c := range poly.Coefficients {
				dc := dg.NewScalar()
				if _, err := dc.SetBytes(c.Bytes()); err != nil {
					zeroSecrets()
					return nil, fmt.Errorf("golden: derived[%d] coeff %d SetBytes: %w", idx, j, err)
				}
				derivedCoeffs[j] = dc
			}
			derivedPoly := &Polynomial{Coefficients: derivedCoeffs}

			// Generate derived shares.
			derivedShares, err := GenerateShares(dg, derivedPoly, config.N)
			if err != nil {
				derivedPoly.Zero()
				zeroSecrets()
				return nil, fmt.Errorf("golden: derived[%d] generating shares: %w", idx, err)
			}
			derivedPrivateShares[idx] = derivedShares[self.ID]

			// VSS commitments on derived group.
			derivedVSS, err := VSSCommit(dg, derivedPoly)
			if err != nil {
				derivedPoly.Zero()
				zeroSecrets()
				return nil, fmt.Errorf("golden: derived[%d] VSS commit: %w", idx, err)
			}

			// Encrypt for each peer using cached pad bytes.
			derivedCts := make(map[int]*Ciphertext, len(peers))
			for _, peer := range peers {
				// Derive pad for this group (auto-reduces via SetBytes).
				derivedPad := dg.NewScalar()
				if _, err := derivedPad.SetBytes(padBytesCache[peer.ID]); err != nil {
					derivedPoly.Zero()
					zeroSecrets()
					return nil, fmt.Errorf("golden: derived[%d] pad SetBytes peer %d: %w", idx, peer.ID, err)
				}

				// z = derivedPad + derivedShare
				z := dg.NewScalar().Add(derivedPad, derivedShares[peer.ID])

				// R = derivedPad * G_derived
				R := dg.NewPoint().ScalarMult(derivedPad, dg.Generator())

				derivedCts[peer.ID] = &Ciphertext{RCommitment: R, EncryptedShare: z}
				derivedPad.Zero()
			}

			derivedCurves[idx] = &DerivedCurveData{
				VSSCommitments: derivedVSS,
				Ciphertexts:    derivedCts,
			}

			// Zero derived polynomial and peer shares.
			derivedPoly.Zero()
			for id, share := range derivedShares {
				if id != self.ID {
					share.Zero()
				}
			}
		}
	}

	// Zero polynomial, omega, peer shares, and cached pad bytes.
	zeroSecrets()

	return &DkgDealing{
		Message: &Round0Msg{
			SessionID:      config.SessionID,
			From:           self.ID,
			RandomMsg:      randomMsg,
			VSSCommitments: vssCommitments,
			Ciphertexts:    ciphertexts,
			IdentityProof:  identityProof,
			EVRFProofs:     evrfProofs,
			DerivedCurves:  derivedCurves,
		},
		PrivateShare:         ownShare,
		DerivedPrivateShares: derivedPrivateShares,
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
	if config == nil {
		return fmt.Errorf("golden: nil DkgConfig")
	}
	if msg == nil {
		return fmt.Errorf("golden: nil Round0Msg")
	}
	if self == nil {
		return fmt.Errorf("golden: nil self Participant")
	}
	innerGroup := suite.InnerGroup()
	outerGroup := suite.OuterGroup()

	// Validate dealerPK is not nil or identity.
	if dealerPK == nil || dealerPK.IsIdentity() {
		return fmt.Errorf("%w: dealer has nil or identity public key", ErrIdentityPoint)
	}

	// Check session ID.
	if msg.SessionID != config.SessionID {
		return ErrSessionIDMismatch
	}

	// Validate msg.From is within [1, N].
	if msg.From < 1 || msg.From > config.N {
		return fmt.Errorf("%w: dealer ID %d out of range [1, %d]", ErrInvalidNodeID, msg.From, config.N)
	}

	// Validate recipient public keys are not nil or identity.
	for id, pk := range recipientPKs {
		if pk == nil || pk.IsIdentity() {
			return fmt.Errorf("%w: recipient %d has nil or identity public key", ErrIdentityPoint, id)
		}
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

	// Validate derived curve count (structural check before expensive crypto).
	if len(config.DerivedGroups) > 0 {
		if len(msg.DerivedCurves) != len(config.DerivedGroups) {
			return ErrDerivedCurveCountMismatch
		}
	} else if len(msg.DerivedCurves) > 0 {
		return ErrDerivedCurveCountMismatch
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

		expectedShareCommit, err := ExpectedShareCommitment(outerGroup, msg.VSSCommitments, recipientID)
		if err != nil {
			return fmt.Errorf("golden: share commitment for recipient %d: %w", recipientID, err)
		}
		rhs := outerGroup.NewPoint().Add(ct.RCommitment, expectedShareCommit)

		if !zG.Equal(rhs) {
			return fmt.Errorf("%w: recipient %d", ErrCiphertextVerification, recipientID)
		}
	}

	// Verify eVRF proofs for all recipients.
	sessionData := [][]byte{config.SessionID[:], msg.RandomMsg[:]}
	for recipientID, proofBytes := range msg.EVRFProofs {
		if len(proofBytes) == 0 {
			return fmt.Errorf("%w: recipient %d has empty proof", ErrEVRFProofFailed, recipientID)
		}

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

	// Verify derived curve data (count already validated above).
	if len(config.DerivedGroups) > 0 {
		for idx, dg := range config.DerivedGroups {
			dc := msg.DerivedCurves[idx]
			if dc == nil {
				return fmt.Errorf("golden: nil derived curve data at index %d", idx)
			}

			// Validate VSS length matches threshold.
			if len(dc.VSSCommitments) != config.T {
				return fmt.Errorf("%w: derived[%d]", ErrInvalidVSSLength, idx)
			}

			// PK contribution must not be identity.
			if dc.VSSCommitments[0].IsIdentity() {
				return fmt.Errorf("%w: derived[%d] PK contribution", ErrIdentityPoint, idx)
			}

			// Validate recipient set: must match expected recipients exactly.
			// Mirrors primary ciphertext validation at lines above.
			if _, ok := dc.Ciphertexts[msg.From]; ok {
				return fmt.Errorf("%w: derived[%d]", ErrDealerSelfCiphertext, idx)
			}
			if len(dc.Ciphertexts) != len(recipientPKs) {
				return fmt.Errorf("%w: derived[%d]", ErrExtraCiphertexts, idx)
			}
			for recipientID := range recipientPKs {
				if _, ok := dc.Ciphertexts[recipientID]; !ok {
					return fmt.Errorf("%w: derived[%d] recipient %d", ErrMissingCiphertext, idx, recipientID)
				}
			}

			// Verify ciphertext algebraic consistency for all recipients.
			for recipientID, ct := range dc.Ciphertexts {
				if ct == nil {
					return fmt.Errorf("%w: derived[%d] recipient %d", ErrNilCiphertext, idx, recipientID)
				}
				// R commitment must not be identity (would mean share is unencrypted).
				if ct.RCommitment.IsIdentity() {
					return fmt.Errorf("%w: derived[%d] recipient %d", ErrIdentityRCommitment, idx, recipientID)
				}
				// z * G_derived == R + ExpectedShareCommitment(derivedVSS, recipientID)
				zG := dg.NewPoint().ScalarMult(ct.EncryptedShare, dg.Generator())
				expected, err := ExpectedShareCommitment(dg, dc.VSSCommitments, recipientID)
				if err != nil {
					return fmt.Errorf("golden: derived[%d] share commitment for recipient %d: %w", idx, recipientID, err)
				}
				rhs := dg.NewPoint().Add(ct.RCommitment, expected)

				if !zG.Equal(rhs) {
					return fmt.Errorf("%w: derived[%d] recipient %d", ErrDerivedCiphertextVerification, idx, recipientID)
				}
			}
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
	if config == nil {
		return nil, fmt.Errorf("golden: nil DkgConfig")
	}
	if self == nil {
		return nil, fmt.Errorf("golden: nil self Participant")
	}
	if ownDealing == nil {
		return nil, fmt.Errorf("golden: nil ownDealing")
	}
	if self.SK == nil || self.PK == nil {
		return nil, fmt.Errorf("golden: nil self secret key or public key")
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

	// Validate peer public keys are not identity.
	for id, pk := range peerPKs {
		if pk == nil || pk.IsIdentity() {
			return nil, fmt.Errorf("%w: peer %d has nil or identity public key", ErrIdentityPoint, id)
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

	// Cache pad bytes per peer during primary decryption so derived curves
	// can reuse them without re-deriving (single DerivePad call per peer).
	hasDerived := len(config.DerivedGroups) > 0
	var padBytesPerPeer map[int][]byte
	if hasDerived {
		padBytesPerPeer = make(map[int][]byte, len(peerDealings))
	}

	// errZeroSecret zeros secretShare (and cached pad bytes) and returns the error.
	errZeroSecret := func(format string, args ...any) (*DkgOutput, error) {
		secretShare.Zero()
		for id := range padBytesPerPeer {
			for i := range padBytesPerPeer[id] {
				padBytesPerPeer[id][i] = 0
			}
		}
		return nil, fmt.Errorf(format, args...)
	}

	// Group key = sum of all VSSCommitments[0] (= omega_d * G_outer for each dealer).
	groupKey := outerGroup.NewPoint().Set(ownDealing.Message.VSSCommitments[0])

	// Collect all VSS commitments for computing PK shares.
	allVSSCommitments := make([][]group.Point, 0, config.N)
	allVSSCommitments = append(allVSSCommitments, ownDealing.Message.VSSCommitments)

	for _, msg := range peerDealings {
		// Validate peer's VSSCommitments length matches config.T.
		if len(msg.VSSCommitments) != config.T {
			return errZeroSecret("%s: from dealer %d", ErrInvalidVSSLength, msg.From)
		}

		// Validate peer's DerivedCurves length matches config.
		if hasDerived && len(msg.DerivedCurves) != len(config.DerivedGroups) {
			return errZeroSecret("%s: from dealer %d", ErrDerivedCurveCountMismatch, msg.From)
		}

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

		// Re-derive pad (single call — bytes are cached for derived curves).
		sessionData := [][]byte{config.SessionID[:], msg.RandomMsg[:]}
		padResult, err := DerivePad(suite, self.SK, peerPKs[msg.From], sessionData, alpha)
		if err != nil {
			return errZeroSecret("golden: re-derive pad from %d: %w", msg.From, err)
		}

		// Cache pad bytes before zeroing, for derived curve decryption.
		if hasDerived {
			padBytesPerPeer[msg.From] = padResult.Pad.Bytes()
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
			shareCommit, err := ExpectedShareCommitment(outerGroup, vss, i)
			if err != nil {
				return nil, fmt.Errorf("golden: pk share commitment for participant %d: %w", i, err)
			}
			if pkShare == nil {
				pkShare = shareCommit
			} else {
				pkShare = outerGroup.NewPoint().Add(pkShare, shareCommit)
			}
		}
		pkShares[i] = pkShare
	}

	// Derived curve share accumulation.
	var derivedOutputs []*DerivedOutput

	if hasDerived {
		// Validate own dealing has matching derived data.
		if len(ownDealing.Message.DerivedCurves) != len(config.DerivedGroups) {
			return errZeroSecret("%s", ErrDerivedCurveCountMismatch)
		}
		if len(ownDealing.DerivedPrivateShares) != len(config.DerivedGroups) {
			return errZeroSecret("%s", ErrDerivedCurveCountMismatch)
		}

		// errZeroDerived zeros accumulated secrets and cached pad bytes.
		errZeroDerived := func(derivedSecrets []group.Scalar, format string, args ...any) (*DkgOutput, error) {
			for _, s := range derivedSecrets {
				if s != nil {
					s.Zero()
				}
			}
			for id := range padBytesPerPeer {
				for i := range padBytesPerPeer[id] {
					padBytesPerPeer[id][i] = 0
				}
			}
			secretShare.Zero()
			return nil, fmt.Errorf(format, args...)
		}

		derivedOutputs = make([]*DerivedOutput, len(config.DerivedGroups))
		derivedSecrets := make([]group.Scalar, len(config.DerivedGroups))

		for idx, dg := range config.DerivedGroups {
			// Start with own derived share.
			derivedSecrets[idx] = dg.NewScalar().Set(ownDealing.DerivedPrivateShares[idx])

			// Group key from own VSS[0].
			derivedGroupKey := dg.NewPoint().Set(ownDealing.Message.DerivedCurves[idx].VSSCommitments[0])

			// Collect all derived VSS commitments.
			allDerivedVSS := make([][]group.Point, 0, config.N)
			allDerivedVSS = append(allDerivedVSS, ownDealing.Message.DerivedCurves[idx].VSSCommitments)

			for _, msg := range peerDealings {
				dc := msg.DerivedCurves[idx]

				// Add peer's derived PK contribution.
				derivedGroupKey = dg.NewPoint().Add(derivedGroupKey, dc.VSSCommitments[0])

				// Collect VSS commitments.
				allDerivedVSS = append(allDerivedVSS, dc.VSSCommitments)

				// Find our ciphertext.
				ct := dc.Ciphertexts[self.ID]
				if ct == nil {
					return errZeroDerived(derivedSecrets, "golden: no derived[%d] ciphertext for self from dealer %d", idx, msg.From)
				}

				// Reduce cached BN254 pad bytes to derived group order.
				derivedPad := dg.NewScalar()
				if _, err := derivedPad.SetBytes(padBytesPerPeer[msg.From]); err != nil {
					return errZeroDerived(derivedSecrets, "golden: derived[%d] pad SetBytes: %w", idx, err)
				}

				// Decrypt: share = z - derivedPad.
				decrypted := dg.NewScalar().Sub(ct.EncryptedShare, derivedPad)
				derivedPad.Zero()

				// Accumulate.
				derivedSecrets[idx] = dg.NewScalar().Add(derivedSecrets[idx], decrypted)
				decrypted.Zero()
			}

			// Compute derived PK shares.
			derivedPKShares := make(map[int]group.Point, config.N)
			for i := 1; i <= config.N; i++ {
				var pk group.Point
				for _, vss := range allDerivedVSS {
					sc, err := ExpectedShareCommitment(dg, vss, i)
					if err != nil {
						return nil, fmt.Errorf("golden: derived[%d] pk share commitment for participant %d: %w", idx, i, err)
					}
					if pk == nil {
						pk = sc
					} else {
						pk = dg.NewPoint().Add(pk, sc)
					}
				}
				derivedPKShares[i] = pk
			}

			derivedOutputs[idx] = &DerivedOutput{
				Group:           dg,
				PublicKey:       derivedGroupKey,
				PublicKeyShares: derivedPKShares,
				SecretShare:     derivedSecrets[idx],
			}
		}

		// Zero cached pad bytes on success path.
		for id := range padBytesPerPeer {
			for i := range padBytesPerPeer[id] {
				padBytesPerPeer[id][i] = 0
			}
		}
	}

	return &DkgOutput{
		PublicKey:       groupKey,
		PublicKeyShares: pkShares,
		SecretShare:     secretShare,
		DerivedOutputs:  derivedOutputs,
	}, nil
}
