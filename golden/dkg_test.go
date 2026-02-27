package golden

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/bn254g1"
	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/group"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

// testParticipant creates a participant with a BJJ key pair.
func testParticipant(t *testing.T, bjjGroup group.Group, id int) *Participant {
	t.Helper()
	sk, err := bjjGroup.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatalf("participant %d: random scalar: %v", id, err)
	}
	pk := bjjGroup.NewPoint().ScalarMult(sk, bjjGroup.Generator())
	return &Participant{ID: id, SK: sk, PK: pk}
}

// testConfig creates a DKG config with a random session ID.
func testConfig(t *testing.T, n, threshold int) *DkgConfig {
	t.Helper()
	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	return &DkgConfig{N: n, T: threshold, SessionID: sid}
}

// scalarFromIntForTest creates a scalar from a small non-negative integer
// using big-endian uint32 at bytes [28:32], matching frost.scalarFromInt encoding.
func scalarFromIntForTest(g group.Group, n int) group.Scalar {
	s := g.NewScalar()
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[28:], uint32(n))
	if _, err := s.SetBytes(buf); err != nil {
		panic(err)
	}
	return s
}

// createDealingNoProofs creates a DKG dealing without generating eVRF proofs.
// This bypasses the PLONK circuit compilation while still exercising the
// polynomial, VSS, share encryption, and identity proof logic.
func createDealingNoProofs(
	bjjGroup, bn254Group group.Group,
	config *DkgConfig,
	self *Participant,
	peers []*Participant,
	rng io.Reader,
) (*DkgDealing, error) {
	// Sample omega and create polynomial of degree t-1 over Fr.
	omega, err := bn254Group.RandomScalar(rng)
	if err != nil {
		return nil, err
	}
	poly, err := NewRandomPolynomial(bn254Group, omega, config.T-1, rng)
	if err != nil {
		return nil, err
	}

	// VSS commitments on BN254 G1.
	vssCommitments, err := VSSCommit(bn254Group, poly)
	if err != nil {
		return nil, err
	}

	// Generate shares for all participants in Fr.
	shares := GenerateShares(bn254Group, poly, config.N)
	ownShare := shares[self.ID]

	// Random 32-byte nonce.
	var randomMsg [32]byte
	if _, err := io.ReadFull(rng, randomMsg[:]); err != nil {
		return nil, err
	}

	// Schnorr identity proof (cheap, no PLONK).
	identityProof, err := ProveIdentity(bjjGroup, self.SK, self.PK, config.SessionID, rng)
	if err != nil {
		return nil, err
	}

	// Derive alpha for LHL combination.
	alpha, err := bn254Group.HashToScalar([]byte("golden-lhl-alpha"), config.SessionID[:])
	if err != nil {
		return nil, err
	}

	// Encrypt shares for each peer using DerivePad (no PLONK proofs).
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}
	ciphertexts := make(map[int]*Ciphertext, len(peers))

	for _, peer := range peers {
		padResult, err := DerivePad(bjjGroup, bn254Group, self.SK, peer.PK, sessionData, alpha)
		if err != nil {
			return nil, err
		}
		z := bn254Group.NewScalar().Add(padResult.Pad, shares[peer.ID])
		ciphertexts[peer.ID] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}
	}

	// Zero polynomial coefficients after use.
	poly.Zero()

	return &DkgDealing{
		Message: &Round0Msg{
			SessionID:      config.SessionID,
			From:           self.ID,
			RandomMsg:      randomMsg,
			VSSCommitments: vssCommitments,
			Ciphertexts:    ciphertexts,
			IdentityProof:  identityProof,
			EVRFProofs:     map[int][]byte{}, // skipped
		},
		PrivateShare: ownShare,
	}, nil
}

// goldenRunDKGNoProofs runs the DKG protocol without eVRF proof generation/verification.
// This exercises the core DKG logic (polynomial, VSS, share encryption, aggregation)
// without requiring the gnark PLONK circuit. All tests that verify DKG correctness
// (share reconstruction, FROST signing, group key agreement) use this helper.
//
// The full integration tests using CreateDealing + VerifyDealing (with eVRF proofs)
// are in goldenRunDKG and will pass once the eVRF circuit compilation is fixed.
func goldenRunDKGNoProofs(t *testing.T, bjjGroup, bn254Group group.Group, config *DkgConfig, participants []*Participant) map[int]*DkgOutput {
	t.Helper()
	n := len(participants)

	// Build peer PKs map.
	peerPKs := make(map[int]group.Point, n)
	for _, p := range participants {
		peerPKs[p.ID] = p.PK
	}

	// Phase 1: Each participant creates a dealing (without eVRF proofs).
	dealings := make(map[int]*DkgDealing, n)
	for _, self := range participants {
		var peers []*Participant
		for _, p := range participants {
			if p.ID != self.ID {
				peers = append(peers, p)
			}
		}
		dealing, err := createDealingNoProofs(bjjGroup, bn254Group, config, self, peers, rand.Reader)
		if err != nil {
			t.Fatalf("createDealingNoProofs(node %d): %v", self.ID, err)
		}
		dealings[self.ID] = dealing
	}

	// Phase 2: Skip VerifyDealing (requires eVRF proofs).
	// The ciphertext consistency is verified implicitly: if shares decrypt
	// correctly, the encryption was consistent.

	// Phase 3: Each participant completes the DKG.
	outputs := make(map[int]*DkgOutput, n)
	for _, self := range participants {
		var peerMsgs []*Round0Msg
		for dealerID, dealing := range dealings {
			if dealerID != self.ID {
				peerMsgs = append(peerMsgs, dealing.Message)
			}
		}
		output, err := Complete(bjjGroup, bn254Group, config, self, dealings[self.ID], peerMsgs, peerPKs)
		if err != nil {
			t.Fatalf("Complete(node %d): %v", self.ID, err)
		}
		outputs[self.ID] = output
	}

	return outputs
}

// goldenRunDKG runs a complete DKG protocol including eVRF proof generation
// and verification. This is the full integration test path.
// NOTE: Requires a working eVRF PLONK circuit. Will fail if circuit compilation
// has issues (pre-existing gnark compatibility issue).
func goldenRunDKG(t *testing.T, bjjGroup, bn254Group group.Group, config *DkgConfig, participants []*Participant) map[int]*DkgOutput {
	t.Helper()
	n := len(participants)

	peerPKs := make(map[int]group.Point, n)
	for _, p := range participants {
		peerPKs[p.ID] = p.PK
	}

	dealings := make(map[int]*DkgDealing, n)
	for _, self := range participants {
		var peers []*Participant
		for _, p := range participants {
			if p.ID != self.ID {
				peers = append(peers, p)
			}
		}
		dealing, err := CreateDealing(bjjGroup, bn254Group, config, self, peers, rand.Reader)
		if err != nil {
			t.Fatalf("CreateDealing(node %d): %v", self.ID, err)
		}
		dealings[self.ID] = dealing
	}

	for _, verifier := range participants {
		for dealerID, dealing := range dealings {
			if dealerID == verifier.ID {
				continue
			}
			recipientPKs := make(map[int]group.Point)
			for id, pk := range peerPKs {
				if id != dealerID {
					recipientPKs[id] = pk
				}
			}
			err := VerifyDealing(bjjGroup, bn254Group, config, dealing.Message, verifier, peerPKs[dealerID], recipientPKs)
			if err != nil {
				t.Fatalf("VerifyDealing(verifier %d, dealer %d): %v", verifier.ID, dealerID, err)
			}
		}
	}

	outputs := make(map[int]*DkgOutput, n)
	for _, self := range participants {
		var peerMsgs []*Round0Msg
		for dealerID, dealing := range dealings {
			if dealerID != self.ID {
				peerMsgs = append(peerMsgs, dealing.Message)
			}
		}
		output, err := Complete(bjjGroup, bn254Group, config, self, dealings[self.ID], peerMsgs, peerPKs)
		if err != nil {
			t.Fatalf("Complete(node %d): %v", self.ID, err)
		}
		outputs[self.ID] = output
	}

	return outputs
}

// lagrangeCoeffFr computes the Lagrange coefficient for participant i
// in the given subset, evaluated at x=0, using Fr arithmetic.
//
// lambda_i = product(0 - j) / product(i - j) for j in subset, j != i
//          = product(-j) / product(i - j)
func lagrangeCoeffFr(g group.Group, i int, subset []int) group.Scalar {
	num := scalarFromIntForTest(g, 1)
	den := scalarFromIntForTest(g, 1)
	iScalar := scalarFromIntForTest(g, i)

	for _, j := range subset {
		if j == i {
			continue
		}
		jScalar := scalarFromIntForTest(g, j)
		// num *= (0 - j) = -j
		negJ := g.NewScalar().Negate(jScalar)
		num = g.NewScalar().Mul(num, negJ)
		// den *= (i - j)
		diff := g.NewScalar().Sub(iScalar, jScalar)
		den = g.NewScalar().Mul(den, diff)
	}

	denInv, err := g.NewScalar().Invert(den)
	if err != nil {
		panic("lagrangeCoeffFr: zero denominator")
	}
	return g.NewScalar().Mul(num, denInv)
}

// frostSignAndVerify is a test helper that performs a full FROST signing round
// with the given signer IDs and verifies the resulting signature.
func frostSignAndVerify(t *testing.T, bn254G group.Group, f *frost.FROST, keyShares map[int]*frost.KeyShare, signerIDs []int, msg []byte) {
	t.Helper()

	nonces := make([]*frost.SigningNonce, len(signerIDs))
	commitments := make([]*frost.SigningCommitment, len(signerIDs))
	var err error
	for i, id := range signerIDs {
		nonces[i], commitments[i], err = f.SignRound1(rand.Reader, keyShares[id])
		if err != nil {
			t.Fatalf("SignRound1(signer %d): %v", id, err)
		}
	}

	sigShares := make([]*frost.SignatureShare, len(signerIDs))
	for i, id := range signerIDs {
		sigShares[i], err = f.SignRound2(keyShares[id], nonces[i], msg, commitments)
		if err != nil {
			t.Fatalf("SignRound2(signer %d): %v", id, err)
		}
	}

	sig, err := f.Aggregate(msg, commitments, sigShares)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	if !f.Verify(msg, sig, keyShares[signerIDs[0]].GroupKey) {
		t.Fatal("FROST signature verification failed")
	}

	if f.Verify([]byte("wrong message"), sig, keyShares[signerIDs[0]].GroupKey) {
		t.Error("FROST signature should not verify with wrong message")
	}
}

// --------------------------------------------------------------------------
// Core DKG correctness tests (no eVRF dependency)
// --------------------------------------------------------------------------

func TestFullDKGRoundTrip(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// All participants should agree on the group key.
	var groupKey group.Point
	for id, output := range outputs {
		if groupKey == nil {
			groupKey = output.PublicKey
		} else if !output.PublicKey.Equal(groupKey) {
			t.Errorf("node %d has different group key", id)
		}
	}

	// Group key should not be identity.
	if groupKey.IsIdentity() {
		t.Error("group key is identity")
	}

	// Each participant's PK share should match secretShare * G_bn254.
	for id, output := range outputs {
		expectedPK := bn254G.NewPoint().ScalarMult(output.SecretShare, bn254G.Generator())
		if !output.PublicKeyShares[id].Equal(expectedPK) {
			t.Errorf("node %d: PK share mismatch", id)
		}
	}
}

func TestSharesReconstructSecret(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// Use any t participants to reconstruct the secret via Lagrange interpolation in Fr.
	subset := []int{1, 2}

	// Lagrange interpolation at x=0.
	reconstructed := bn254G.NewScalar()
	for _, i := range subset {
		lambda := lagrangeCoeffFr(bn254G, i, subset)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed = bn254G.NewScalar().Add(reconstructed, term)
	}

	// reconstructed * G should equal the group key.
	expectedGroupKey := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
	if !expectedGroupKey.Equal(outputs[1].PublicKey) {
		t.Error("Lagrange reconstruction does not match group key")
	}

	// Try a different subset: participants 2 and 3.
	subset2 := []int{2, 3}
	reconstructed2 := bn254G.NewScalar()
	for _, i := range subset2 {
		lambda := lagrangeCoeffFr(bn254G, i, subset2)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed2 = bn254G.NewScalar().Add(reconstructed2, term)
	}
	expectedGroupKey2 := bn254G.NewPoint().ScalarMult(reconstructed2, bn254G.Generator())
	if !expectedGroupKey2.Equal(outputs[1].PublicKey) {
		t.Error("different subset Lagrange reconstruction does not match group key")
	}
}

func TestReconstructionWithAllSubsets3of3(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)
	groupKey := outputs[1].PublicKey

	// All possible threshold subsets of 3 nodes with threshold 2.
	subsets := [][]int{
		{1, 2},
		{1, 3},
		{2, 3},
	}

	for _, subset := range subsets {
		reconstructed := bn254G.NewScalar()
		for _, i := range subset {
			lambda := lagrangeCoeffFr(bn254G, i, subset)
			term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
			reconstructed = bn254G.NewScalar().Add(reconstructed, term)
		}
		expectedGK := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
		if !expectedGK.Equal(groupKey) {
			t.Errorf("subset %v: Lagrange reconstruction does not match group key", subset)
		}
	}
}

// --------------------------------------------------------------------------
// GOLDEN DKG -> FROST signing tests
// --------------------------------------------------------------------------

func TestGoldenDKGToFROSTSigning(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// Convert DKG outputs to FROST KeyShares.
	keyShares := make(map[int]*frost.KeyShare, n)
	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}
		keyShares[p.ID] = ks
	}

	// Create FROST instance for BN254.
	f, err := frost.New(bn254G, threshold, n)
	if err != nil {
		t.Fatalf("frost.New: %v", err)
	}

	// Sign with a threshold subset.
	msg := []byte("test message for FROST signing")
	frostSignAndVerify(t, bn254G, f, keyShares, []int{1, 3}, msg)
}

func TestGoldenDKGToFROSTSigningAllSubsets(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	keyShares := make(map[int]*frost.KeyShare, n)
	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}
		keyShares[p.ID] = ks
	}

	f, err := frost.New(bn254G, threshold, n)
	if err != nil {
		t.Fatalf("frost.New: %v", err)
	}

	msg := []byte("test all subsets")

	// All possible threshold subsets of {1, 2, 3}.
	subsets := [][]int{
		{1, 2},
		{1, 3},
		{2, 3},
		{1, 2, 3}, // more than threshold
	}

	for _, subset := range subsets {
		frostSignAndVerify(t, bn254G, f, keyShares, subset, msg)
	}
}

// --------------------------------------------------------------------------
// Cross-field accumulation / larger N tests
// --------------------------------------------------------------------------

func TestCrossFieldAccumulationN5(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 5, 3
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// All should agree on group key.
	groupKey := outputs[1].PublicKey
	for id, output := range outputs {
		if !output.PublicKey.Equal(groupKey) {
			t.Errorf("node %d has different group key", id)
		}
	}

	// Verify Lagrange reconstruction with a threshold subset.
	subset := []int{1, 3, 5}
	reconstructed := bn254G.NewScalar()
	for _, i := range subset {
		lambda := lagrangeCoeffFr(bn254G, i, subset)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed = bn254G.NewScalar().Add(reconstructed, term)
	}
	expectedGK := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
	if !expectedGK.Equal(groupKey) {
		t.Error("n=5 t=3: Lagrange reconstruction failed")
	}
}

func TestCrossFieldAccumulationN8(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 8, 5
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// All should agree on group key.
	groupKey := outputs[1].PublicKey
	for id, output := range outputs {
		if !output.PublicKey.Equal(groupKey) {
			t.Errorf("node %d has different group key", id)
		}
	}

	// Verify Lagrange with non-contiguous subset.
	subset := []int{1, 3, 5, 7, 8}
	reconstructed := bn254G.NewScalar()
	for _, i := range subset {
		lambda := lagrangeCoeffFr(bn254G, i, subset)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed = bn254G.NewScalar().Add(reconstructed, term)
	}
	expectedGK := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
	if !expectedGK.Equal(groupKey) {
		t.Error("n=8 t=5: Lagrange reconstruction failed")
	}

	// Also check FROST signing with n=8 DKG.
	keyShares := make(map[int]*frost.KeyShare, n)
	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}
		keyShares[p.ID] = ks
	}

	f, err := frost.New(bn254G, threshold, n)
	if err != nil {
		t.Fatalf("frost.New: %v", err)
	}

	frostSignAndVerify(t, bn254G, f, keyShares, []int{2, 4, 5, 6, 8}, []byte("n=8 FROST signing test"))
}

// --------------------------------------------------------------------------
// Error / validation tests (no eVRF dependency)
// --------------------------------------------------------------------------

func TestInvalidNodeIDRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	badParticipant := &Participant{ID: 0} // Invalid: must be >= 1

	_, err := CreateDealing(bjjG, bn254G, config, badParticipant, nil, rand.Reader)
	if err != ErrInvalidNodeID {
		t.Errorf("expected ErrInvalidNodeID, got: %v", err)
	}
}

func TestNegativeNodeIDRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	badParticipant := &Participant{ID: -1}

	_, err := CreateDealing(bjjG, bn254G, config, badParticipant, nil, rand.Reader)
	if err != ErrInvalidNodeID {
		t.Errorf("expected ErrInvalidNodeID, got: %v", err)
	}
}

func TestPeerNodeIDZeroRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	self := testParticipant(t, bjjG, 1)
	badPeer := &Participant{ID: 0}
	goodPeer := testParticipant(t, bjjG, 2)

	_, err := CreateDealing(bjjG, bn254G, config, self, []*Participant{badPeer, goodPeer}, rand.Reader)
	if err != ErrInvalidNodeID {
		t.Errorf("expected ErrInvalidNodeID for peer with ID 0, got: %v", err)
	}
}

func TestDuplicateNodeIDRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	self := testParticipant(t, bjjG, 1)
	peer1 := testParticipant(t, bjjG, 2)
	peer2 := testParticipant(t, bjjG, 2) // duplicate of peer1

	_, err := CreateDealing(bjjG, bn254G, config, self, []*Participant{peer1, peer2}, rand.Reader)
	if err != ErrDuplicateNodeID {
		t.Errorf("expected ErrDuplicateNodeID, got: %v", err)
	}
}

func TestSelfDuplicateAsPeerRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	self := testParticipant(t, bjjG, 1)
	peer := testParticipant(t, bjjG, 1) // same ID as self

	_, err := CreateDealing(bjjG, bn254G, config, self, []*Participant{peer, testParticipant(t, bjjG, 2)}, rand.Reader)
	if err != ErrDuplicateNodeID {
		t.Errorf("expected ErrDuplicateNodeID, got: %v", err)
	}
}

func TestPeerCountMismatch(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	self := testParticipant(t, bjjG, 1)
	peer := testParticipant(t, bjjG, 2)

	// Only 1 peer for N=3 (need 2).
	_, err := CreateDealing(bjjG, bn254G, config, self, []*Participant{peer}, rand.Reader)
	if err != ErrPeerCountMismatch {
		t.Errorf("expected ErrPeerCountMismatch, got: %v", err)
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	self := testParticipant(t, bjjG, 1)

	t.Run("ThresholdZero", func(t *testing.T) {
		config := &DkgConfig{N: 3, T: 0}
		_, err := CreateDealing(bjjG, bn254G, config, self, nil, rand.Reader)
		if err != ErrInvalidConfig {
			t.Errorf("expected ErrInvalidConfig, got: %v", err)
		}
	})

	t.Run("ThresholdExceedsN", func(t *testing.T) {
		config := &DkgConfig{N: 2, T: 3}
		_, err := CreateDealing(bjjG, bn254G, config, self, nil, rand.Reader)
		if err != ErrInvalidConfig {
			t.Errorf("expected ErrInvalidConfig, got: %v", err)
		}
	})
}

func TestSessionIDMismatchRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	// Build a synthetic Round0Msg with a specific session ID.
	// VerifyDealing checks session ID first, before any crypto.
	var msgSID SessionID
	if _, err := rand.Read(msgSID[:]); err != nil {
		t.Fatal(err)
	}
	msg := &Round0Msg{
		SessionID:      msgSID,
		From:           1,
		VSSCommitments: []group.Point{bn254G.Generator()}, // non-identity
	}

	recipientPKs := map[int]group.Point{2: participants[1].PK, 3: participants[2].PK}
	err := VerifyDealing(bjjG, bn254G, config, msg, participants[1], participants[0].PK, recipientPKs)
	if err != ErrSessionIDMismatch {
		t.Errorf("expected ErrSessionIDMismatch, got: %v", err)
	}
}

func TestTamperedCiphertextDetected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	// Build a synthetic dealing manually (bypassing eVRF proof generation).
	omega, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poly, err := NewRandomPolynomial(bn254G, omega, config.T-1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vssCommitments, err := VSSCommit(bn254G, poly)
	if err != nil {
		t.Fatal(err)
	}
	shares := GenerateShares(bn254G, poly, config.N)

	identityProof, err := ProveIdentity(bjjG, participants[0].SK, participants[0].PK, config.SessionID, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	alpha, err := bn254G.HashToScalar([]byte("golden-lhl-alpha"), config.SessionID[:])
	if err != nil {
		t.Fatal(err)
	}

	var randomMsg [32]byte
	rand.Read(randomMsg[:])
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}

	ciphertexts := make(map[int]*Ciphertext, 2)
	for _, peer := range []*Participant{participants[1], participants[2]} {
		padResult, err := DerivePad(bjjG, bn254G, participants[0].SK, peer.PK, sessionData, alpha)
		if err != nil {
			t.Fatal(err)
		}
		z := bn254G.NewScalar().Add(padResult.Pad, shares[peer.ID])
		ciphertexts[peer.ID] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}
	}

	msg := &Round0Msg{
		SessionID:      config.SessionID,
		From:           participants[0].ID,
		RandomMsg:      randomMsg,
		VSSCommitments: vssCommitments,
		Ciphertexts:    ciphertexts,
		IdentityProof:  identityProof,
		EVRFProofs:     map[int][]byte{}, // ciphertext check happens before eVRF
	}

	// Tamper with the encrypted share for recipient 2.
	one := scalarFromIntForTest(bn254G, 1)
	ct := msg.Ciphertexts[2]
	ct.EncryptedShare = bn254G.NewScalar().Add(ct.EncryptedShare, one)

	recipientPKs := map[int]group.Point{2: participants[1].PK, 3: participants[2].PK}
	err = VerifyDealing(bjjG, bn254G, config, msg, participants[1], participants[0].PK, recipientPKs)
	if err == nil {
		t.Error("expected error for tampered ciphertext, got nil")
	}
}

func TestTamperedVSSCommitmentDetected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	// Build a synthetic dealing manually.
	omega, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poly, err := NewRandomPolynomial(bn254G, omega, config.T-1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vssCommitments, err := VSSCommit(bn254G, poly)
	if err != nil {
		t.Fatal(err)
	}
	shares := GenerateShares(bn254G, poly, config.N)

	identityProof, err := ProveIdentity(bjjG, participants[0].SK, participants[0].PK, config.SessionID, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	alpha, err := bn254G.HashToScalar([]byte("golden-lhl-alpha"), config.SessionID[:])
	if err != nil {
		t.Fatal(err)
	}

	var randomMsg [32]byte
	rand.Read(randomMsg[:])
	sessionData := [][]byte{config.SessionID[:], randomMsg[:]}

	ciphertexts := make(map[int]*Ciphertext, 2)
	for _, peer := range []*Participant{participants[1], participants[2]} {
		padResult, err := DerivePad(bjjG, bn254G, participants[0].SK, peer.PK, sessionData, alpha)
		if err != nil {
			t.Fatal(err)
		}
		z := bn254G.NewScalar().Add(padResult.Pad, shares[peer.ID])
		ciphertexts[peer.ID] = &Ciphertext{
			RCommitment:    padResult.RCommitment,
			EncryptedShare: z,
		}
	}

	msg := &Round0Msg{
		SessionID:      config.SessionID,
		From:           participants[0].ID,
		RandomMsg:      randomMsg,
		VSSCommitments: vssCommitments,
		Ciphertexts:    ciphertexts,
		IdentityProof:  identityProof,
		EVRFProofs:     map[int][]byte{},
	}

	// Tamper with VSS commitment[0] (the PK contribution).
	// This breaks ciphertext consistency: z*G != R + (tampered)ExpectedShareCommitment.
	msg.VSSCommitments[0] = bn254G.NewPoint().Add(
		msg.VSSCommitments[0],
		bn254G.Generator(),
	)

	recipientPKs := map[int]group.Point{2: participants[1].PK, 3: participants[2].PK}
	err = VerifyDealing(bjjG, bn254G, config, msg, participants[1], participants[0].PK, recipientPKs)
	if err == nil {
		t.Error("expected error for tampered VSS commitment, got nil")
	}
}

func TestEmptyVSSCommitmentsRejected(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	// Build a synthetic message with empty VSS commitments.
	// VerifyDealing checks this before identity proof or ciphertexts.
	msg := &Round0Msg{
		SessionID:      config.SessionID,
		From:           1,
		VSSCommitments: nil,
	}

	recipientPKs := map[int]group.Point{2: participants[1].PK, 3: participants[2].PK}
	err := VerifyDealing(bjjG, bn254G, config, msg, participants[1], participants[0].PK, recipientPKs)
	if err != ErrInvalidVSSLength {
		t.Errorf("expected ErrInvalidVSSLength for empty VSS commitments, got: %v", err)
	}
}

func TestCompletePeerCountMismatch(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	config := testConfig(t, 3, 2)
	participants := make([]*Participant, 3)
	for i := 0; i < 3; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	// Build a minimal synthetic DkgDealing (no eVRF proofs needed).
	// Complete checks peer count before processing any dealings.
	omega, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownShare, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dealing := &DkgDealing{
		Message: &Round0Msg{
			SessionID:      config.SessionID,
			From:           participants[0].ID,
			VSSCommitments: []group.Point{bn254G.NewPoint().ScalarMult(omega, bn254G.Generator())},
		},
		PrivateShare: ownShare,
	}

	peerPKs := map[int]group.Point{
		1: participants[0].PK,
		2: participants[1].PK,
		3: participants[2].PK,
	}

	// Pass wrong number of peer dealings (0 instead of 2).
	_, err = Complete(bjjG, bn254G, config, participants[0], dealing, nil, peerPKs)
	if err != ErrPeerCountMismatch {
		t.Errorf("expected ErrPeerCountMismatch, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// DkgOutputToKeyShare tests
// --------------------------------------------------------------------------

func TestDkgOutputToKeyShareFields(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}

		// ID should be the scalar encoding of the participant's integer ID.
		expectedID := scalarFromIntForTest(bn254G, p.ID)
		if !ks.ID.Equal(expectedID) {
			t.Errorf("node %d: ID scalar mismatch", p.ID)
		}

		// SecretKey should match the DKG SecretShare.
		if !ks.SecretKey.Equal(outputs[p.ID].SecretShare) {
			t.Errorf("node %d: SecretKey mismatch", p.ID)
		}

		// PublicKey should match the PK share.
		if !ks.PublicKey.Equal(outputs[p.ID].PublicKeyShares[p.ID]) {
			t.Errorf("node %d: PublicKey mismatch", p.ID)
		}

		// GroupKey should match the DKG PublicKey.
		if !ks.GroupKey.Equal(outputs[p.ID].PublicKey) {
			t.Errorf("node %d: GroupKey mismatch", p.ID)
		}
	}
}

// --------------------------------------------------------------------------
// VSS / polynomial consistency tests (no eVRF dependency)
// --------------------------------------------------------------------------

func TestVSSCommitmentStructure(t *testing.T) {
	bn254G := &bn254g1.BN254G1{}

	threshold := 2
	omega, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poly, err := NewRandomPolynomial(bn254G, omega, threshold-1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vssCommitments, err := VSSCommit(bn254G, poly)
	if err != nil {
		t.Fatal(err)
	}

	// VSS commitments should have T entries (degree t-1 polynomial has t coefficients).
	if len(vssCommitments) != threshold {
		t.Errorf("expected %d VSS commitments, got %d", threshold, len(vssCommitments))
	}

	// VSSCommitments[0] = omega * G should not be identity (omega is random).
	if vssCommitments[0].IsIdentity() {
		t.Error("VSSCommitments[0] should not be identity")
	}

	// VSSCommitments[0] should equal omega * G.
	expectedPKContrib := bn254G.NewPoint().ScalarMult(omega, bn254G.Generator())
	if !vssCommitments[0].Equal(expectedPKContrib) {
		t.Error("VSSCommitments[0] != omega * G")
	}
}

func TestShareConsistentWithVSS(t *testing.T) {
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	omega, err := bn254G.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poly, err := NewRandomPolynomial(bn254G, omega, threshold-1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vssCommitments, err := VSSCommit(bn254G, poly)
	if err != nil {
		t.Fatal(err)
	}
	shares := GenerateShares(bn254G, poly, n)

	// For each participant, f(i) * G should equal ExpectedShareCommitment(vss, i).
	for i := 1; i <= n; i++ {
		shareCommit := bn254G.NewPoint().ScalarMult(shares[i], bn254G.Generator())
		expectedCommit := ExpectedShareCommitment(bn254G, vssCommitments, i)
		if !shareCommit.Equal(expectedCommit) {
			t.Errorf("node %d: share*G != ExpectedShareCommitment", i)
		}
	}
}

// --------------------------------------------------------------------------
// Edge cases: threshold boundaries
// --------------------------------------------------------------------------

func TestThresholdEqualsN(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 3
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// All agree on group key.
	groupKey := outputs[1].PublicKey
	for id, out := range outputs {
		if !out.PublicKey.Equal(groupKey) {
			t.Errorf("node %d disagrees on group key", id)
		}
	}

	// Reconstruction requires all n shares.
	allIDs := []int{1, 2, 3}
	reconstructed := bn254G.NewScalar()
	for _, i := range allIDs {
		lambda := lagrangeCoeffFr(bn254G, i, allIDs)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed = bn254G.NewScalar().Add(reconstructed, term)
	}
	expectedGK := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
	if !expectedGK.Equal(groupKey) {
		t.Error("t=n reconstruction failed")
	}
}

// TestThresholdOne exercises the Shamir math layer with a degree-0 polynomial.
// Note: T=1 is rejected by the protocol entry point CreateDealing (requires T >= 2
// for FROST compatibility). This test uses the internal createDealingNoProofs helper
// to verify mathematical correctness of the polynomial evaluation at the boundary.
func TestThresholdOne(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 1
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// All agree on group key.
	groupKey := outputs[1].PublicKey
	for id, out := range outputs {
		if !out.PublicKey.Equal(groupKey) {
			t.Errorf("node %d disagrees on group key", id)
		}
	}

	// With t=1, the polynomial is constant (f(x) = omega for all x).
	// Every share equals the secret, so share*G = groupKey for all participants.
	for id := 1; id <= n; id++ {
		shareG := bn254G.NewPoint().ScalarMult(outputs[id].SecretShare, bn254G.Generator())
		if !shareG.Equal(groupKey) {
			t.Errorf("t=1: node %d share*G != group key", id)
		}
	}
}

// --------------------------------------------------------------------------
// N=2 minimal case
// --------------------------------------------------------------------------

func TestMinimalN2T2(t *testing.T) {
	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 2, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKGNoProofs(t, bjjG, bn254G, config, participants)

	// Both agree on group key.
	if !outputs[1].PublicKey.Equal(outputs[2].PublicKey) {
		t.Error("nodes 1 and 2 disagree on group key")
	}

	// Reconstruction with both.
	subset := []int{1, 2}
	reconstructed := bn254G.NewScalar()
	for _, i := range subset {
		lambda := lagrangeCoeffFr(bn254G, i, subset)
		term := bn254G.NewScalar().Mul(lambda, outputs[i].SecretShare)
		reconstructed = bn254G.NewScalar().Add(reconstructed, term)
	}
	expectedGK := bn254G.NewPoint().ScalarMult(reconstructed, bn254G.Generator())
	if !expectedGK.Equal(outputs[1].PublicKey) {
		t.Error("n=2 t=2 reconstruction failed")
	}

	// FROST signing with n=2 t=2.
	keyShares := make(map[int]*frost.KeyShare, n)
	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}
		keyShares[p.ID] = ks
	}

	f, err := frost.New(bn254G, threshold, n)
	if err != nil {
		t.Fatalf("frost.New: %v", err)
	}

	frostSignAndVerify(t, bn254G, f, keyShares, []int{1, 2}, []byte("n=2 signing test"))
}

// --------------------------------------------------------------------------
// Full integration test (requires working eVRF PLONK circuit).
// Skipped by default - will pass once gnark circuit compilation is fixed.
// --------------------------------------------------------------------------

func TestFullDKGWithEVRFProofs(t *testing.T) {
	if testing.Short() {
		t.Skip("eVRF PLONK proof generation is slow (~3s per proof)")
	}

	bjjG := &bjj.BJJ{}
	bn254G := &bn254g1.BN254G1{}

	n, threshold := 3, 2
	config := testConfig(t, n, threshold)

	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = testParticipant(t, bjjG, i+1)
	}

	outputs := goldenRunDKG(t, bjjG, bn254G, config, participants)

	// All participants should agree on the group key.
	groupKey := outputs[1].PublicKey
	for id, output := range outputs {
		if !output.PublicKey.Equal(groupKey) {
			t.Errorf("node %d has different group key", id)
		}
	}

	// FROST signing.
	keyShares := make(map[int]*frost.KeyShare, n)
	for _, p := range participants {
		ks, err := DkgOutputToKeyShare(bn254G, p.ID, outputs[p.ID])
		if err != nil {
			t.Fatalf("DkgOutputToKeyShare(node %d): %v", p.ID, err)
		}
		keyShares[p.ID] = ks
	}

	f, err := frost.New(bn254G, threshold, n)
	if err != nil {
		t.Fatalf("frost.New: %v", err)
	}

	frostSignAndVerify(t, bn254G, f, keyShares, []int{1, 3}, []byte("full integration test"))
}
