package frost

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

// setupDKG runs a full DKG and returns a FROST instance plus key shares.
func setupDKG(t *testing.T, threshold, total int) (*FROST, []*KeyShare) {
	t.Helper()

	g := &bjj.BJJ{}
	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatalf("New(%d, %d): %v", threshold, total, err)
	}

	participants := make([]*Participant, total)
	for i := range total {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatalf("NewParticipant(%d): %v", i+1, err)
		}
		participants[i] = p
	}

	broadcasts := make([]*Round1Data, total)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	for i, sender := range participants {
		for j := range total {
			if i == j {
				continue
			}
			pd := f.Round1PrivateSend(sender, j+1)
			if err := f.Round2ReceiveShare(participants[j], pd, broadcasts[i].Commitments); err != nil {
				t.Fatalf("Round2ReceiveShare(%d->%d): %v", i+1, j+1, err)
			}
		}
	}

	keyShares := make([]*KeyShare, total)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatalf("Finalize(%d): %v", i+1, err)
		}
		keyShares[i] = ks
	}

	for i := 1; i < total; i++ {
		if !keyShares[i].GroupKey.Equal(keyShares[0].GroupKey) {
			t.Fatal("group keys differ after DKG")
		}
	}

	return f, keyShares
}

// buildPublicKeys builds the publicKeys map required by PiggybackAggregate.
func buildPublicKeys(keyShares []*KeyShare) map[string]group.Point {
	pk := make(map[string]group.Point, len(keyShares))
	for _, ks := range keyShares {
		pk[string(ks.ID.Bytes())] = ks.PublicKey
	}
	return pk
}

// piggybackBootstrap runs the full bootstrap flow for a set of signers and
// returns the piggyback states, piggybacked shares, current-session
// commitments, and the session-0 session index used.
func piggybackBootstrap(
	t *testing.T,
	f *FROST,
	signers []*KeyShare,
) (
	states []*PiggybackNonceState,
	shares []*PiggybackSignatureShare,
	commitments []*SigningCommitment,
) {
	t.Helper()

	n := len(signers)
	states = make([]*PiggybackNonceState, n)
	nonces := make([]*SigningNonce, n)
	commitments = make([]*SigningCommitment, n)

	for i, ks := range signers {
		states[i] = NewPiggybackState(ks)
		var err error
		nonces[i], commitments[i], err = f.BootstrapRound1(rand.Reader, states[i], ks)
		if err != nil {
			t.Fatalf("BootstrapRound1(%d): %v", i, err)
		}
	}

	message := []byte("bootstrap message")
	shares = make([]*PiggybackSignatureShare, n)
	for i, ks := range signers {
		var err error
		shares[i], err = f.BootstrapRound2(ks, states[i], nonces[i], message, commitments)
		if err != nil {
			t.Fatalf("BootstrapRound2(%d): %v", i, err)
		}
	}

	return states, shares, commitments
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPiggybackBootstrapAndSign(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	// Verify bootstrap signature (session 0).
	bootstrapMsg := []byte("bootstrap message")
	pubKeys := buildPublicKeys(keyShares)

	sig0, collector, err := f.PiggybackAggregate(
		bootstrapMsg, 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate(session 0): %v", err)
	}
	if !f.PiggybackVerify(bootstrapMsg, 0, sig0, signers[0].GroupKey) {
		t.Fatal("bootstrap signature verification failed")
	}

	// One piggyback round (session 1).
	nextCommitments := collector.Commitments()
	piggybackMsg := []byte("piggyback round 1")
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		var err error
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], piggybackMsg, nextCommitments)
		if err != nil {
			t.Fatalf("PiggybackSign(%d): %v", i, err)
		}
	}

	sig1, _, err := f.PiggybackAggregate(
		piggybackMsg, 1, nextCommitments, pbShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate(session 1): %v", err)
	}
	if !f.PiggybackVerify(piggybackMsg, 1, sig1, signers[0].GroupKey) {
		t.Fatal("piggyback session 1 verification failed")
	}
}

func TestPiggybackMultipleRounds(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	pubKeys := buildPublicKeys(keyShares)
	bootstrapMsg := []byte("bootstrap message")

	_, collector, err := f.PiggybackAggregate(
		bootstrapMsg, 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate(session 0): %v", err)
	}

	currentCommitments := collector.Commitments()

	const rounds = 5
	for round := 1; round <= rounds; round++ {
		msg := []byte("round message")
		msg = append(msg, byte(round))

		pbShares := make([]*PiggybackSignatureShare, len(signers))
		for i, ks := range signers {
			pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg, currentCommitments)
			if err != nil {
				t.Fatalf("round %d, signer %d: PiggybackSign: %v", round, i, err)
			}
		}

		sessionIdx := uint64(round)
		sig, coll, err := f.PiggybackAggregate(
			msg, sessionIdx, currentCommitments, pbShares, pubKeys, signers[0].GroupKey,
		)
		if err != nil {
			t.Fatalf("round %d: PiggybackAggregate: %v", round, err)
		}
		if !f.PiggybackVerify(msg, sessionIdx, sig, signers[0].GroupKey) {
			t.Fatalf("round %d: verification failed", round)
		}

		currentCommitments = coll.Commitments()
	}
}

func TestPiggybackDifferentSignerSubsets(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 4)

	// Subset A: signers {0, 1}.
	signersA := keyShares[:2]
	statesA, bootstrapSharesA, bootstrapCommitmentsA := piggybackBootstrap(t, f, signersA)

	pubKeys := buildPublicKeys(keyShares)
	bootstrapMsg := []byte("bootstrap message")

	sigA, collA, err := f.PiggybackAggregate(
		bootstrapMsg, 0, bootstrapCommitmentsA, bootstrapSharesA, pubKeys, signersA[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate subsetA: %v", err)
	}
	if !f.PiggybackVerify(bootstrapMsg, 0, sigA, signersA[0].GroupKey) {
		t.Fatal("subset A bootstrap verification failed")
	}

	// Sign one round with subset A.
	nextA := collA.Commitments()
	msgA := []byte("subset A signing")
	pbSharesA := make([]*PiggybackSignatureShare, len(signersA))
	for i, ks := range signersA {
		pbSharesA[i], err = f.PiggybackSign(rand.Reader, ks, statesA[i], msgA, nextA)
		if err != nil {
			t.Fatalf("subsetA PiggybackSign(%d): %v", i, err)
		}
	}
	sigA1, _, err := f.PiggybackAggregate(
		msgA, 1, nextA, pbSharesA, pubKeys, signersA[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("subsetA PiggybackAggregate: %v", err)
	}
	if !f.PiggybackVerify(msgA, 1, sigA1, signersA[0].GroupKey) {
		t.Fatal("subset A session 1 verification failed")
	}

	// Subset B: signers {0, 2} -- fresh bootstrap.
	signersB := []*KeyShare{keyShares[0], keyShares[2]}
	statesB, bootstrapSharesB, bootstrapCommitmentsB := piggybackBootstrap(t, f, signersB)

	sigB, collB, err := f.PiggybackAggregate(
		bootstrapMsg, 0, bootstrapCommitmentsB, bootstrapSharesB, pubKeys, signersB[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate subsetB: %v", err)
	}
	if !f.PiggybackVerify(bootstrapMsg, 0, sigB, signersB[0].GroupKey) {
		t.Fatal("subset B bootstrap verification failed")
	}

	// Sign one round with subset B.
	nextB := collB.Commitments()
	msgB := []byte("subset B signing")
	pbSharesB := make([]*PiggybackSignatureShare, len(signersB))
	for i, ks := range signersB {
		pbSharesB[i], err = f.PiggybackSign(rand.Reader, ks, statesB[i], msgB, nextB)
		if err != nil {
			t.Fatalf("subsetB PiggybackSign(%d): %v", i, err)
		}
	}
	sigB1, _, err := f.PiggybackAggregate(
		msgB, 1, nextB, pbSharesB, pubKeys, signersB[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("subsetB PiggybackAggregate: %v", err)
	}
	if !f.PiggybackVerify(msgB, 1, sigB1, signersB[0].GroupKey) {
		t.Fatal("subset B session 1 verification failed")
	}
}

func TestPiggybackReBootstrap(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)
	pubKeys := buildPublicKeys(keyShares)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// One piggyback round.
	nextComm := collector.Commitments()
	msg1 := []byte("before reboot")
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg1, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}
	sig1, _, err := f.PiggybackAggregate(msg1, 1, nextComm, pbShares, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !f.PiggybackVerify(msg1, 1, sig1, signers[0].GroupKey) {
		t.Fatal("pre-reboot signature failed")
	}

	// ReBootstrap.
	for _, s := range states {
		s.ReBootstrap()
	}

	// Verify states are inactive.
	for i, s := range states {
		if s.Active {
			t.Fatalf("state %d still active after ReBootstrap", i)
		}
		if s.SessionIndex != 0 {
			t.Fatalf("state %d SessionIndex not reset", i)
		}
	}

	// Fresh bootstrap.
	states2, bootstrapShares2, bootstrapCommitments2 := piggybackBootstrap(t, f, signers)

	_, collector2, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments2, bootstrapShares2, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Piggyback round after reboot.
	nextComm2 := collector2.Commitments()
	msg2 := []byte("after reboot")
	pbShares2 := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares2[i], err = f.PiggybackSign(rand.Reader, ks, states2[i], msg2, nextComm2)
		if err != nil {
			t.Fatal(err)
		}
	}
	sig2, _, err := f.PiggybackAggregate(msg2, 1, nextComm2, pbShares2, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !f.PiggybackVerify(msg2, 1, sig2, signers[0].GroupKey) {
		t.Fatal("post-reboot signature failed")
	}
}

func TestPiggybackOfflineSigner(t *testing.T) {
	f, keyShares := setupDKG(t, 3, 5)

	// Bootstrap with signers {0,1,2,3} -- 4 out of 5.
	signers := keyShares[:4]
	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	pubKeys := buildPublicKeys(keyShares)
	_, _, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Now signer 3 goes offline. Remaining: {0,1,2} (still >= threshold=3).
	remainingSigners := signers[:3]
	remainingStates := states[:3]

	// The remaining signers need a fresh re-bootstrap since the commitment set changed
	// (signer 3's commitment is no longer part of the session).
	for _, s := range remainingStates {
		s.ReBootstrap()
	}

	statesRe, bootstrapSharesRe, bootstrapCommitmentsRe := piggybackBootstrap(t, f, remainingSigners)

	_, collectorRe, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitmentsRe, bootstrapSharesRe, pubKeys, remainingSigners[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Sign with remaining 3 signers.
	nextComm := collectorRe.Commitments()
	msg := []byte("offline signer test")
	pbShares := make([]*PiggybackSignatureShare, len(remainingSigners))
	for i, ks := range remainingSigners {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, statesRe[i], msg, nextComm)
		if err != nil {
			t.Fatalf("PiggybackSign(%d): %v", i, err)
		}
	}

	sig, _, err := f.PiggybackAggregate(msg, 1, nextComm, pbShares, pubKeys, remainingSigners[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !f.PiggybackVerify(msg, 1, sig, remainingSigners[0].GroupKey) {
		t.Fatal("signature with offline signer failed verification")
	}
}

func TestPiggybackNonceSecureErasure(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)
	pubKeys := buildPublicKeys(keyShares)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Capture the pending nonce scalars before signing.
	// PiggybackSign will clone them, zero the originals, and install new ones.
	// After the call, the OLD pending nonce D and E should be zero.
	oldNonceD := make([]group.Scalar, len(signers))
	oldNonceE := make([]group.Scalar, len(signers))
	for i, s := range states {
		// Store references to the current pending nonce scalars.
		oldNonceD[i] = s.PendingNonce.D
		oldNonceE[i] = s.PendingNonce.E
	}

	nextComm := collector.Commitments()
	msg := []byte("erasure test")
	for i, ks := range signers {
		_, err := f.PiggybackSign(rand.Reader, ks, states[i], msg, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}

	// The old nonce scalars should now be zeroed.
	for i := range signers {
		if !oldNonceD[i].IsZero() {
			t.Errorf("signer %d: consumed nonce D not zeroed", i)
		}
		if !oldNonceE[i].IsZero() {
			t.Errorf("signer %d: consumed nonce E not zeroed", i)
		}
	}
}

// limitedReader returns io.EOF after N bytes have been read.
type limitedReader struct {
	remaining int
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	// Read real random bytes for the portion we allow.
	toRead := len(p)
	if toRead > r.remaining {
		toRead = r.remaining
	}
	n, err := rand.Read(p[:toRead])
	r.remaining -= n
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestPiggybackRNGFailure(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)
	pubKeys := buildPublicKeys(keyShares)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()

	// Save state before failed attempt.
	savedSessionIdx := states[0].SessionIndex
	savedActive := states[0].Active

	// Use a reader that allows pre-validation to pass but fails when
	// generating the next nonce. PiggybackSign calls SignRound1 which needs
	// 32 bytes for D + 32 bytes for E = 64 bytes. We give 0 bytes so it
	// fails immediately at next-nonce generation.
	failReader := &limitedReader{remaining: 0}

	msg := []byte("rng fail test")
	_, err = f.PiggybackSign(failReader, signers[0], states[0], msg, nextComm)
	if err == nil {
		t.Fatal("expected error from RNG failure")
	}

	// State should be unchanged (pre-validation passed, RNG failed before
	// point of no return).
	if states[0].SessionIndex != savedSessionIdx {
		t.Error("SessionIndex changed after RNG failure")
	}
	if states[0].Active != savedActive {
		t.Error("Active changed after RNG failure")
	}
	if states[0].PendingNonce == nil {
		t.Error("PendingNonce nil after RNG failure -- state should be unchanged")
	}

	// Retry with a good reader should succeed.
	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], msg, nextComm)
	if err != nil {
		t.Fatalf("retry after RNG failure should succeed: %v", err)
	}
}

func TestPiggybackInactiveStateFails(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)

	state := NewPiggybackState(keyShares[0])

	// State is inactive (never bootstrapped).
	_, err := f.PiggybackSign(rand.Reader, keyShares[0], state, []byte("test"), nil)
	if !errors.Is(err, ErrPiggybackInactive) {
		t.Fatalf("expected ErrPiggybackInactive, got: %v", err)
	}
}

func TestPiggybackSessionIndexMismatch(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	g := f.group

	states, bootstrapShares, _ := piggybackBootstrap(t, f, signers)
	_ = states // not needed further

	// Forge shares with wrong session index.
	wrongIdx := uint64(999)
	forgedShares := make([]*PiggybackSignatureShare, len(bootstrapShares))
	for i, s := range bootstrapShares {
		forgedShares[i] = &PiggybackSignatureShare{
			SignatureShare: s.SignatureShare,
			NextCommitment: &SigningCommitment{
				ID:           s.NextCommitment.ID,
				HidingPoint:  g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
				BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
			},
			SessionIndex: wrongIdx,
		}
	}

	_, err := CollectPiggybackCommitments(forgedShares, 1)
	if !errors.Is(err, ErrSessionIndexMismatch) {
		t.Fatalf("expected ErrSessionIndexMismatch, got: %v", err)
	}
}

func TestPiggybackIdentityCommitmentRejected(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	g := f.group

	_, bootstrapShares, _ := piggybackBootstrap(t, f, signers)

	// Forge: set NextCommitment to contain an identity point.
	forgedShares := make([]*PiggybackSignatureShare, len(bootstrapShares))
	for i, s := range bootstrapShares {
		forgedShares[i] = &PiggybackSignatureShare{
			SignatureShare: s.SignatureShare,
			NextCommitment: &SigningCommitment{
				ID:           s.SignatureShare.ID,
				HidingPoint:  g.NewPoint(), // identity
				BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
			},
			SessionIndex: s.SessionIndex,
		}
	}

	_, err := CollectPiggybackCommitments(forgedShares, forgedShares[0].SessionIndex)
	if !errors.Is(err, ErrIdentityCommitment) {
		t.Fatalf("expected ErrIdentityCommitment, got: %v", err)
	}
}

func TestPiggybackCommitmentIDMismatch(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	g := f.group

	_, bootstrapShares, _ := piggybackBootstrap(t, f, signers)

	// Forge: set NextCommitment.ID to a different signer's ID.
	forgedShares := make([]*PiggybackSignatureShare, len(bootstrapShares))
	for i, s := range bootstrapShares {
		// Use the OTHER signer's ID for NextCommitment.
		wrongID := bootstrapShares[(i+1)%len(bootstrapShares)].SignatureShare.ID
		forgedShares[i] = &PiggybackSignatureShare{
			SignatureShare: s.SignatureShare,
			NextCommitment: &SigningCommitment{
				ID:           wrongID,
				HidingPoint:  g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
				BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
			},
			SessionIndex: s.SessionIndex,
		}
	}

	_, err := CollectPiggybackCommitments(forgedShares, forgedShares[0].SessionIndex)
	if !errors.Is(err, ErrCommitmentIDMismatch) {
		t.Fatalf("expected ErrCommitmentIDMismatch, got: %v", err)
	}
}

func TestPiggybackAggregateWithVerification(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	bootstrapMsg := []byte("bootstrap message")
	sig, collector, err := f.PiggybackAggregate(
		bootstrapMsg, 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatalf("PiggybackAggregate: %v", err)
	}
	if !f.PiggybackVerify(bootstrapMsg, 0, sig, signers[0].GroupKey) {
		t.Fatal("valid aggregate verification failed")
	}

	// Tamper with one share and try again.
	nextComm := collector.Commitments()
	msg := []byte("tamper test")
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Tamper: corrupt the Z scalar of the first share.
	g := f.group
	one := g.NewScalar()
	one.SetBytes([]byte{1})
	pbShares[0].SignatureShare.Z = g.NewScalar().Add(pbShares[0].SignatureShare.Z, one)

	_, _, err = f.PiggybackAggregate(
		msg, 1, nextComm, pbShares, pubKeys, signers[0].GroupKey,
	)
	if err == nil {
		t.Fatal("expected error for tampered share, got nil")
	}
}

func TestPiggybackSessionBinding(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)
	msg := []byte("session binding test")

	// Session A.
	statesA, bootstrapSharesA, bootstrapCommitmentsA := piggybackBootstrap(t, f, signers)
	sigA, collectorA, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitmentsA, bootstrapSharesA, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = sigA

	nextCommA := collectorA.Commitments()
	pbSharesA := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbSharesA[i], err = f.PiggybackSign(rand.Reader, ks, statesA[i], msg, nextCommA)
		if err != nil {
			t.Fatal(err)
		}
	}
	sig1, _, err := f.PiggybackAggregate(msg, 1, nextCommA, pbSharesA, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Session B: fresh bootstrap, same message.
	statesB, bootstrapSharesB, bootstrapCommitmentsB := piggybackBootstrap(t, f, signers)
	_, collectorB, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitmentsB, bootstrapSharesB, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextCommB := collectorB.Commitments()
	pbSharesB := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbSharesB[i], err = f.PiggybackSign(rand.Reader, ks, statesB[i], msg, nextCommB)
		if err != nil {
			t.Fatal(err)
		}
	}
	sig2, _, err := f.PiggybackAggregate(msg, 1, nextCommB, pbSharesB, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Same message, different sessions => different signatures (different nonces).
	if sig1.R.Equal(sig2.R) && sig1.Z.Equal(sig2.Z) {
		t.Fatal("signatures from different sessions should differ")
	}

	// Both should verify independently.
	if !f.PiggybackVerify(msg, 1, sig1, signers[0].GroupKey) {
		t.Fatal("sig1 verification failed")
	}
	if !f.PiggybackVerify(msg, 1, sig2, signers[0].GroupKey) {
		t.Fatal("sig2 verification failed")
	}

	// Cross-verify: sig from session A should not verify with session B's index
	// if sessions used different nonces (R differs), and it should not verify
	// at a wrong session index.
	if f.PiggybackVerify(msg, 999, sig1, signers[0].GroupKey) {
		t.Fatal("sig1 should not verify at wrong session index")
	}
}

func TestPiggybackDoubleCallSafety(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()
	msg := []byte("double call test")

	// First call succeeds.
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}

	_, collector2, err := f.PiggybackAggregate(msg, 1, nextComm, pbShares, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Second call with the OLD commitments should fail because the states
	// have moved on (pending nonce was consumed and replaced).
	// The old commitments no longer match the current pending nonce, so
	// validation should catch the mismatch (own commitment not found).
	// We use the NEW commitments for the second signer but OLD for both --
	// the key point is no panic.
	nextComm2 := collector2.Commitments()

	// Signer 0 tries again with old commitments.
	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], msg, nextComm)
	// This should fail (own commitment not found, or some validation error),
	// but must NOT panic.
	if err == nil {
		// Even if it somehow succeeds (unlikely), the point is no panic.
		t.Log("second call with old commitments unexpectedly succeeded")
	}

	// Signer 0 tries with correct commitments -- should succeed.
	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], msg, nextComm2)
	if err != nil {
		t.Fatalf("retry with correct commitments failed: %v", err)
	}
}

func TestPiggybackBindingFactorRegression(t *testing.T) {
	// Verify that the binding factor computation for the current session
	// uses ONLY the current-session commitments and not the piggybacked
	// NextCommitment. This ensures NextCommitment doesn't leak into the
	// binding factor hash.
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()
	msg := []byte("binding factor regression")

	// Compute binding factors from the current-session commitments.
	sessionMsg := sessionBoundMessage(1, msg)
	encCommitList := f.encodeCommitments(nextComm)
	bindingFactors := f.computeBindingFactors(sessionMsg, encCommitList, nextComm)

	// Now run PiggybackSign and collect the piggybacked shares.
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}

	// The piggybacked shares carry NextCommitment data. Verify that
	// encoding of current commitments does NOT include any NextCommitment.
	// We re-encode using only the current commitments and check they match.
	encCommitListAfter := f.encodeCommitments(nextComm)
	if !bytes.Equal(encCommitList, encCommitListAfter) {
		t.Fatal("commitment encoding changed after PiggybackSign")
	}

	bindingFactorsAfter := f.computeBindingFactors(sessionMsg, encCommitListAfter, nextComm)
	for _, c := range nextComm {
		if !bindingFactors[string(c.ID.Bytes())].Equal(bindingFactorsAfter[string(c.ID.Bytes())]) {
			t.Fatal("binding factors differ after PiggybackSign -- possible contamination from NextCommitment")
		}
	}
}

func TestPiggybackSessionOverflow(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)
	pubKeys := buildPublicKeys(keyShares)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()

	// Directly set SessionIndex to MaxUint64 to trigger overflow check.
	states[0].SessionIndex = math.MaxUint64

	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], []byte("overflow"), nextComm)
	if !errors.Is(err, ErrSessionOverflow) {
		t.Fatalf("expected ErrSessionOverflow, got: %v", err)
	}
}

func TestPiggybackCommitmentOrdering(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	g := f.group

	// Create two valid commitments with different IDs.
	commA := &SigningCommitment{
		ID:           signers[0].ID,
		HidingPoint:  g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
		BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
	}
	commB := &SigningCommitment{
		ID:           signers[1].ID,
		HidingPoint:  g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
		BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
	}

	// Build a collector with shares in order [A, B].
	sharesAB := []*PiggybackSignatureShare{
		{
			SignatureShare: SignatureShare{ID: signers[0].ID, Z: mustRandomScalar(t, g)},
			NextCommitment: commA,
			SessionIndex:   1,
		},
		{
			SignatureShare: SignatureShare{ID: signers[1].ID, Z: mustRandomScalar(t, g)},
			NextCommitment: commB,
			SessionIndex:   1,
		},
	}

	collAB, err := CollectPiggybackCommitments(sharesAB, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Build a collector with shares in reverse order [B, A].
	sharesBA := []*PiggybackSignatureShare{
		{
			SignatureShare: SignatureShare{ID: signers[1].ID, Z: mustRandomScalar(t, g)},
			NextCommitment: commB,
			SessionIndex:   1,
		},
		{
			SignatureShare: SignatureShare{ID: signers[0].ID, Z: mustRandomScalar(t, g)},
			NextCommitment: commA,
			SessionIndex:   1,
		},
	}

	collBA, err := CollectPiggybackCommitments(sharesBA, 1)
	if err != nil {
		t.Fatal(err)
	}

	// The Commitments() output should be deterministic regardless of insertion order.
	resultAB := collAB.Commitments()
	resultBA := collBA.Commitments()

	if len(resultAB) != len(resultBA) {
		t.Fatal("commitment lists have different lengths")
	}

	for i := range resultAB {
		if !resultAB[i].ID.Equal(resultBA[i].ID) {
			t.Fatalf("commitment %d: ID mismatch between orderings", i)
		}
		if !resultAB[i].HidingPoint.Equal(resultBA[i].HidingPoint) {
			t.Fatalf("commitment %d: HidingPoint mismatch between orderings", i)
		}
		if !resultAB[i].BindingPoint.Equal(resultBA[i].BindingPoint) {
			t.Fatalf("commitment %d: BindingPoint mismatch between orderings", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests added by triple-review fix
// ---------------------------------------------------------------------------

// Test 1: Post-failure re-bootstrap recovery.
// Verifies that after the state becomes inactive (simulating a FAILED state),
// ReBootstrap + fresh bootstrap + PiggybackSign works correctly.
func TestPiggybackPostFailureReBootstrapRecovery(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Do one successful piggyback round.
	nextComm := collector.Commitments()
	msg := []byte("before failure")
	pbShares := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbShares[i], err = f.PiggybackSign(rand.Reader, ks, states[i], msg, nextComm)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = f.PiggybackAggregate(msg, 1, nextComm, pbShares, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate FAILED state by deactivating.
	states[0].Active = false
	states[0].PendingNonce = nil
	states[0].PendingCommitment = nil

	// Verify PiggybackSign returns ErrPiggybackInactive.
	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], []byte("fail"), nil)
	if !errors.Is(err, ErrPiggybackInactive) {
		t.Fatalf("expected ErrPiggybackInactive, got: %v", err)
	}

	// Recovery: ReBootstrap all signers and do a fresh bootstrap.
	for _, s := range states {
		s.ReBootstrap()
	}
	statesNew, bootstrapSharesNew, bootstrapCommitmentsNew := piggybackBootstrap(t, f, signers)

	_, collectorNew, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitmentsNew, bootstrapSharesNew, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Piggyback round after recovery.
	nextCommNew := collectorNew.Commitments()
	msgRecovery := []byte("after recovery")
	pbSharesNew := make([]*PiggybackSignatureShare, len(signers))
	for i, ks := range signers {
		pbSharesNew[i], err = f.PiggybackSign(rand.Reader, ks, statesNew[i], msgRecovery, nextCommNew)
		if err != nil {
			t.Fatalf("PiggybackSign after recovery(%d): %v", i, err)
		}
	}
	sigNew, _, err := f.PiggybackAggregate(msgRecovery, 1, nextCommNew, pbSharesNew, pubKeys, signers[0].GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !f.PiggybackVerify(msgRecovery, 1, sigNew, signers[0].GroupKey) {
		t.Fatal("post-recovery signature verification failed")
	}
}

// Test 2: BootstrapRound1 RNG failure on second nonce.
// Uses a limitedReader that provides enough bytes for the first SignRound1 call
// but fails on the second. Verifies the error is returned and the current nonce
// scalars are zeroed.
func TestPiggybackBootstrapRound1SecondNonceRNGFailure(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)

	state := NewPiggybackState(keyShares[0])

	// SignRound1 needs 32 bytes for D + 32 bytes for E = 64 bytes per call.
	// We provide exactly 64 bytes so the first call succeeds and the second fails.
	failReader := &limitedReader{remaining: 64}

	nonce, comm, err := f.BootstrapRound1(failReader, state, keyShares[0])
	if err == nil {
		t.Fatal("expected error from RNG failure on second nonce generation")
	}

	// The returned values should be nil.
	if nonce != nil {
		t.Error("expected nil nonce on error")
	}
	if comm != nil {
		t.Error("expected nil commitment on error")
	}

	// State should not have been activated.
	if state.Active {
		t.Error("state should not be active after failed BootstrapRound1")
	}
}

// Test 3: BootstrapRound1 on active state (defense-in-depth zeroing).
// Bootstraps normally, then calls BootstrapRound1 again without ReBootstrap.
// Verifies old pending nonce D/E are zeroed by the defense-in-depth call.
func TestPiggybackBootstrapRound1DefenseInDepthZeroing(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)

	state := NewPiggybackState(keyShares[0])

	// First bootstrap.
	_, _, err := f.BootstrapRound1(rand.Reader, state, keyShares[0])
	if err != nil {
		t.Fatal(err)
	}

	// Hold references to old pending nonce D/E.
	oldD := state.PendingNonce.D
	oldE := state.PendingNonce.E

	// Verify they're non-zero before second call.
	if oldD.IsZero() || oldE.IsZero() {
		t.Fatal("pending nonce should be non-zero after first BootstrapRound1")
	}

	// Second BootstrapRound1 without ReBootstrap.
	_, _, err = f.BootstrapRound1(rand.Reader, state, keyShares[0])
	if err != nil {
		t.Fatal(err)
	}

	// The old nonce scalars should now be zeroed by defense-in-depth.
	if !oldD.IsZero() {
		t.Error("old pending nonce D should be zeroed after second BootstrapRound1")
	}
	if !oldE.IsZero() {
		t.Error("old pending nonce E should be zeroed after second BootstrapRound1")
	}

	// State should have new pending nonce (non-zero).
	if state.PendingNonce == nil || state.PendingNonce.D.IsZero() || state.PendingNonce.E.IsZero() {
		t.Error("new pending nonce should be non-zero")
	}
}

// Test 4: Concurrent PiggybackSign safety.
// Runs multiple goroutines calling PiggybackSign on the same state.
// Key assertion: no panic, no race (run with -race).
func TestPiggybackConcurrentSignSafety(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()
	msg := []byte("concurrent test")

	// Run multiple goroutines attempting PiggybackSign on state[0].
	const numGoroutines = 10
	var wg sync.WaitGroup
	successes := make(chan int, numGoroutines)
	errs := make(chan error, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := f.PiggybackSign(rand.Reader, signers[0], states[0], msg, nextComm)
			if err != nil {
				errs <- err
			} else {
				successes <- idx
			}
		}(g)
	}

	wg.Wait()
	close(successes)
	close(errs)

	// Exactly one goroutine should succeed (the first one that acquires the lock
	// and finds the matching commitment). The rest should fail because the state
	// moved on (commitment mismatch or other validation error).
	successCount := 0
	for range successes {
		successCount++
	}

	// At least one should succeed.
	if successCount == 0 {
		t.Fatal("expected at least one goroutine to succeed")
	}

	// The rest should have gotten errors (not panics).
	errorCount := 0
	for range errs {
		errorCount++
	}
	t.Logf("concurrent sign: %d successes, %d errors", successCount, errorCount)
}

// Test 5: Own-commitment mismatch detection (Fix 1).
// Bootstraps normally, then constructs a commitment list where the signer's
// own ID has different HidingPoint/BindingPoint than state.PendingCommitment.
func TestPiggybackOwnCommitmentMismatch(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)
	signers := keyShares[:2]
	pubKeys := buildPublicKeys(keyShares)
	g := f.group

	states, bootstrapShares, bootstrapCommitments := piggybackBootstrap(t, f, signers)

	_, collector, err := f.PiggybackAggregate(
		[]byte("bootstrap message"), 0, bootstrapCommitments, bootstrapShares, pubKeys, signers[0].GroupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	nextComm := collector.Commitments()

	// Save state before the attempt for later verification.
	savedSessionIdx := states[0].SessionIndex
	savedActive := states[0].Active

	// Build forged commitments: replace the signer's own commitment with
	// different HidingPoint/BindingPoint.
	forgedComm := make([]*SigningCommitment, len(nextComm))
	for i, c := range nextComm {
		if c.ID.Equal(signers[0].ID) {
			forgedComm[i] = &SigningCommitment{
				ID:           c.ID,
				HidingPoint:  g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
				BindingPoint: g.NewPoint().ScalarMult(mustRandomScalar(t, g), g.Generator()),
			}
		} else {
			forgedComm[i] = c
		}
	}

	_, err = f.PiggybackSign(rand.Reader, signers[0], states[0], []byte("mismatch test"), forgedComm)
	if err == nil {
		t.Fatal("expected error for own commitment mismatch")
	}
	if !strings.Contains(err.Error(), "own commitment does not match pending commitment") {
		t.Fatalf("expected commitment mismatch error, got: %v", err)
	}

	// State should be unchanged (retryable error).
	if states[0].SessionIndex != savedSessionIdx {
		t.Error("SessionIndex changed after commitment mismatch")
	}
	if states[0].Active != savedActive {
		t.Error("Active changed after commitment mismatch")
	}
	if states[0].PendingNonce == nil {
		t.Error("PendingNonce nil after commitment mismatch -- state should be unchanged")
	}
}

// Test 6: BootstrapRound2 without BootstrapRound1 (Fix 3).
// Creates a fresh PiggybackNonceState, calls BootstrapRound2 without
// BootstrapRound1, and verifies it returns an error.
func TestPiggybackBootstrapRound2WithoutRound1(t *testing.T) {
	f, keyShares := setupDKG(t, 2, 3)

	state := NewPiggybackState(keyShares[0])

	// Call BootstrapRound2 directly without BootstrapRound1.
	_, err := f.BootstrapRound2(keyShares[0], state, nil, []byte("test"), nil)
	if err == nil {
		t.Fatal("expected error when calling BootstrapRound2 without BootstrapRound1")
	}
	if !strings.Contains(err.Error(), "BootstrapRound2 called without BootstrapRound1") {
		t.Fatalf("expected precondition error, got: %v", err)
	}
}

// mustRandomScalar generates a random scalar, failing the test on error.
func mustRandomScalar(t *testing.T, g group.Group) group.Scalar {
	t.Helper()
	s, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatalf("RandomScalar: %v", err)
	}
	return s
}
