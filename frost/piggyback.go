package frost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sort"
	"sync"

	"github.com/f3rmion/fy/group"
)

// Error sentinels for the piggyback nonce preprocessing protocol.
var (
	// ErrPiggybackInactive is returned when PiggybackSign is called on an
	// inactive state (before bootstrap or after failure).
	ErrPiggybackInactive = errors.New("frost: piggyback state is not active")

	// ErrSessionOverflow is returned when SessionIndex reaches math.MaxUint64.
	// The signer must call ReBootstrap to reset the counter.
	ErrSessionOverflow = errors.New("frost: session index overflow (MaxUint64)")

	// ErrCommitmentIDMismatch is returned by the collector when a piggybacked
	// commitment's ID does not match the signature share's ID.
	ErrCommitmentIDMismatch = errors.New("frost: piggybacked commitment ID does not match share ID")

	// ErrDuplicateSigner is returned when duplicate signer IDs are detected
	// in piggybacked shares.
	ErrDuplicateSigner = errors.New("frost: duplicate signer ID in piggybacked shares")

	// ErrIdentityCommitment is returned when a piggybacked commitment
	// contains an identity point (RFC 9591 Section 4.3).
	ErrIdentityCommitment = errors.New("frost: piggybacked commitment contains identity point")

	// ErrNilNextCommitment is returned when a piggybacked share has a nil
	// NextCommitment field.
	ErrNilNextCommitment = errors.New("frost: nil NextCommitment in piggybacked share")

	// ErrSessionIndexMismatch is returned when a piggybacked share's
	// SessionIndex does not match the expected value.
	ErrSessionIndexMismatch = errors.New("frost: session index mismatch in piggybacked share")
)

// PiggybackNonceState tracks the pending nonce commitment that was
// piggybacked in the previous signing session. Each signer maintains
// one instance per signing group.
type PiggybackNonceState struct {
	mu sync.Mutex

	// ID is the participant's identifier.
	ID group.Scalar

	// PendingNonce holds the secret nonce values pre-generated during
	// the previous session. Nil during bootstrap or after failure.
	PendingNonce *SigningNonce

	// PendingCommitment holds the public commitment broadcast during
	// the previous session. Nil during bootstrap or after failure.
	PendingCommitment *SigningCommitment

	// SessionIndex is a monotonically increasing counter tracking
	// the nonce generation epoch. Cryptographically bound into the
	// binding factor hash to prevent cross-session replay.
	SessionIndex uint64

	// Active indicates whether this state has a valid pending nonce
	// ready for consumption. Set to true after bootstrap or after
	// a successful piggyback round. Set to false on failure.
	Active bool
}

// PiggybackSignatureShare extends SignatureShare with the next
// session's nonce commitment, piggybacked onto the round-2 message.
type PiggybackSignatureShare struct {
	// SignatureShare is the standard FROST signature share for the
	// current session.
	SignatureShare

	// NextCommitment is the nonce commitment for the NEXT signing
	// session. Other signers must store this and use it as the
	// round-1 commitment in the next session.
	NextCommitment *SigningCommitment

	// SessionIndex identifies the nonce epoch of the NextCommitment, NOT the
	// signing session that produced this share. Recipients use this to detect
	// stale or replayed messages and to match commitments to sessions.
	SessionIndex uint64
}

// PiggybackSessionCollector aggregates piggybacked commitments
// received from all signers for the next session.
type PiggybackSessionCollector struct {
	// NextCommitments maps signer ID (as byte key) to the commitment
	// piggybacked for the next session.
	NextCommitments map[string]*SigningCommitment

	// ExpectedSigners is the number of signers expected.
	ExpectedSigners int

	// SessionIndex is the epoch for which these commitments are valid.
	SessionIndex uint64
}

// sessionBoundMessage prepends the session index as big-endian 8 bytes
// to the message. This binds the signing session's binding factor to
// the nonce epoch, preventing cross-session commitment replay.
func sessionBoundMessage(sessionIndex uint64, message []byte) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], sessionIndex)
	out := make([]byte, 8+len(message))
	copy(out, buf[:])
	copy(out[8:], message)
	return out
}

// cloneSigningNonce performs a deep copy of a SigningNonce using the
// group's scalar Set method. The clone is independent of the original;
// zeroing the original does not affect the clone.
func (f *FROST) cloneSigningNonce(nonce *SigningNonce) *SigningNonce {
	return &SigningNonce{
		ID: nonce.ID,
		D:  f.group.NewScalar().Set(nonce.D),
		E:  f.group.NewScalar().Set(nonce.E),
	}
}

// NewPiggybackState creates a fresh piggyback state for a signer.
// The state starts in the INACTIVE state; call BootstrapRound1 to begin.
func NewPiggybackState(share *KeyShare) *PiggybackNonceState {
	return &PiggybackNonceState{
		ID:     share.ID,
		Active: false,
	}
}

// BootstrapRound1 generates nonces for the current (bootstrap) session
// and pre-generates the NEXT session's nonces. The current nonce and
// commitment are returned for broadcast; the next nonce pair is stored
// in the state.
//
// After BootstrapRound1, the caller must broadcast currentCommitment,
// collect all commitments, and then call BootstrapRound2.
//
// If BootstrapRound2 is not subsequently called (e.g., due to network failure),
// the caller MUST call state.ReBootstrap() to securely erase the pre-generated nonce.
// The returned currentNonce must also be zeroed by the caller in that case.
func (f *FROST) BootstrapRound1(
	r io.Reader,
	state *PiggybackNonceState,
	share *KeyShare,
) (currentNonce *SigningNonce, currentCommitment *SigningCommitment, err error) {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Defense-in-depth: zero any existing pending nonce.
	state.zeroLocked()

	// Generate nonces for session 0 (bootstrap session).
	currentNonce, currentCommitment, err = f.SignRound1(r, share)
	if err != nil {
		return nil, nil, err
	}

	// Pre-generate nonces for session 1 (first piggyback session).
	nextNonce, nextCommitment, err := f.SignRound1(r, share)
	if err != nil {
		// Zero the current nonce since we can't proceed.
		currentNonce.D.Zero()
		currentNonce.E.Zero()
		return nil, nil, err
	}

	state.PendingNonce = nextNonce
	state.PendingCommitment = nextCommitment
	state.SessionIndex = 1
	// Active remains false until BootstrapRound2 completes.

	return currentNonce, currentCommitment, nil
}

// BootstrapRound2 computes the signature share for the bootstrap session
// (session 0) using a session-bound message, and attaches the pre-generated
// next commitment. On success, the state transitions to ACTIVE.
func (f *FROST) BootstrapRound2(
	share *KeyShare,
	state *PiggybackNonceState,
	nonce *SigningNonce,
	message []byte,
	commitments []*SigningCommitment,
) (*PiggybackSignatureShare, error) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.PendingCommitment == nil {
		return nil, errors.New("frost: BootstrapRound2 called without BootstrapRound1")
	}

	// Bootstrap is session 0.
	sessionMsg := sessionBoundMessage(0, message)

	sigShare, err := f.SignRound2(share, nonce, sessionMsg, commitments)
	if err != nil {
		return nil, err
	}

	state.Active = true

	return &PiggybackSignatureShare{
		SignatureShare: *sigShare,
		NextCommitment: state.PendingCommitment,
		SessionIndex:   state.SessionIndex,
	}, nil
}

// PiggybackSign performs a 1-round signing session using the pending
// nonce from the previous session. The flow is:
//
//  1. Pre-validate commitments (retryable on failure -- state unchanged).
//  2. Pre-generate next nonce (retryable on failure -- state unchanged).
//  3. Clone and consume the pending nonce (point of no return).
//  4. Call SignRound2 with session-bound message.
//  5. On SignRound2 failure: transition to FAILED state.
//  6. On success: increment SessionIndex and return the piggybacked share.
func (f *FROST) PiggybackSign(
	r io.Reader,
	share *KeyShare,
	state *PiggybackNonceState,
	message []byte,
	commitments []*SigningCommitment,
) (*PiggybackSignatureShare, error) {
	state.mu.Lock()
	defer state.mu.Unlock()

	// --- Validate state ---
	if !state.Active {
		return nil, ErrPiggybackInactive
	}
	if state.SessionIndex == math.MaxUint64 {
		return nil, ErrSessionOverflow
	}
	if state.PendingNonce == nil {
		return nil, ErrPiggybackInactive
	}

	// --- PRE-VALIDATION (retryable on failure) ---
	if err := f.piggybackPreValidate(state, commitments); err != nil {
		return nil, err
	}

	// --- PRE-GENERATE NEXT NONCE (retryable on failure) ---
	nextNonce, nextCommitment, err := f.SignRound1(r, share)
	if err != nil {
		return nil, err
	}

	// --- POINT OF NO RETURN: consume nonce ---
	clonedNonce := f.cloneSigningNonce(state.PendingNonce)

	// Zero the original pending nonce scalars.
	state.PendingNonce.D.Zero()
	state.PendingNonce.E.Zero()

	// Install new pending nonce for the next session.
	state.PendingNonce = nextNonce
	state.PendingCommitment = nextCommitment

	// --- SIGN ---
	sessionMsg := sessionBoundMessage(state.SessionIndex, message)
	sigShare, err := f.SignRound2(share, clonedNonce, sessionMsg, commitments)
	// SignRound2's defer zeroes clonedNonce.D and clonedNonce.E.
	if err != nil {
		// FAILED state: zero the newly installed nonce and deactivate.
		state.PendingNonce.D.Zero()
		state.PendingNonce.E.Zero()
		state.PendingNonce = nil
		state.PendingCommitment = nil
		state.Active = false
		return nil, err
	}

	// --- SUCCESS ---
	// Increment SessionIndex. The returned share's SessionIndex is the NEW
	// value (after increment), matching the epoch of the NextCommitment.
	state.SessionIndex++

	return &PiggybackSignatureShare{
		SignatureShare: *sigShare,
		NextCommitment: nextCommitment,
		SessionIndex:   state.SessionIndex,
	}, nil
}

// piggybackPreValidate checks commitments before consuming the nonce.
// Failures here are retryable (state unchanged).
func (f *FROST) piggybackPreValidate(state *PiggybackNonceState, commitments []*SigningCommitment) error {
	// Threshold check.
	if len(commitments) < f.threshold {
		return errors.New("frost: not enough commitments to meet threshold")
	}

	// Identity point check (RFC 9591).
	if err := validateCommitments(commitments); err != nil {
		return err
	}

	// Duplicate and own-commitment check.
	seen := make(map[string]bool, len(commitments))
	ownFound := false
	for _, c := range commitments {
		key := string(c.ID.Bytes())
		if seen[key] {
			return errors.New("frost: duplicate signer ID in commitment list")
		}
		seen[key] = true
		if c.ID.Equal(state.ID) {
			ownFound = true
			// Verify commitment matches our pending commitment.
			if state.PendingCommitment != nil {
				if !c.HidingPoint.Equal(state.PendingCommitment.HidingPoint) ||
					!c.BindingPoint.Equal(state.PendingCommitment.BindingPoint) {
					return errors.New("frost: own commitment does not match pending commitment")
				}
			}
		}
	}
	if !ownFound {
		return errors.New("frost: own commitment not found in commitment list")
	}

	return nil
}

// CollectPiggybackCommitments extracts next-session commitments from
// piggybacked signature shares. It validates:
//   - NextCommitment is non-nil
//   - NextCommitment.ID matches the SignatureShare.ID
//   - SessionIndex matches the expected value
//   - No identity-point commitments
//   - No duplicate signer IDs
func CollectPiggybackCommitments(
	shares []*PiggybackSignatureShare,
	expectedSessionIndex uint64,
) (*PiggybackSessionCollector, error) {
	collector := &PiggybackSessionCollector{
		NextCommitments: make(map[string]*SigningCommitment, len(shares)),
		ExpectedSigners: len(shares),
		SessionIndex:    expectedSessionIndex,
	}

	for _, s := range shares {
		// Nil check.
		if s.NextCommitment == nil {
			return nil, ErrNilNextCommitment
		}

		// ID match: NextCommitment.ID must equal SignatureShare.ID.
		if !s.NextCommitment.ID.Equal(s.SignatureShare.ID) {
			return nil, ErrCommitmentIDMismatch
		}

		// Session index match.
		if s.SessionIndex != expectedSessionIndex {
			return nil, ErrSessionIndexMismatch
		}

		// Identity point validation.
		if s.NextCommitment.HidingPoint.IsIdentity() || s.NextCommitment.BindingPoint.IsIdentity() {
			return nil, ErrIdentityCommitment
		}

		// Duplicate check.
		key := string(s.SignatureShare.ID.Bytes())
		if _, exists := collector.NextCommitments[key]; exists {
			return nil, ErrDuplicateSigner
		}

		collector.NextCommitments[key] = s.NextCommitment
	}

	return collector, nil
}

// Commitments returns the collected commitments sorted by signer ID bytes.
// Deterministic ordering is required for consistent binding factor computation.
func (c *PiggybackSessionCollector) Commitments() []*SigningCommitment {
	result := make([]*SigningCommitment, 0, len(c.NextCommitments))
	for _, comm := range c.NextCommitments {
		result = append(result, comm)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].ID.Bytes(), result[j].ID.Bytes()) < 0
	})
	return result
}

// PiggybackAggregate aggregates piggybacked signature shares with
// per-share verification (mandatory per review C3), extracts the final
// signature, and collects next-session commitments.
//
// The currentCommitments parameter contains the commitments for the
// current session (collected from the previous session's piggyback or
// from bootstrap). The shares contain both the signature shares for the
// current session and the NextCommitment for the next session.
//
// publicKeys maps signer ID bytes to their public key, required for
// per-share verification.
func (f *FROST) PiggybackAggregate(
	message []byte,
	sessionIndex uint64,
	currentCommitments []*SigningCommitment,
	shares []*PiggybackSignatureShare,
	publicKeys map[string]group.Point,
	groupKey group.Point,
) (*Signature, *PiggybackSessionCollector, error) {
	if sessionIndex == math.MaxUint64 {
		return nil, nil, ErrSessionOverflow
	}

	// Extract standard signature shares from piggybacked shares.
	sigShares := make([]*SignatureShare, len(shares))
	for i, s := range shares {
		ss := s.SignatureShare // copy the struct
		sigShares[i] = &ss
	}

	// Build session-bound message.
	sessionMsg := sessionBoundMessage(sessionIndex, message)

	// Aggregate with per-share verification (MANDATORY).
	sig, err := f.AggregateWithVerification(sessionMsg, currentCommitments, sigShares, publicKeys, groupKey)
	if err != nil {
		return nil, nil, err
	}

	// Collect next-session commitments.
	// The shares' SessionIndex should be sessionIndex+1 (the next epoch).
	collector, err := CollectPiggybackCommitments(shares, sessionIndex+1)
	if err != nil {
		return nil, nil, err
	}

	return sig, collector, nil
}

// PiggybackVerify is a convenience wrapper that verifies a signature
// produced by the piggyback protocol. It prepends the session index
// to the message before calling Verify, matching the session-bound
// message used during signing.
func (f *FROST) PiggybackVerify(message []byte, sessionIndex uint64, sig *Signature, groupKey group.Point) bool {
	sessionMsg := sessionBoundMessage(sessionIndex, message)
	return f.Verify(sessionMsg, sig, groupKey)
}

// ReBootstrap discards the current piggyback state and resets to INACTIVE.
// All pending nonce material is securely erased. After calling ReBootstrap,
// the signer must run a new bootstrap round (BootstrapRound1 + BootstrapRound2)
// before signing again.
//
// Re-bootstrap by any signer requires all signers in the active set to
// re-bootstrap, since the commitment set changes.
func (state *PiggybackNonceState) ReBootstrap() {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.zeroLocked()
	state.Active = false
	// SessionIndex is reset to 0. Cross-epoch replay is prevented by fresh
	// nonce randomness, not by session index uniqueness.
	state.SessionIndex = 0
	state.PendingNonce = nil
	state.PendingCommitment = nil
}

// Zero securely erases all secret material in the piggyback state.
// After calling Zero, the state is unusable and must not be reused.
func (state *PiggybackNonceState) Zero() {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.zeroLocked()
}

// zeroLocked erases pending nonce scalars. Must be called with mu held.
func (state *PiggybackNonceState) zeroLocked() {
	if state.PendingNonce != nil {
		if state.PendingNonce.D != nil {
			state.PendingNonce.D.Zero()
		}
		if state.PendingNonce.E != nil {
			state.PendingNonce.E.Zero()
		}
	}
}
