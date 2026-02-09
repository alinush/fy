package session

import (
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/group"
)

// SigningSession manages a single signing operation with built-in nonce safety.
// Each session can only be used once; attempting to sign twice returns an error.
//
// Create sessions using [Participant.NewSigningSession].
type SigningSession struct {
	mu         sync.Mutex
	frost      *frost.FROST
	keyShare   *frost.KeyShare
	message    []byte
	nonce      *frost.SigningNonce
	commitment *frost.SigningCommitment
	consumed   bool
}

// NewSigningSession creates a new signing session for the given message.
//
// This generates fresh nonces internally. The session must be used exactly
// once - calling Sign a second time will return an error.
//
// The participant must have completed DKG before creating signing sessions.
func (p *Participant) NewSigningSession(rng io.Reader, message []byte) (*SigningSession, error) {
	if p.keyShare == nil {
		return nil, errors.New("DKG not complete: no key share available")
	}

	nonce, commitment, err := p.frost.SignRound1(rng, p.keyShare)
	if err != nil {
		return nil, err
	}

	// Copy message to prevent external modification
	msgCopy := make([]byte, len(message))
	copy(msgCopy, message)

	return &SigningSession{
		frost:      p.frost,
		keyShare:   p.keyShare,
		message:    msgCopy,
		nonce:      nonce,
		commitment: commitment,
	}, nil
}

// Commitment returns the public commitment that must be broadcast to other signers.
func (s *SigningSession) Commitment() *frost.SigningCommitment {
	return s.commitment
}

// Message returns the message being signed.
func (s *SigningSession) Message() []byte {
	return s.message
}

// Sign produces a signature share for this session.
//
// The allCommitments slice must contain commitments from all participating
// signers, including this participant's own commitment.
//
// This method consumes the session. Calling Sign a second time returns
// an error to prevent nonce reuse, which would compromise security.
//
// After Sign returns (successfully or not), the internal nonces are zeroed.
func (s *SigningSession) Sign(allCommitments []*frost.SigningCommitment) (*frost.SignatureShare, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.consumed {
		return nil, errors.New("session already consumed: nonce reuse prevented")
	}

	// Mark as consumed immediately, before any operations that might fail
	s.consumed = true

	// Ensure nonces are zeroed after this call, regardless of success
	defer s.zeroNonces()

	// Verify our commitment is in the list
	found := false
	for _, c := range allCommitments {
		if c.ID.Equal(s.commitment.ID) {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("own commitment not found in commitment list")
	}

	return s.frost.SignRound2(s.keyShare, s.nonce, s.message, allCommitments)
}

// zeroNonces overwrites secret nonce values before releasing them.
// This is a best-effort defense-in-depth measure. Limitations:
//   - SetBytes creates new internal state in math/big rather than overwriting
//     existing memory, so old words may persist in GC-managed memory.
//   - runtime.KeepAlive prevents GC collection before SetBytes completes,
//     but cannot prevent GC from copying the object during compaction.
//
// For stronger guarantees, use a scalar implementation backed by fixed-size
// byte arrays rather than math/big. Despite these limitations, overwriting
// reduces the exposure window and is the standard Go best-effort approach.
func (s *SigningSession) zeroNonces() {
	if s.nonce == nil {
		return
	}
	// Overwrite the scalar bytes with zeros before dropping the reference
	zeroBytes := make([]byte, 32)
	if s.nonce.D != nil {
		s.nonce.D.SetBytes(zeroBytes)
		runtime.KeepAlive(s.nonce.D)
	}
	if s.nonce.E != nil {
		s.nonce.E.SetBytes(zeroBytes)
		runtime.KeepAlive(s.nonce.E)
	}
	s.nonce = nil
}

// IsConsumed returns true if this session has already been used for signing.
func (s *SigningSession) IsConsumed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumed
}

// Aggregate combines signature shares into a final signature.
//
// This is typically called by a coordinator after collecting shares from
// all participating signers.
//
// Parameters:
//   - f: The FROST instance (must match the one used for signing)
//   - message: The message that was signed
//   - commitments: All signing commitments from participants
//   - shares: All signature shares from participants
func Aggregate(
	f *frost.FROST,
	message []byte,
	commitments []*frost.SigningCommitment,
	shares []*frost.SignatureShare,
) (*frost.Signature, error) {
	if len(shares) == 0 {
		return nil, errors.New("no signature shares provided")
	}
	if len(commitments) == 0 {
		return nil, errors.New("no commitments provided")
	}
	if len(shares) != len(commitments) {
		return nil, errors.New("number of shares must match number of commitments")
	}

	return f.Aggregate(message, commitments, shares)
}

// Verify checks whether a signature is valid for the given message and group key.
//
// Returns nil if the signature is valid, or an error describing why it's invalid.
func Verify(f *frost.FROST, message []byte, sig *frost.Signature, groupKey group.Point) error {
	if !f.Verify(message, sig, groupKey) {
		return errors.New("signature verification failed")
	}
	return nil
}

// QuickSign performs a complete signing operation when all key shares are local.
//
// This is useful for testing or single-machine threshold setups where all
// participants are in the same process. For distributed signing, use
// [SigningSession] instead.
//
// The signerShares must contain at least threshold key shares.
func QuickSign(
	f *frost.FROST,
	rng io.Reader,
	signerShares []*frost.KeyShare,
	message []byte,
) (*frost.Signature, error) {
	if len(signerShares) == 0 {
		return nil, errors.New("no key shares provided")
	}

	// Round 1: Generate nonces and commitments
	nonces := make([]*frost.SigningNonce, len(signerShares))
	commitments := make([]*frost.SigningCommitment, len(signerShares))

	for i, share := range signerShares {
		nonce, commitment, err := f.SignRound1(rng, share)
		if err != nil {
			return nil, err
		}
		nonces[i] = nonce
		commitments[i] = commitment
	}

	// Round 2: Generate signature shares
	shares := make([]*frost.SignatureShare, len(signerShares))

	for i, keyShare := range signerShares {
		share, err := f.SignRound2(keyShare, nonces[i], message, commitments)
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}

	// Aggregate
	return f.Aggregate(message, commitments, shares)
}
