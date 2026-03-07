package ot

import (
	"errors"
	"math"
	"slices"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

// Seed is a 32-byte random seed used by the receiver
type Seed = [dkls23.Security]byte

// ErrOTFailed is returned when the OT protocol fails
var ErrOTFailed = errors.New("OT protocol failed")

// Sender holds the sender's state for the base OT protocol
type Sender struct {
	S     group.Scalar      // Secret scalar
	Proof *dkls23.DLogProof // Proof of discrete log for s * G
}

// Receiver holds the receiver's state for the base OT protocol
type Receiver struct {
	Seed Seed // Random seed for generating h
}

// NewSender creates a new OT sender with a fresh secret and proof
func NewSender(sessionID []byte) (*Sender, error) {
	// Sample a random non-zero scalar s
	s, err := dkls23.RandomScalar()
	if err != nil {
		return nil, err
	}

	// Create a proof of discrete log for s
	sid := slices.Concat(sessionID, []byte("DLogProof"))
	proof, err := dkls23.NewDLogProof(s, sid)
	if err != nil {
		return nil, err
	}

	return &Sender{
		S:     s,
		Proof: proof,
	}, nil
}

// Zero securely erases the sender's secret scalar.
func (s *Sender) Zero() {
	if s.S != nil {
		s.S.Zero()
	}
}

// Phase1 returns the DLogProof to be sent to the receiver
func (s *Sender) Phase1() *dkls23.DLogProof {
	return s.Proof
}

// Phase2 processes the receiver's data and computes the two output messages
func (s *Sender) Phase2(sessionID []byte, seed *Seed, encProof *dkls23.EncProof) (m0, m1 dkls23.HashOutput, err error) {
	// Reconstruct h from the seed
	msgForH := slices.Concat([]byte("Receiver"), seed[:])
	hScalar := dkls23.HashAsScalar(msgForH, sessionID)
	h := dkls23.ScalarBaseMult(hScalar)

	// Verify the encryption proof.
	// NOTE: The EncProof is bound to the session ID via the Fiat-Shamir challenge
	// (HashAsScalar uses sessionID as salt). Session ID uniqueness is assumed;
	// callers must ensure each protocol execution uses a distinct session ID
	// to prevent cross-session proof replay.
	sid := slices.Concat(sessionID, []byte("EncProof"))
	if !encProof.Verify(sid) {
		return m0, m1, ErrOTFailed
	}

	// Check if h matches the one in the proof (BaseH is inside Proof0)
	if !dkls23.PointEqual(h, encProof.Proof0.BaseH) {
		return m0, m1, errors.New("receiver cheated: h mismatch")
	}

	// Get u and v from the proof
	_, v := encProof.GetUAndV()

	// Compute messages:
	// m0 = H("Sender" || v * s)
	// m1 = H("Sender" || (v - h) * s)
	valueForM0 := dkls23.ScalarMult(v, s.S)
	valueForM1 := dkls23.ScalarMult(dkls23.PointSub(v, h), s.S)

	msgForM0 := slices.Concat([]byte("Sender"), dkls23.PointToBytes(valueForM0))
	msgForM1 := slices.Concat([]byte("Sender"), dkls23.PointToBytes(valueForM1))

	m0 = dkls23.Hash(msgForM0, sessionID)
	m1 = dkls23.Hash(msgForM1, sessionID)

	return m0, m1, nil
}

// Phase2Batch processes multiple encryption proofs from the receiver
func (s *Sender) Phase2Batch(sessionID []byte, seed *Seed, encProofs []*dkls23.EncProof) ([]dkls23.HashOutput, []dkls23.HashOutput, error) {
	batchSize := len(encProofs)
	if batchSize > math.MaxUint16 {
		return nil, nil, errors.New("batch size exceeds uint16 maximum; session ID counter would wrap")
	}
	vecM0 := make([]dkls23.HashOutput, batchSize)
	vecM1 := make([]dkls23.HashOutput, batchSize)

	for i := 0; i < batchSize; i++ {
		// Use different session IDs for different iterations
		currentSID := slices.Concat(uint16ToBytes(uint16(i)), sessionID)

		m0, m1, err := s.Phase2(currentSID, seed, encProofs[i])
		if err != nil {
			return nil, nil, err
		}

		vecM0[i] = m0
		vecM1[i] = m1
	}

	return vecM0, vecM1, nil
}

// NewReceiver creates a new OT receiver with a fresh seed
func NewReceiver() (*Receiver, error) {
	seed, err := dkls23.RandBytes(dkls23.Security)
	if err != nil {
		return nil, err
	}

	var s Seed
	copy(s[:], seed)

	return &Receiver{Seed: s}, nil
}

// Phase1 generates the receiver's data for the given choice bit.
// Returns the secret scalar r (to keep), the EncProof (to send), and an error.
// The caller MUST zero the returned scalar after use (e.g., via Phase2Step2 or Phase2Batch).
func (r *Receiver) Phase1(sessionID []byte, bit bool) (group.Scalar, *dkls23.EncProof, error) {
	// Sample random r
	rScalar, err := dkls23.RandomScalar()
	if err != nil {
		return nil, nil, err
	}

	// Compute h = Hash(receiver_id || seed) * G
	msgForH := slices.Concat([]byte("Receiver"), r.Seed[:])
	hScalar := dkls23.HashAsScalar(msgForH, sessionID)
	h := dkls23.ScalarBaseMult(hScalar)

	// Create the encryption proof
	sid := slices.Concat(sessionID, []byte("EncProof"))
	proof, err := dkls23.NewEncProof(sid, h, rScalar, bit)
	if err != nil {
		return nil, nil, err
	}

	return rScalar, proof, nil
}

// Phase1Batch generates receiver data for multiple choice bits
func (r *Receiver) Phase1Batch(sessionID []byte, bits []bool) ([]group.Scalar, []*dkls23.EncProof, error) {
	batchSize := len(bits)
	if batchSize > math.MaxUint16 {
		return nil, nil, errors.New("batch size exceeds uint16 maximum; session ID counter would wrap")
	}
	vecR := make([]group.Scalar, batchSize)
	vecProof := make([]*dkls23.EncProof, batchSize)

	for i := 0; i < batchSize; i++ {
		// Use different session IDs for different iterations
		currentSID := slices.Concat(uint16ToBytes(uint16(i)), sessionID)

		var err error
		vecR[i], vecProof[i], err = r.Phase1(currentSID, bits[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return vecR, vecProof, nil
}

// Phase2Step1 verifies the sender's DLogProof and returns the point z
func (r *Receiver) Phase2Step1(sessionID []byte, dlogProof *dkls23.DLogProof) (group.Point, error) {
	sid := slices.Concat(sessionID, []byte("DLogProof"))
	if !dlogProof.Verify(sid) {
		return nil, errors.New("sender cheated: DLogProof failed")
	}
	return dlogProof.Point, nil
}

// Phase2Step2 computes the receiver's output message.
// The rScalar is zeroed after use to prevent secret leakage.
func (r *Receiver) Phase2Step2(sessionID []byte, rScalar group.Scalar, z group.Point) dkls23.HashOutput {
	// Compute m_b = H("Sender" || r * z)
	valueForMb := dkls23.ScalarMult(z, rScalar)
	msgForMb := slices.Concat([]byte("Sender"), dkls23.PointToBytes(valueForMb))

	// Zero the secret scalar after use.
	rScalar.Zero()

	return dkls23.Hash(msgForMb, sessionID)
}

// Phase2Batch verifies the proof and computes outputs for all scalars.
// The vecR scalars are zeroed after use to prevent secret leakage.
func (r *Receiver) Phase2Batch(sessionID []byte, vecR []group.Scalar, dlogProof *dkls23.DLogProof) ([]dkls23.HashOutput, error) {
	if len(vecR) > math.MaxUint16 {
		return nil, errors.New("batch size exceeds uint16 maximum; session ID counter would wrap")
	}

	// Zero secret r scalars after computing outputs.
	defer func() {
		for _, rScalar := range vecR {
			if rScalar != nil {
				rScalar.Zero()
			}
		}
	}()

	// Step 1: Verify the proof
	z, err := r.Phase2Step1(sessionID, dlogProof)
	if err != nil {
		return nil, err
	}

	// Step 2: Compute outputs for each r
	batchSize := len(vecR)
	vecMb := make([]dkls23.HashOutput, batchSize)

	for i := 0; i < batchSize; i++ {
		// Use different session IDs for different iterations
		currentSID := slices.Concat(uint16ToBytes(uint16(i)), sessionID)
		vecMb[i] = r.Phase2Step2(currentSID, vecR[i], z)
	}

	return vecMb, nil
}

// Zero securely erases the receiver's seed.
func (r *Receiver) Zero() {
	for i := range r.Seed {
		r.Seed[i] = 0
	}
}

// GetSeed returns a copy of the receiver's seed (to be sent to the sender).
// A copy is returned so that zeroing the Receiver does not invalidate
// seed values already transmitted to the counterparty.
func (r *Receiver) GetSeed() *Seed {
	s := new(Seed)
	*s = r.Seed
	return s
}

// uint16ToBytes converts a uint16 to big-endian bytes
func uint16ToBytes(n uint16) []byte {
	return []byte{byte(n >> 8), byte(n)}
}
