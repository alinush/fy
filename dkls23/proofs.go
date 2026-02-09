// Ported to Go from https://github.com/0xCarbon/DKLs23
// Licensed under MIT/Apache-2.0 (dual license).
//
// Zero-knowledge proofs required by the protocols.
// DLogProof uses Schnorr's protocol with randomized Fischlin transform.
// EncProof uses Chaum-Pedersen with OR-composition and Fiat-Shamir.

package dkls23

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/f3rmion/fy/group"
)

// InteractiveDLogProof represents Schnorr's protocol (interactive version).
type InteractiveDLogProof struct {
	Challenge        []byte       // T-bit challenge
	ChallengeReponse group.Scalar // z = r - e*s
}

// dlogProveStep1 samples random commitments.
// Returns (scalar_rand_commitment, point_rand_commitment, error)
func dlogProveStep1() (group.Scalar, group.Point, error) {
	// Sample a nonzero random scalar
	var scalarRandCommitment group.Scalar
	for {
		s, err := RandomScalar()
		if err != nil {
			return nil, nil, err
		}
		if !s.IsZero() {
			scalarRandCommitment = s
			break
		}
	}
	pointRandCommitment := ScalarBaseMult(scalarRandCommitment)
	return scalarRandCommitment, pointRandCommitment, nil
}

// dlogProveStep2 computes the response for a given challenge.
func dlogProveStep2(scalar, scalarRandCommitment group.Scalar, challenge []byte) *InteractiveDLogProof {
	// Convert challenge bytes to scalar (extend to 32 bytes)
	extended := make([]byte, 32-FischlinT/8)
	extended = append(extended, challenge...)
	// Error is impossible: input is always exactly 32 bytes of zero-padding + challenge bytes
	challengeScalar, _ := ScalarFromBytes(extended)

	// z = r - e*s
	challengeResponse := ScalarSub(scalarRandCommitment, ScalarMul(challengeScalar, scalar))

	return &InteractiveDLogProof{
		Challenge:        challenge,
		ChallengeReponse: challengeResponse,
	}
}

// verifyInteractiveDLogProof verifies an interactive DLog proof.
func verifyInteractiveDLogProof(proof *InteractiveDLogProof, point, pointRandCommitment group.Point) bool {
	// Convert challenge bytes to scalar
	extended := make([]byte, 32-FischlinT/8)
	extended = append(extended, proof.Challenge...)
	// Error is impossible: input is always exactly 32 bytes of zero-padding + challenge bytes
	challengeScalar, _ := ScalarFromBytes(extended)

	// Verify: z*G + e*point == pointRandCommitment
	lhs := PointAdd(ScalarBaseMult(proof.ChallengeReponse), ScalarMult(point, challengeScalar))
	return PointEqual(lhs, pointRandCommitment)
}

// DLogProof is a non-interactive discrete log proof using randomized Fischlin transform.
// Proves knowledge of s such that Point = s * G
type DLogProof struct {
	Point           group.Point             // The public point (s * G)
	RandCommitments []group.Point           // R random commitments (64)
	Proofs          []*InteractiveDLogProof // R proofs (64)
}

// NewDLogProof creates a Schnorr proof using randomized Fischlin transform.
// Returns an error if the iteration budget is exhausted or CSPRNG fails.
func NewDLogProof(scalar group.Scalar, sessionID []byte) (*DLogProof, error) {
	// Execute Step 1 R times
	randCommitments := make([]group.Point, FischlinR)
	states := make([]group.Scalar, FischlinR)
	for i := 0; i < FischlinR; i++ {
		state, randCommitment, err := dlogProveStep1()
		if err != nil {
			return nil, err
		}
		randCommitments[i] = randCommitment
		states[i] = state
	}

	// Convert commitments to bytes for hashing
	rcAsBytes := make([]byte, 0)
	for _, rc := range randCommitments {
		rcAsBytes = append(rcAsBytes, PointToBytes(rc)...)
	}

	// "Proof of work" - find matching challenges
	firstProofs := make([]*InteractiveDLogProof, 0, FischlinR/2)
	lastProofs := make([]*InteractiveDLogProof, 0, FischlinR/2)

	challengeBytes := FischlinT / 8

	// Total iteration budget across all proof pairs.
	// Expected iterations: ~32 pairs * ~256 trials/pair = ~8,192.
	// Budget of 1M (~122x expected) ensures negligible false failure probability.
	const totalBudget = 1_000_000
	totalIterations := 0
	for i := 0; i < FischlinR/2; i++ {
		var flag bool
		for firstCounter := 0; firstCounter < 65535 && !flag; firstCounter++ {
			totalIterations++
			if totalIterations > totalBudget {
				return nil, errors.New("Fischlin proof: exceeded iteration budget")
			}
			// Sample first challenge
			firstChallenge := make([]byte, challengeBytes)
			if _, err := rand.Read(firstChallenge); err != nil {
				return nil, err
			}

			// Execute Step 2 at index i
			firstProof := dlogProveStep2(scalar, states[i], firstChallenge)

			// Compute first hash
			iBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(iBytes, uint16(i))
			firstMsg := append(PointToBytes(Generator()), rcAsBytes...)
			firstMsg = append(firstMsg, iBytes...)
			firstMsg = append(firstMsg, firstChallenge...)
			firstMsg = append(firstMsg, firstProof.ChallengeReponse.Bytes()...)
			firstHashFull := Hash(firstMsg, sessionID)
			firstHash := firstHashFull[:FischlinL/4]

			// Search for matching second challenge
			for secondCounter := 0; secondCounter < 65535; secondCounter++ {
				totalIterations++
				if totalIterations > totalBudget {
					return nil, errors.New("Fischlin proof: exceeded iteration budget")
				}
				secondChallenge := make([]byte, challengeBytes)
				if _, err := rand.Read(secondChallenge); err != nil {
					return nil, err
				}

				// Execute Step 2 at index i + R/2
				secondProof := dlogProveStep2(scalar, states[i+FischlinR/2], secondChallenge)

				// Compute second hash
				i2Bytes := make([]byte, 2)
				binary.BigEndian.PutUint16(i2Bytes, uint16(i+FischlinR/2))
				secondMsg := append(PointToBytes(Generator()), rcAsBytes...)
				secondMsg = append(secondMsg, i2Bytes...)
				secondMsg = append(secondMsg, secondChallenge...)
				secondMsg = append(secondMsg, secondProof.ChallengeReponse.Bytes()...)
				secondHashFull := Hash(secondMsg, sessionID)
				secondHash := secondHashFull[:FischlinL/4]

				// Check if hashes match
				if bytes.Equal(firstHash, secondHash) {
					firstProofs = append(firstProofs, firstProof)
					lastProofs = append(lastProofs, secondProof)
					flag = true
					break
				}
			}
		}
	}

	// Verify all proof pairs were found
	if len(firstProofs) != FischlinR/2 || len(lastProofs) != FischlinR/2 {
		return nil, errors.New("Fischlin proof: not all proof pairs found within budget")
	}

	// Combine proofs
	proofs := append(firstProofs, lastProofs...)

	return &DLogProof{
		Point:           ScalarBaseMult(scalar),
		RandCommitments: randCommitments,
		Proofs:          proofs,
	}, nil
}

// Verify verifies a DLogProof.
func (p *DLogProof) Verify(sessionID []byte) bool {
	// Check lengths
	if len(p.RandCommitments) != FischlinR || len(p.Proofs) != FischlinR {
		return false
	}

	// Convert commitments to bytes
	rcAsBytes := make([]byte, 0)
	for _, rc := range p.RandCommitments {
		rcAsBytes = append(rcAsBytes, PointToBytes(rc)...)
	}

	// Check for duplicate commitments
	seen := make(map[string]bool)
	for _, rc := range p.RandCommitments {
		key := string(PointToBytes(rc))
		if seen[key] {
			return false
		}
		seen[key] = true
	}

	// Verify each pair
	for i := 0; i < FischlinR/2; i++ {
		// Compute first hash
		iBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(iBytes, uint16(i))
		firstMsg := append(PointToBytes(Generator()), rcAsBytes...)
		firstMsg = append(firstMsg, iBytes...)
		firstMsg = append(firstMsg, p.Proofs[i].Challenge...)
		firstMsg = append(firstMsg, p.Proofs[i].ChallengeReponse.Bytes()...)
		firstHashFull := Hash(firstMsg, sessionID)
		firstHash := firstHashFull[:FischlinL/4]

		// Compute second hash
		i2Bytes := make([]byte, 2)
		binary.BigEndian.PutUint16(i2Bytes, uint16(i+FischlinR/2))
		secondMsg := append(PointToBytes(Generator()), rcAsBytes...)
		secondMsg = append(secondMsg, i2Bytes...)
		secondMsg = append(secondMsg, p.Proofs[i+FischlinR/2].Challenge...)
		secondMsg = append(secondMsg, p.Proofs[i+FischlinR/2].ChallengeReponse.Bytes()...)
		secondHashFull := Hash(secondMsg, sessionID)
		secondHash := secondHashFull[:FischlinL/4]

		// Check hash equality
		if !bytes.Equal(firstHash, secondHash) {
			return false
		}

		// Verify both interactive proofs
		if !verifyInteractiveDLogProof(p.Proofs[i], p.Point, p.RandCommitments[i]) {
			return false
		}
		if !verifyInteractiveDLogProof(p.Proofs[i+FischlinR/2], p.Point, p.RandCommitments[i+FischlinR/2]) {
			return false
		}
	}

	return true
}

// RandomCommitments holds random commitments for Chaum-Pedersen protocol.
type RandomCommitments struct {
	RcG group.Point
	RcH group.Point
}

// CPProof is the Chaum-Pedersen protocol (interactive version).
type CPProof struct {
	BaseG            group.Point // Parameters for the proof
	BaseH            group.Point
	PointU           group.Point
	PointV           group.Point
	ChallengeReponse group.Scalar
}

// cpProveStep1 samples random commitments for Chaum-Pedersen.
func cpProveStep1(baseG, baseH group.Point) (group.Scalar, *RandomCommitments, error) {
	// Sample a nonzero random scalar
	var scalarRandCommitment group.Scalar
	for {
		s, err := RandomScalar()
		if err != nil {
			return nil, nil, err
		}
		if !s.IsZero() {
			scalarRandCommitment = s
			break
		}
	}

	rcG := ScalarMult(baseG, scalarRandCommitment)
	rcH := ScalarMult(baseH, scalarRandCommitment)

	return scalarRandCommitment, &RandomCommitments{RcG: rcG, RcH: rcH}, nil
}

// cpProveStep2 computes the response for Chaum-Pedersen.
func cpProveStep2(baseG, baseH group.Point, scalar, scalarRandCommitment, challenge group.Scalar) *CPProof {
	pointU := ScalarMult(baseG, scalar)
	pointV := ScalarMult(baseH, scalar)
	challengeResponse := ScalarSub(scalarRandCommitment, ScalarMul(challenge, scalar))

	return &CPProof{
		BaseG:            baseG,
		BaseH:            baseH,
		PointU:           pointU,
		PointV:           pointV,
		ChallengeReponse: challengeResponse,
	}
}

// verifyCPProof verifies a Chaum-Pedersen proof.
func verifyCPProof(proof *CPProof, randCommitments *RandomCommitments, challenge group.Scalar) bool {
	// z*G + e*U == RcG
	pointVerifyG := PointAdd(ScalarMult(proof.BaseG, proof.ChallengeReponse), ScalarMult(proof.PointU, challenge))
	// z*H + e*V == RcH
	pointVerifyH := PointAdd(ScalarMult(proof.BaseH, proof.ChallengeReponse), ScalarMult(proof.PointV, challenge))

	return PointEqual(pointVerifyG, randCommitments.RcG) && PointEqual(pointVerifyH, randCommitments.RcH)
}

// cpSimulate simulates a "fake" Chaum-Pedersen proof.
func cpSimulate(baseG, baseH, pointU, pointV group.Point) (*RandomCommitments, group.Scalar, *CPProof, error) {
	challenge, err := RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}
	challengeResponse, err := RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute "random" commitments that work for this challenge
	rcG := PointAdd(ScalarMult(baseG, challengeResponse), ScalarMult(pointU, challenge))
	rcH := PointAdd(ScalarMult(baseH, challengeResponse), ScalarMult(pointV, challenge))

	return &RandomCommitments{RcG: rcG, RcH: rcH}, challenge, &CPProof{
		BaseG:            baseG,
		BaseH:            baseH,
		PointU:           pointU,
		PointV:           pointV,
		ChallengeReponse: challengeResponse,
	}, nil
}

// EncProof is an encryption proof for the Endemic OT protocol.
// Uses Chaum-Pedersen with OR-composition.
type EncProof struct {
	Proof0       *CPProof
	Proof1       *CPProof
	Commitments0 *RandomCommitments
	Commitments1 *RandomCommitments
	Challenge0   group.Scalar
	Challenge1   group.Scalar
}

// NewEncProof creates an encryption proof for OT.
func NewEncProof(sessionID []byte, baseH group.Point, scalar group.Scalar, bit bool) (*EncProof, error) {
	baseG := Generator()

	// u = r * H (independent of bit)
	u := ScalarMult(baseH, scalar)

	// v = r*G + bit*H
	var v, fakeV group.Point
	if bit {
		v = PointAdd(ScalarBaseMult(scalar), baseH)
		fakeV = PointAdd(ScalarBaseMult(scalar), baseH) // Same as v for bit=1
	} else {
		v = ScalarBaseMult(scalar)
		fakeV = PointSub(ScalarBaseMult(scalar), baseH) // v - H for simulation
	}

	// Real proof commitments
	realScalarCommitment, realCommitments, err := cpProveStep1(baseG, baseH)
	if err != nil {
		return nil, err
	}

	// Fake proof (simulated)
	fakeCommitments, fakeChallenge, fakeProof, err := cpSimulate(baseG, baseH, fakeV, u)
	if err != nil {
		return nil, err
	}

	// Fiat-Shamir: compute total challenge
	baseGBytes := PointToBytes(baseG)
	baseHBytes := PointToBytes(baseH)
	uBytes := PointToBytes(u)
	vBytes := PointToBytes(v)
	rRcGBytes := PointToBytes(realCommitments.RcG)
	rRcHBytes := PointToBytes(realCommitments.RcH)
	fRcGBytes := PointToBytes(fakeCommitments.RcG)
	fRcHBytes := PointToBytes(fakeCommitments.RcH)

	var msgForChallenge []byte
	if bit {
		// Fake proof (v) goes first, real proof (v-h) goes second
		msgForChallenge = append(baseGBytes, baseHBytes...)
		msgForChallenge = append(msgForChallenge, uBytes...)
		msgForChallenge = append(msgForChallenge, vBytes...)
		msgForChallenge = append(msgForChallenge, fRcGBytes...)
		msgForChallenge = append(msgForChallenge, fRcHBytes...)
		msgForChallenge = append(msgForChallenge, rRcGBytes...)
		msgForChallenge = append(msgForChallenge, rRcHBytes...)
	} else {
		// Real proof (v) goes first, fake proof (v-h) goes second
		msgForChallenge = append(baseGBytes, baseHBytes...)
		msgForChallenge = append(msgForChallenge, uBytes...)
		msgForChallenge = append(msgForChallenge, vBytes...)
		msgForChallenge = append(msgForChallenge, rRcGBytes...)
		msgForChallenge = append(msgForChallenge, rRcHBytes...)
		msgForChallenge = append(msgForChallenge, fRcGBytes...)
		msgForChallenge = append(msgForChallenge, fRcHBytes...)
	}

	challenge := HashAsScalar(msgForChallenge, sessionID)

	// Real challenge = total - fake
	realChallenge := ScalarSub(challenge, fakeChallenge)

	// Complete real proof
	realProof := cpProveStep2(baseG, baseH, scalar, realScalarCommitment, realChallenge)

	// Assemble EncProof
	if bit {
		return &EncProof{
			Proof0:       fakeProof,
			Proof1:       realProof,
			Commitments0: fakeCommitments,
			Commitments1: realCommitments,
			Challenge0:   fakeChallenge,
			Challenge1:   realChallenge,
		}, nil
	}
	return &EncProof{
		Proof0:       realProof,
		Proof1:       fakeProof,
		Commitments0: realCommitments,
		Commitments1: fakeCommitments,
		Challenge0:   realChallenge,
		Challenge1:   fakeChallenge,
	}, nil
}

// Verify verifies an EncProof.
func (p *EncProof) Verify(sessionID []byte) bool {
	// Check proof compatibility
	if !PointEqual(p.Proof0.BaseG, Generator()) ||
		!PointEqual(p.Proof0.BaseG, p.Proof1.BaseG) ||
		!PointEqual(p.Proof0.BaseH, p.Proof1.BaseH) ||
		!PointEqual(p.Proof0.PointV, p.Proof1.PointV) { // This is u from the paper
		return false
	}

	// Check proof0.PointU == proof1.PointU + H
	expectedU := PointAdd(p.Proof1.PointU, p.Proof1.BaseH)
	if !PointEqual(p.Proof0.PointU, expectedU) {
		return false
	}

	// Reconstruct challenge
	baseGBytes := PointToBytes(p.Proof0.BaseG)
	baseHBytes := PointToBytes(p.Proof0.BaseH)
	uBytes := PointToBytes(p.Proof0.PointV) // u is stored in PointV
	vBytes := PointToBytes(p.Proof0.PointU) // v is stored in PointU of proof0

	rc0GBytes := PointToBytes(p.Commitments0.RcG)
	rc0HBytes := PointToBytes(p.Commitments0.RcH)
	rc1GBytes := PointToBytes(p.Commitments1.RcG)
	rc1HBytes := PointToBytes(p.Commitments1.RcH)

	msgForChallenge := append(baseGBytes, baseHBytes...)
	msgForChallenge = append(msgForChallenge, uBytes...)
	msgForChallenge = append(msgForChallenge, vBytes...)
	msgForChallenge = append(msgForChallenge, rc0GBytes...)
	msgForChallenge = append(msgForChallenge, rc0HBytes...)
	msgForChallenge = append(msgForChallenge, rc1GBytes...)
	msgForChallenge = append(msgForChallenge, rc1HBytes...)

	expectedChallenge := HashAsScalar(msgForChallenge, sessionID)

	// Challenge should be sum of individual challenges
	sumChallenge := ScalarAdd(p.Challenge0, p.Challenge1)
	if !ScalarEqual(expectedChallenge, sumChallenge) {
		return false
	}

	// Verify both proofs
	return verifyCPProof(p.Proof0, p.Commitments0, p.Challenge0) &&
		verifyCPProof(p.Proof1, p.Commitments1, p.Challenge1)
}

// GetUAndV extracts u and v from an EncProof.
// Note: u and v here match the paper notation, not the CPProof field names.
func (p *EncProof) GetUAndV() (group.Point, group.Point) {
	return p.Proof0.PointV, p.Proof0.PointU
}

// CommitPoint creates a hash commitment to a point.
func CommitPoint(point group.Point) (HashOutput, []byte, error) {
	salt := make([]byte, 2*Security)
	if _, err := rand.Read(salt); err != nil {
		return HashOutput{}, nil, err
	}
	pointBytes := PointToBytes(point)
	commitment := Hash(pointBytes, salt)
	return commitment, salt, nil
}

// VerifyCommitmentPoint verifies a point commitment.
func VerifyCommitmentPoint(point group.Point, commitment HashOutput, salt []byte) bool {
	pointBytes := PointToBytes(point)
	expected := Hash(pointBytes, salt)
	return bytes.Equal(commitment[:], expected[:])
}

// Serialize serializes a DLogProof to bytes.
func (p *DLogProof) Serialize() []byte {
	var buf bytes.Buffer

	// Point (33 bytes compressed)
	pointBytes := PointToBytes(p.Point)
	buf.Write(uint16ToBytes(uint16(len(pointBytes))))
	buf.Write(pointBytes)

	// Number of rand commitments
	buf.Write(uint16ToBytes(uint16(len(p.RandCommitments))))
	for _, rc := range p.RandCommitments {
		rcBytes := PointToBytes(rc)
		buf.Write(uint16ToBytes(uint16(len(rcBytes))))
		buf.Write(rcBytes)
	}

	// Number of proofs
	buf.Write(uint16ToBytes(uint16(len(p.Proofs))))
	for _, proof := range p.Proofs {
		// Challenge length + data
		buf.Write(uint16ToBytes(uint16(len(proof.Challenge))))
		buf.Write(proof.Challenge)
		// Response
		respBytes := proof.ChallengeReponse.Bytes()
		buf.Write(uint16ToBytes(uint16(len(respBytes))))
		buf.Write(respBytes)
	}

	return buf.Bytes()
}

// DeserializeDLogProof deserializes bytes to a DLogProof.
func DeserializeDLogProof(data []byte) (*DLogProof, error) {
	if len(data) < 6 {
		return nil, ErrInvalidProof
	}

	p := &DLogProof{}
	offset := 0

	// Parse Point
	pointLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+pointLen > len(data) {
		return nil, ErrInvalidProof
	}
	point, err := PointFromBytes(data[offset : offset+pointLen])
	if err != nil {
		return nil, err
	}
	p.Point = point
	offset += pointLen

	// Parse rand commitments count
	if offset+2 > len(data) {
		return nil, ErrInvalidProof
	}
	rcCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	p.RandCommitments = make([]group.Point, rcCount)
	for i := 0; i < rcCount; i++ {
		if offset+2 > len(data) {
			return nil, ErrInvalidProof
		}
		rcLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+rcLen > len(data) {
			return nil, ErrInvalidProof
		}
		rc, err := PointFromBytes(data[offset : offset+rcLen])
		if err != nil {
			return nil, err
		}
		p.RandCommitments[i] = rc
		offset += rcLen
	}

	// Parse proofs count
	if offset+2 > len(data) {
		return nil, ErrInvalidProof
	}
	proofCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	p.Proofs = make([]*InteractiveDLogProof, proofCount)
	for i := 0; i < proofCount; i++ {
		proof := &InteractiveDLogProof{}

		// Challenge
		if offset+2 > len(data) {
			return nil, ErrInvalidProof
		}
		challengeLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+challengeLen > len(data) {
			return nil, ErrInvalidProof
		}
		proof.Challenge = make([]byte, challengeLen)
		copy(proof.Challenge, data[offset:offset+challengeLen])
		offset += challengeLen

		// Response
		if offset+2 > len(data) {
			return nil, ErrInvalidProof
		}
		respLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+respLen > len(data) {
			return nil, ErrInvalidProof
		}
		resp, err := ScalarFromBytes(data[offset : offset+respLen])
		if err != nil {
			return nil, err
		}
		proof.ChallengeReponse = resp
		offset += respLen

		p.Proofs[i] = proof
	}

	return p, nil
}

// Serialize serializes an EncProof to bytes.
func (p *EncProof) Serialize() []byte {
	var buf bytes.Buffer

	// Helper to serialize CPProof
	serializeCPProof := func(cp *CPProof) {
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(cp.BaseG)))))
		buf.Write(PointToBytes(cp.BaseG))
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(cp.BaseH)))))
		buf.Write(PointToBytes(cp.BaseH))
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(cp.PointU)))))
		buf.Write(PointToBytes(cp.PointU))
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(cp.PointV)))))
		buf.Write(PointToBytes(cp.PointV))
		respBytes := cp.ChallengeReponse.Bytes()
		buf.Write(uint16ToBytes(uint16(len(respBytes))))
		buf.Write(respBytes)
	}

	// Helper to serialize RandomCommitments
	serializeRC := func(rc *RandomCommitments) {
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(rc.RcG)))))
		buf.Write(PointToBytes(rc.RcG))
		buf.Write(uint16ToBytes(uint16(len(PointToBytes(rc.RcH)))))
		buf.Write(PointToBytes(rc.RcH))
	}

	serializeCPProof(p.Proof0)
	serializeCPProof(p.Proof1)
	serializeRC(p.Commitments0)
	serializeRC(p.Commitments1)

	c0Bytes := p.Challenge0.Bytes()
	buf.Write(uint16ToBytes(uint16(len(c0Bytes))))
	buf.Write(c0Bytes)

	c1Bytes := p.Challenge1.Bytes()
	buf.Write(uint16ToBytes(uint16(len(c1Bytes))))
	buf.Write(c1Bytes)

	return buf.Bytes()
}

// DeserializeEncProof deserializes bytes to an EncProof.
func DeserializeEncProof(data []byte) (*EncProof, error) {
	if len(data) < 10 {
		return nil, ErrInvalidProof
	}

	p := &EncProof{}
	offset := 0

	// Helper to deserialize a point
	readPoint := func() (group.Point, error) {
		if offset+2 > len(data) {
			return nil, ErrInvalidProof
		}
		pLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+pLen > len(data) {
			return nil, ErrInvalidProof
		}
		pt, err := PointFromBytes(data[offset : offset+pLen])
		offset += pLen
		return pt, err
	}

	// Helper to deserialize a scalar
	readScalar := func() (group.Scalar, error) {
		if offset+2 > len(data) {
			return nil, ErrInvalidProof
		}
		sLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+sLen > len(data) {
			return nil, ErrInvalidProof
		}
		sc, err := ScalarFromBytes(data[offset : offset+sLen])
		offset += sLen
		return sc, err
	}

	// Helper to deserialize CPProof
	readCPProof := func() (*CPProof, error) {
		cp := &CPProof{}
		var err error
		if cp.BaseG, err = readPoint(); err != nil {
			return nil, err
		}
		if cp.BaseH, err = readPoint(); err != nil {
			return nil, err
		}
		if cp.PointU, err = readPoint(); err != nil {
			return nil, err
		}
		if cp.PointV, err = readPoint(); err != nil {
			return nil, err
		}
		if cp.ChallengeReponse, err = readScalar(); err != nil {
			return nil, err
		}
		return cp, nil
	}

	// Helper to deserialize RandomCommitments
	readRC := func() (*RandomCommitments, error) {
		rc := &RandomCommitments{}
		var err error
		if rc.RcG, err = readPoint(); err != nil {
			return nil, err
		}
		if rc.RcH, err = readPoint(); err != nil {
			return nil, err
		}
		return rc, nil
	}

	var err error
	if p.Proof0, err = readCPProof(); err != nil {
		return nil, err
	}
	if p.Proof1, err = readCPProof(); err != nil {
		return nil, err
	}
	if p.Commitments0, err = readRC(); err != nil {
		return nil, err
	}
	if p.Commitments1, err = readRC(); err != nil {
		return nil, err
	}
	if p.Challenge0, err = readScalar(); err != nil {
		return nil, err
	}
	if p.Challenge1, err = readScalar(); err != nil {
		return nil, err
	}

	return p, nil
}

// ErrInvalidProof is returned when a ZK proof fails verification or deserialization.
var ErrInvalidProof = errors.New("invalid proof")

func uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}
