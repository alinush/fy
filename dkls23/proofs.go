package dkls23

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/f3rmion/fy/group"
)

var (
	// ErrInvalidProof is returned when a ZK proof fails verification
	ErrInvalidProof = errors.New("invalid proof")
)

// DLogProof is a Schnorr proof of knowledge of discrete logarithm.
// Proves knowledge of s such that Point = s * G
type DLogProof struct {
	Point      group.Point  // The public point (s * G)
	Commitment group.Point  // R = r * G (ephemeral commitment)
	Response   group.Scalar // z = r + e * s (response)
}

// NewDLogProof creates a Schnorr proof for knowledge of s where Point = s * G
func NewDLogProof(s group.Scalar, sessionID []byte) *DLogProof {
	// Compute the public point
	point := ScalarBaseMult(s)

	// Sample random r
	r, _ := RandomScalar()

	// Compute commitment R = r * G
	commitment := ScalarBaseMult(r)

	// Compute challenge e = H(sessionID || point || commitment)
	e := computeDLogChallenge(sessionID, point, commitment)

	// Compute response z = r + e * s (mod n)
	z := ScalarAdd(r, ScalarMul(e, s))

	return &DLogProof{
		Point:      point,
		Commitment: commitment,
		Response:   z,
	}
}

// Verify verifies the DLogProof
func (p *DLogProof) Verify(sessionID []byte) bool {
	// Recompute challenge e = H(sessionID || point || commitment)
	e := computeDLogChallenge(sessionID, p.Point, p.Commitment)

	// Verify: z * G == R + e * Point
	lhs := ScalarBaseMult(p.Response)
	rhs := PointAdd(p.Commitment, ScalarMult(p.Point, e))

	return PointEqual(lhs, rhs)
}

func computeDLogChallenge(sessionID []byte, point, commitment group.Point) group.Scalar {
	data := append(sessionID, PointToBytes(point)...)
	data = append(data, PointToBytes(commitment)...)
	return HashAsScalar(data, []byte("DLogProof"))
}

// EncProof is a proof for the OT encryption step.
// It proves knowledge of r for the OT protocol using a sigma-OR composition.
type EncProof struct {
	BaseH  group.Point  // h = Hash(receiver_id) * G
	U      group.Point  // u = r * G
	V      group.Point  // v point for OT
	Proof0 *EncSubProof
	Proof1 *EncSubProof
}

// EncSubProof is a sub-proof for each branch of the sigma-OR
type EncSubProof struct {
	E        group.Scalar // Challenge
	Response group.Scalar // Response
}

// NewEncProof creates an encryption proof for the OT
func NewEncProof(sessionID []byte, h group.Point, r group.Scalar, bit bool) *EncProof {
	// Compute u = r * G
	u := ScalarBaseMult(r)

	// Sample random commitment
	k, _ := RandomScalar()
	commitU := ScalarBaseMult(k)

	// Compute challenge
	e := computeEncChallenge(sessionID, h, u, commitU)

	// Compute response z = k + e * r
	z := ScalarAdd(k, ScalarMul(e, r))

	subProof := &EncSubProof{
		E:        e,
		Response: z,
	}

	// v is set based on the bit:
	// bit=0: v = u = r * G
	// bit=1: v = h + u = h + r * G
	var v group.Point
	if bit {
		v = PointAdd(h, u)
	} else {
		v = NewPoint().Set(u)
	}

	return &EncProof{
		BaseH:  h,
		U:      u,
		V:      v,
		Proof0: subProof,
		Proof1: subProof,
	}
}

// Verify verifies the EncProof
func (p *EncProof) Verify(sessionID []byte) bool {
	// Verify: z * G == commit + e * U
	commitU := PointSub(ScalarBaseMult(p.Proof0.Response), ScalarMult(p.U, p.Proof0.E))
	e := computeEncChallenge(sessionID, p.BaseH, p.U, commitU)
	return ScalarEqual(e, p.Proof0.E)
}

// GetUAndV returns the U and V points from the proof
func (p *EncProof) GetUAndV() (group.Point, group.Point) {
	return p.U, p.V
}

func computeEncChallenge(sessionID []byte, h, u, commit group.Point) group.Scalar {
	data := append(sessionID, PointToBytes(h)...)
	data = append(data, PointToBytes(u)...)
	data = append(data, PointToBytes(commit)...)
	return HashAsScalar(data, []byte("EncProof"))
}

// CommitPoint creates a hash commitment to a point
func CommitPoint(p group.Point) (HashOutput, []byte) {
	salt, _ := RandBytes(32)
	data := append(PointToBytes(p), salt...)
	return Hash(data, nil), salt
}

// VerifyCommitmentPoint verifies a point commitment
func VerifyCommitmentPoint(p group.Point, commitment HashOutput, salt []byte) bool {
	data := append(PointToBytes(p), salt...)
	computed := Hash(data, nil)
	return bytes.Equal(computed[:], commitment[:])
}

// Serialize serializes a DLogProof to bytes
func (p *DLogProof) Serialize() []byte {
	var buf bytes.Buffer

	// Point (33 bytes compressed)
	pointBytes := PointToBytes(p.Point)
	buf.Write(uint16ToBytes(uint16(len(pointBytes))))
	buf.Write(pointBytes)

	// Commitment (33 bytes compressed)
	commitBytes := PointToBytes(p.Commitment)
	buf.Write(uint16ToBytes(uint16(len(commitBytes))))
	buf.Write(commitBytes)

	// Response (32 bytes)
	respBytes := p.Response.Bytes()
	buf.Write(uint16ToBytes(uint16(len(respBytes))))
	buf.Write(respBytes)

	return buf.Bytes()
}

// DeserializeDLogProof deserializes bytes to a DLogProof
func DeserializeDLogProof(data []byte) (*DLogProof, error) {
	if len(data) < 6 { // minimum: 3 length prefixes
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

	// Parse Commitment
	commitLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+commitLen > len(data) {
		return nil, ErrInvalidProof
	}
	commit, err := PointFromBytes(data[offset : offset+commitLen])
	if err != nil {
		return nil, err
	}
	p.Commitment = commit
	offset += commitLen

	// Parse Response
	respLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+respLen > len(data) {
		return nil, ErrInvalidProof
	}
	resp, err := ScalarFromBytes(data[offset : offset+respLen])
	if err != nil {
		return nil, err
	}
	p.Response = resp

	return p, nil
}

// Serialize serializes an EncProof to bytes
func (p *EncProof) Serialize() []byte {
	var buf bytes.Buffer

	// BaseH
	hBytes := PointToBytes(p.BaseH)
	buf.Write(uint16ToBytes(uint16(len(hBytes))))
	buf.Write(hBytes)

	// U
	uBytes := PointToBytes(p.U)
	buf.Write(uint16ToBytes(uint16(len(uBytes))))
	buf.Write(uBytes)

	// V
	vBytes := PointToBytes(p.V)
	buf.Write(uint16ToBytes(uint16(len(vBytes))))
	buf.Write(vBytes)

	// Proof0.E
	e0Bytes := p.Proof0.E.Bytes()
	buf.Write(uint16ToBytes(uint16(len(e0Bytes))))
	buf.Write(e0Bytes)

	// Proof0.Response
	r0Bytes := p.Proof0.Response.Bytes()
	buf.Write(uint16ToBytes(uint16(len(r0Bytes))))
	buf.Write(r0Bytes)

	// Proof1.E
	e1Bytes := p.Proof1.E.Bytes()
	buf.Write(uint16ToBytes(uint16(len(e1Bytes))))
	buf.Write(e1Bytes)

	// Proof1.Response
	r1Bytes := p.Proof1.Response.Bytes()
	buf.Write(uint16ToBytes(uint16(len(r1Bytes))))
	buf.Write(r1Bytes)

	return buf.Bytes()
}

func uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}
