// Package dkg implements the DKLs23 Distributed Key Generation protocol.
// This is Protocol 9.1 from https://eprint.iacr.org/2023/602.pdf
package dkg

import (
	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/ot"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// Parameters contains t (threshold) and n (share_count)
type Parameters struct {
	Threshold  uint8
	ShareCount uint8
}

// SessionData contains data for a DKG session
type SessionData struct {
	Parameters Parameters
	PartyIndex uint8
	SessionID  []byte
}

// ProofCommitment contains proof and commitment for DKG
type ProofCommitment struct {
	Index      uint8
	Proof      *dkls23.DLogProof
	Commitment dkls23.HashOutput
	Salt       []byte
}

// ZeroSeed is a 32-byte seed for zero shares
type ZeroSeed = [dkls23.Security]byte

// Phase2to4ZeroTransmit is transmitted for zero shares init
type Phase2to4ZeroTransmit struct {
	Sender     uint8
	Receiver   uint8
	Commitment dkls23.HashOutput
}

// Phase3to4ZeroTransmit is transmitted for zero shares init
type Phase3to4ZeroTransmit struct {
	Sender   uint8
	Receiver uint8
	Seed     ZeroSeed
	Salt     []byte
}

// Phase2to3ZeroKeep is kept for zero shares init
type Phase2to3ZeroKeep struct {
	Seed ZeroSeed
	Salt []byte
}

// Phase3to4ZeroKeep is kept for zero shares init
type Phase3to4ZeroKeep struct {
	Seed ZeroSeed
}

// Phase3to4MulTransmit is transmitted for multiplication init
type Phase3to4MulTransmit struct {
	Sender    uint8
	Receiver  uint8
	DLogProof *dkls23.DLogProof
	Nonce     group.Scalar
	EncProofs []*dkls23.EncProof
	Seed      *ot.Seed
}

// Phase3to4MulKeep is kept for multiplication init
type Phase3to4MulKeep struct {
	OTSender    *ot.Sender
	Nonce       group.Scalar
	OTReceiver  *ot.Receiver
	Correlation []bool
	VecR        []group.Scalar
}

// Phase1Output is the output of phase 1
type Phase1Output struct {
	PolyPoints []group.Scalar // Evaluation at each party index
}

// Phase2Output is the output of phase 2
type Phase2Output struct {
	PolyPoint       group.Scalar
	ProofCommitment *ProofCommitment
	ZeroKeep        map[uint8]*Phase2to3ZeroKeep
	ZeroTransmit    []*Phase2to4ZeroTransmit
}

// Phase3Output is the output of phase 3
type Phase3Output struct {
	ZeroKeep     map[uint8]*Phase3to4ZeroKeep
	ZeroTransmit []*Phase3to4ZeroTransmit
	MulKeep      map[uint8]*Phase3to4MulKeep
	MulTransmit  []*Phase3to4MulTransmit
}

// Phase4Input contains all received messages for phase 4
type Phase4Input struct {
	PolyPoint         group.Scalar
	ProofsCommitments []*ProofCommitment
	ZeroKept          map[uint8]*Phase3to4ZeroKeep
	ZeroReceived2     []*Phase2to4ZeroTransmit
	ZeroReceived3     []*Phase3to4ZeroTransmit
	MulKept           map[uint8]*Phase3to4MulKeep
	MulReceived       []*Phase3to4MulTransmit
}

// CommitBytes creates a hash commitment to bytes
func CommitBytes(data []byte) (dkls23.HashOutput, []byte, error) {
	salt, err := dkls23.RandBytes(32)
	if err != nil {
		return dkls23.HashOutput{}, nil, err
	}
	combined := make([]byte, len(data)+len(salt))
	copy(combined, data)
	copy(combined[len(data):], salt)
	return dkls23.Hash(combined, nil), salt, nil
}

// VerifyCommitBytes verifies a byte commitment
func VerifyCommitBytes(data []byte, commitment dkls23.HashOutput, salt []byte) bool {
	combined := make([]byte, len(data)+len(salt))
	copy(combined, data)
	copy(combined[len(data):], salt)
	computed := dkls23.Hash(combined, nil)
	return computed == commitment
}

// GenerateZeroSeedWithCommitment generates a seed and its commitment
func GenerateZeroSeedWithCommitment() (ZeroSeed, dkls23.HashOutput, []byte, error) {
	seedBytes, err := dkls23.RandBytes(dkls23.Security)
	if err != nil {
		return ZeroSeed{}, dkls23.HashOutput{}, nil, err
	}
	var seed ZeroSeed
	copy(seed[:], seedBytes)
	commitment, salt, err := CommitBytes(seed[:])
	if err != nil {
		return ZeroSeed{}, dkls23.HashOutput{}, nil, err
	}
	return seed, commitment, salt, nil
}

// VerifyZeroSeed verifies a zero seed commitment
func VerifyZeroSeed(seed *ZeroSeed, commitment dkls23.HashOutput, salt []byte) bool {
	return VerifyCommitBytes(seed[:], commitment, salt)
}

// GenerateZeroSeedPair combines two seeds into a shared seed pair
func GenerateZeroSeedPair(myIndex, theirIndex uint8, mySeed, theirSeed *ZeroSeed) *sign.ZeroSeedPair {
	var combinedSeed ZeroSeed
	for i := 0; i < dkls23.Security; i++ {
		combinedSeed[i] = mySeed[i] ^ theirSeed[i]
	}

	return &sign.ZeroSeedPair{
		LowestIndex:       myIndex <= theirIndex,
		IndexCounterparty: theirIndex,
		Seed:              combinedSeed,
	}
}
