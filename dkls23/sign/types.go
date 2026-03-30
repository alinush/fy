package sign

import (
	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/mta"
	"github.com/f3rmion/fy/dkls23/ot"
	"github.com/f3rmion/fy/group"
)

// Party represents a party after key generation, ready to sign
type Party struct {
	Index     uint8
	Threshold uint8
	Total     uint8
	SessionID []byte

	// Secret key share (poly_point in Rust)
	KeyShare group.Scalar
	// Public key
	PublicKey group.Point

	// Zero share seeds for each counterparty
	ZeroSeeds map[uint8]*ZeroSeedPair

	// Multiplication protocol instances for each counterparty
	MulSenders   map[uint8]*mta.Sender
	MulReceivers map[uint8]*mta.Receiver
}

// ZeroSeedPair represents the shared seed between two parties
type ZeroSeedPair struct {
	LowestIndex       bool
	IndexCounterparty uint8
	Seed              [dkls23.Security]byte
}

// SignData contains data needed to start signing
type SignData struct {
	SignID         []byte
	Counterparties []uint8
	MessageHash    dkls23.HashOutput
}

// Phase1ToPhase2Transmit is sent from phase 1 to phase 2
type Phase1ToPhase2Transmit struct {
	Sender     uint8
	Receiver   uint8
	Commitment dkls23.HashOutput
	MulData    *ot.DataToSender
}

// Phase1ToPhase2Keep is kept between phase 1 and phase 2
type Phase1ToPhase2Keep struct {
	Salt    []byte
	Chi     group.Scalar
	MulKeep *mta.DataToKeepReceiver
}

// UniqueKeep1to2 is data kept between phase 1 and 2 (same for all counterparties)
type UniqueKeep1to2 struct {
	InstanceKey   group.Scalar
	InstancePoint group.Point
	InversionMask group.Scalar
	Zeta          group.Scalar
}

// Phase2ToPhase3Transmit is sent from phase 2 to phase 3
type Phase2ToPhase3Transmit struct {
	Sender        uint8
	Receiver      uint8
	GammaU        group.Point
	GammaV        group.Point
	Psi           group.Scalar
	PublicShare   group.Point
	InstancePoint group.Point
	Salt          []byte
	MulData       *mta.DataToReceiver
}

// Phase2ToPhase3Keep is kept between phase 2 and phase 3
type Phase2ToPhase3Keep struct {
	CU         group.Scalar
	CV         group.Scalar
	Commitment dkls23.HashOutput
	MulKeep    *mta.DataToKeepReceiver
	Chi        group.Scalar
}

// UniqueKeep2to3 is data kept between phase 2 and 3
type UniqueKeep2to3 struct {
	InstanceKey   group.Scalar
	InstancePoint group.Point
	InversionMask group.Scalar
	KeyShare      group.Scalar
	PublicShare   group.Point
}

// Phase3Broadcast is broadcast after phase 3
type Phase3Broadcast struct {
	U group.Scalar
	W group.Scalar
}

// Signature represents the final ECDSA signature
type Signature struct {
	R          [32]byte
	S          [32]byte
	RecoveryID uint8
}

// Zero securely erases secret scalar material in UniqueKeep1to2.
func (k *UniqueKeep1to2) Zero() {
	if k.InstanceKey != nil {
		k.InstanceKey.Zero()
	}
	if k.InversionMask != nil {
		k.InversionMask.Zero()
	}
	if k.Zeta != nil {
		k.Zeta.Zero()
	}
}

// Zero securely erases secret scalar material in UniqueKeep2to3.
func (k *UniqueKeep2to3) Zero() {
	if k.InstanceKey != nil {
		k.InstanceKey.Zero()
	}
	if k.InversionMask != nil {
		k.InversionMask.Zero()
	}
	if k.KeyShare != nil {
		k.KeyShare.Zero()
	}
}

// Zero securely erases secret scalar material in Phase1ToPhase2Keep.
func (k *Phase1ToPhase2Keep) Zero() {
	if k.Chi != nil {
		k.Chi.Zero()
	}
	if k.MulKeep != nil {
		k.MulKeep.Zero()
	}
}

// Zero securely erases secret scalar material in Phase2ToPhase3Keep.
func (k *Phase2ToPhase3Keep) Zero() {
	if k.CU != nil {
		k.CU.Zero()
	}
	if k.CV != nil {
		k.CV.Zero()
	}
	if k.Chi != nil {
		k.Chi.Zero()
	}
	if k.MulKeep != nil {
		k.MulKeep.Zero()
	}
}

// ComputeZeroShare computes the party's share of zero for the given counterparties
func (p *Party) ComputeZeroShare(counterparties []uint8, sessionID []byte) group.Scalar {
	share := dkls23.NewScalar()
	for _, seed := range p.ZeroSeeds {
		// Skip if not in counterparties list
		found := false
		for _, cp := range counterparties {
			if cp == seed.IndexCounterparty {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Hash the seed to get a fragment
		fragment := dkls23.HashAsScalar(seed.Seed[:], sessionID)

		// Add or subtract based on index ordering
		if seed.LowestIndex {
			share = dkls23.ScalarSub(share, fragment)
		} else {
			share = dkls23.ScalarAdd(share, fragment)
		}
	}
	return share
}

// Zero securely erases secret material in the Party.
func (p *Party) Zero() {
	if p.KeyShare != nil {
		p.KeyShare.Zero()
	}
	for _, seed := range p.ZeroSeeds {
		for i := range seed.Seed {
			seed.Seed[i] = 0
		}
	}
	for _, s := range p.MulSenders {
		if s != nil && s.OTESender != nil {
			s.OTESender.Zero()
		}
	}
	for _, r := range p.MulReceivers {
		if r != nil && r.OTEReceiver != nil {
			r.OTEReceiver.Zero()
		}
	}
}
