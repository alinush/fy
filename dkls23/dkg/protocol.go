package dkg

import (
	"errors"
	"slices"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/mta"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// Step1 generates a random polynomial of degree t-1
func Step1(params *Parameters) ([]group.Scalar, error) {
	polynomial := make([]group.Scalar, params.Threshold)
	for i := uint8(0); i < params.Threshold; i++ {
		s, err := dkls23.RandomScalar()
		if err != nil {
			return nil, err
		}
		polynomial[i] = s
	}
	return polynomial, nil
}

// Step2 evaluates the polynomial at every party index (1 to n)
func Step2(params *Parameters, polynomial []group.Scalar) []group.Scalar {
	points := make([]group.Scalar, params.ShareCount)

	for j := uint8(1); j <= params.ShareCount; j++ {
		// Convert j to scalar
		jBytes := []byte{j}
		jScalar := dkls23.NewScalar()
		jScalar.SetBytes(jBytes)

		// Horner's method for polynomial evaluation
		lastIndex := params.Threshold - 1
		evaluation := dkls23.NewScalar().Set(polynomial[lastIndex])

		for k := int(lastIndex) - 1; k >= 0; k-- {
			// evaluation = evaluation * j + polynomial[k]
			evaluation = dkls23.ScalarAdd(dkls23.ScalarMul(evaluation, jScalar), polynomial[k])
		}

		points[j-1] = evaluation
	}

	return points
}

// Step3 computes poly_point and creates a DLogProof with commitment
func Step3(partyIndex uint8, sessionID []byte, polyFragments []group.Scalar) (group.Scalar, *ProofCommitment, error) {
	// Sum all fragments
	polyPoint := dkls23.NewScalar()
	for _, fragment := range polyFragments {
		polyPoint = dkls23.ScalarAdd(polyPoint, fragment)
	}

	// Create DLogProof
	proof, err := dkls23.NewDLogProof(polyPoint, sessionID)
	if err != nil {
		return nil, nil, err
	}

	// Create commitment to the proof point
	commitment, salt, err := dkls23.CommitPoint(proof.Point)
	if err != nil {
		return nil, nil, err
	}

	return polyPoint, &ProofCommitment{
		Index:      partyIndex,
		Proof:      proof,
		Commitment: commitment,
		Salt:       salt,
	}, nil
}

// Step5 validates proofs and computes the public key
func Step5(params *Parameters, partyIndex uint8, sessionID []byte, proofsCommitments []*ProofCommitment) (group.Point, error) {
	committedPoints := make(map[uint8]group.Point)

	// Verify proofs and gather committed points
	for _, pc := range proofsCommitments {
		if pc.Index != partyIndex {
			// Verify commitment
			if !dkls23.VerifyCommitmentPoint(pc.Proof.Point, pc.Commitment, pc.Salt) {
				return nil, errors.New("commitment verification failed")
			}
			// Verify DLogProof
			if !pc.Proof.Verify(sessionID) {
				return nil, errors.New("DLogProof verification failed")
			}
		}
		committedPoints[pc.Index] = pc.Proof.Point
	}

	// Verify consistency and compute public key using Lagrange interpolation
	var pk group.Point

	for i := uint8(1); i <= params.ShareCount-params.Threshold+1; i++ {
		currentPK := dkls23.NewPoint()

		for j := i; j < i+params.Threshold; j++ {
			// Compute Lagrange coefficient
			jBytes := []byte{j}
			jScalar := dkls23.NewScalar()
			jScalar.SetBytes(jBytes)

			numerator := dkls23.NewScalar()
			numerator.SetBytes([]byte{1})
			denominator := dkls23.NewScalar()
			denominator.SetBytes([]byte{1})

			for k := i; k < i+params.Threshold; k++ {
				if k != j {
					kBytes := []byte{k}
					kScalar := dkls23.NewScalar()
					kScalar.SetBytes(kBytes)

					numerator = dkls23.ScalarMul(numerator, kScalar)
					denominator = dkls23.ScalarMul(denominator, dkls23.ScalarSub(kScalar, jScalar))
				}
			}

			denomInv, err := dkls23.ScalarInvert(denominator)
			if err != nil {
				return nil, errors.New("lagrange coefficient: zero denominator in Step5")
			}
			lj := dkls23.ScalarMul(numerator, denomInv)

			// lj * committed_points[j]
			ljTimesPoint := dkls23.ScalarMult(committedPoints[j], lj)
			currentPK = dkls23.PointAdd(currentPK, ljTimesPoint)
		}

		if i == 1 {
			pk = currentPK
		} else if !dkls23.PointEqual(pk, currentPK) {
			return nil, errors.New("public key reconstruction verification failed")
		}
	}

	return pk, nil
}

// Phase1 executes DKG phase 1
func Phase1(data *SessionData) (*Phase1Output, error) {
	if err := data.ValidateSession(); err != nil {
		return nil, err
	}
	polynomial, err := Step1(&data.Parameters)
	if err != nil {
		return nil, err
	}
	points := Step2(&data.Parameters, polynomial)
	return &Phase1Output{PolyPoints: points}, nil
}

// Phase2 executes DKG phase 2
func Phase2(data *SessionData, polyFragments []group.Scalar) (*Phase2Output, error) {
	polyPoint, proofCommitment, err := Step3(data.PartyIndex, data.SessionID, polyFragments)
	if err != nil {
		return nil, err
	}

	// Initialize zero shares
	zeroKeep := make(map[uint8]*Phase2to3ZeroKeep)
	zeroTransmit := make([]*Phase2to4ZeroTransmit, 0, data.Parameters.ShareCount-1)

	for i := uint8(1); i <= data.Parameters.ShareCount; i++ {
		if i == data.PartyIndex {
			continue
		}

		seed, commitment, salt, err := GenerateZeroSeedWithCommitment()
		if err != nil {
			return nil, err
		}

		zeroKeep[i] = &Phase2to3ZeroKeep{
			Seed: seed,
			Salt: salt,
		}
		zeroTransmit = append(zeroTransmit, &Phase2to4ZeroTransmit{
			Sender:     data.PartyIndex,
			Receiver:   i,
			Commitment: commitment,
		})
	}

	return &Phase2Output{
		PolyPoint:       polyPoint,
		ProofCommitment: proofCommitment,
		ZeroKeep:        zeroKeep,
		ZeroTransmit:    zeroTransmit,
	}, nil
}

// Phase3 executes DKG phase 3
func Phase3(data *SessionData, zeroKept map[uint8]*Phase2to3ZeroKeep) (*Phase3Output, error) {
	// Zero shares: reveal seeds
	zeroKeep := make(map[uint8]*Phase3to4ZeroKeep)
	zeroTransmit := make([]*Phase3to4ZeroTransmit, 0, len(zeroKept))

	for targetParty, kept := range zeroKept {
		zeroKeep[targetParty] = &Phase3to4ZeroKeep{
			Seed: kept.Seed,
		}
		zeroTransmit = append(zeroTransmit, &Phase3to4ZeroTransmit{
			Sender:   data.PartyIndex,
			Receiver: targetParty,
			Seed:     kept.Seed,
			Salt:     kept.Salt,
		})
	}

	// Multiplication initialization
	mulKeep := make(map[uint8]*Phase3to4MulKeep)
	mulTransmit := make([]*Phase3to4MulTransmit, 0, data.Parameters.ShareCount-1)

	for i := uint8(1); i <= data.Parameters.ShareCount; i++ {
		if i == data.PartyIndex {
			continue
		}

		// As receiver (we = receiver, i = sender)
		mulSIDReceiver := buildMulSID(data.PartyIndex, i, data.SessionID)
		otSender, dlogProof, nonce, err := mta.InitReceiverPhase1(mulSIDReceiver)
		if err != nil {
			return nil, err
		}

		// As sender (we = sender, i = receiver)
		mulSIDSender := buildMulSID(i, data.PartyIndex, data.SessionID)
		otReceiver, correlation, vecR, encProofs, err := mta.InitSenderPhase1(mulSIDSender)
		if err != nil {
			return nil, err
		}

		mulKeep[i] = &Phase3to4MulKeep{
			OTSender:    otSender,
			Nonce:       nonce,
			OTReceiver:  otReceiver,
			Correlation: correlation,
			VecR:        vecR,
		}

		mulTransmit = append(mulTransmit, &Phase3to4MulTransmit{
			Sender:    data.PartyIndex,
			Receiver:  i,
			DLogProof: dlogProof,
			Nonce:     nonce,
			EncProofs: encProofs,
			Seed:      otReceiver.GetSeed(),
		})
	}

	return &Phase3Output{
		ZeroKeep:     zeroKeep,
		ZeroTransmit: zeroTransmit,
		MulKeep:      mulKeep,
		MulTransmit:  mulTransmit,
	}, nil
}

// Phase4 executes DKG phase 4 and returns a Party ready for signing
func Phase4(data *SessionData, input *Phase4Input) (*sign.Party, error) {
	// Step 5: Verify proofs and compute public key
	pk, err := Step5(&data.Parameters, data.PartyIndex, data.SessionID, input.ProofsCommitments)
	if err != nil {
		return nil, err
	}

	// Verify public key is not trivial
	if dkls23.IsIdentity(pk) {
		return nil, errors.New("public key is identity")
	}

	// Verify poly_point is not trivial
	if dkls23.IsZero(input.PolyPoint) {
		return nil, errors.New("key share is zero")
	}

	// Initialize zero shares
	zeroSeeds := make(map[uint8]*sign.ZeroSeedPair)
	for targetParty, kept := range input.ZeroKept {
		// Find corresponding received messages
		var received2 *Phase2to4ZeroTransmit
		var received3 *Phase3to4ZeroTransmit

		for _, msg := range input.ZeroReceived2 {
			if msg.Sender == targetParty && msg.Receiver == data.PartyIndex {
				received2 = msg
				break
			}
		}
		for _, msg := range input.ZeroReceived3 {
			if msg.Sender == targetParty && msg.Receiver == data.PartyIndex {
				received3 = msg
				break
			}
		}

		if received2 == nil || received3 == nil {
			continue
		}

		// Verify commitment
		if !VerifyZeroSeed(&received3.Seed, received2.Commitment, received3.Salt) {
			return nil, errors.New("zero seed commitment verification failed")
		}

		// Generate seed pair
		seedPair := GenerateZeroSeedPair(data.PartyIndex, targetParty, &kept.Seed, &received3.Seed)
		zeroSeeds[targetParty] = seedPair
	}

	// Initialize multiplication protocols
	mulReceivers := make(map[uint8]*mta.Receiver)
	mulSenders := make(map[uint8]*mta.Sender)

	for targetParty, kept := range input.MulKept {
		// Find corresponding received message
		var received *Phase3to4MulTransmit
		for _, msg := range input.MulReceived {
			if msg.Sender == targetParty && msg.Receiver == data.PartyIndex {
				received = msg
				break
			}
		}
		if received == nil {
			continue
		}

		// Initialize receiver (we = receiver, target = sender)
		mulSIDReceiver := buildMulSID(data.PartyIndex, targetParty, data.SessionID)
		mulReceiver, err := mta.InitReceiverPhase2(
			kept.OTSender,
			mulSIDReceiver,
			received.Seed,
			received.EncProofs,
			kept.Nonce,
		)
		if err != nil {
			return nil, err
		}

		// Initialize sender (we = sender, target = receiver)
		mulSIDSender := buildMulSID(targetParty, data.PartyIndex, data.SessionID)
		mulSender, err := mta.InitSenderPhase2(
			kept.OTReceiver,
			mulSIDSender,
			kept.Correlation,
			kept.VecR,
			received.DLogProof,
			received.Nonce,
		)
		if err != nil {
			return nil, err
		}

		mulReceivers[targetParty] = mulReceiver
		mulSenders[targetParty] = mulSender
	}

	party := &sign.Party{
		Index:        data.PartyIndex,
		Threshold:    data.Parameters.Threshold,
		Total:        data.Parameters.ShareCount,
		SessionID:    data.SessionID,
		KeyShare:     input.PolyPoint,
		PublicKey:    pk,
		ZeroSeeds:    zeroSeeds,
		MulSenders:   mulSenders,
		MulReceivers: mulReceivers,
	}

	return party, nil
}

func buildMulSID(receiver, sender uint8, sessionID []byte) []byte {
	sid := slices.Concat([]byte("Multiplication protocol"), []byte{receiver, sender}, sessionID)
	return sid
}
