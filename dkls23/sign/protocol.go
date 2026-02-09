package sign

import (
	"errors"
	"math/big"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

// Phase1 executes signing phase 1 (Steps 4, 5, 6 from Protocol 3.6)
func (p *Party) Phase1(data *SignData) (
	*UniqueKeep1to2,
	map[uint8]*Phase1ToPhase2Keep,
	[]*Phase1ToPhase2Transmit,
	error,
) {
	// Step 4: Verify threshold
	if len(data.Counterparties) != int(p.Threshold-1) {
		return nil, nil, nil, errors.New("wrong number of counterparties")
	}

	// Step 5: Sample secret data
	instanceKey, err := dkls23.RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}
	inversionMask, err := dkls23.RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}
	instancePoint := dkls23.ScalarBaseMult(instanceKey)

	// Step 6: Prepare messages for each counterparty
	keep := make(map[uint8]*Phase1ToPhase2Keep)
	transmit := make([]*Phase1ToPhase2Transmit, 0, len(data.Counterparties))

	for _, counterparty := range data.Counterparties {
		// Commit to instance point
		commitment, salt, err := dkls23.CommitPoint(instancePoint)
		if err != nil {
			return nil, nil, nil, err
		}

		// Start multiplication protocol as receiver
		mulSID := buildMulSessionID(p.Index, counterparty, p.SessionID, data.SignID)

		mulReceiver := p.MulReceivers[counterparty]
		chi, mulKeep, mulData, err := mulReceiver.RunPhase1(mulSID)
		if err != nil {
			return nil, nil, nil, err
		}

		keep[counterparty] = &Phase1ToPhase2Keep{
			Salt:    salt,
			Chi:     chi,
			MulKeep: mulKeep,
		}
		transmit = append(transmit, &Phase1ToPhase2Transmit{
			Sender:     p.Index,
			Receiver:   counterparty,
			Commitment: commitment,
			MulData:    mulData,
		})
	}

	// Compute zero share
	zeroSID := append([]byte("Zero shares protocol"), p.SessionID...)
	zeroSID = append(zeroSID, data.SignID...)
	zeta := p.ComputeZeroShare(data.Counterparties, zeroSID)

	uniqueKeep := &UniqueKeep1to2{
		InstanceKey:   instanceKey,
		InstancePoint: instancePoint,
		InversionMask: inversionMask,
		Zeta:          zeta,
	}

	return uniqueKeep, keep, transmit, nil
}

// Phase2 executes signing phase 2 (Step 7 from Protocol 3.6)
func (p *Party) Phase2(
	data *SignData,
	uniqueKept *UniqueKeep1to2,
	kept map[uint8]*Phase1ToPhase2Keep,
	received []*Phase1ToPhase2Transmit,
) (
	*UniqueKeep2to3,
	map[uint8]*Phase2ToPhase3Keep,
	[]*Phase2ToPhase3Transmit,
	error,
) {
	// Compute Lagrange coefficient
	lagrange, err := computeLagrangeCoeff(p.Index, data.Counterparties)
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute key share and public share
	// keyShare = polyPoint * lagrange + zeta
	keyShare := dkls23.ScalarAdd(dkls23.ScalarMul(p.KeyShare, lagrange), uniqueKept.Zeta)
	publicShare := dkls23.ScalarBaseMult(keyShare)

	// Input for multiplication: [instanceKey, keyShare]
	input := []group.Scalar{uniqueKept.InstanceKey, keyShare}

	keep := make(map[uint8]*Phase2ToPhase3Keep)
	transmit := make([]*Phase2ToPhase3Transmit, 0, len(received))

	for _, msg := range received {
		counterparty := msg.Sender
		currentKept := kept[counterparty]

		// Continue multiplication as sender (roles reversed)
		mulSID := buildMulSessionID(counterparty, p.Index, p.SessionID, data.SignID)

		mulSender := p.MulSenders[counterparty]
		cValues, mulDataToReceiver, err := mulSender.Run(mulSID, input, msg.MulData)
		if err != nil {
			return nil, nil, nil, err
		}

		cU := cValues[0]
		cV := cValues[1]

		// Compute gamma values
		gammaU := dkls23.ScalarBaseMult(cU)
		gammaV := dkls23.ScalarBaseMult(cV)

		// Compute psi
		psi := dkls23.ScalarSub(uniqueKept.InversionMask, currentKept.Chi)

		keep[counterparty] = &Phase2ToPhase3Keep{
			CU:         cU,
			CV:         cV,
			Commitment: msg.Commitment,
			MulKeep:    currentKept.MulKeep,
			Chi:        currentKept.Chi,
		}
		transmit = append(transmit, &Phase2ToPhase3Transmit{
			Sender:        p.Index,
			Receiver:      counterparty,
			GammaU:        gammaU,
			GammaV:        gammaV,
			Psi:           psi,
			PublicShare:   publicShare,
			InstancePoint: uniqueKept.InstancePoint,
			Salt:          currentKept.Salt,
			MulData:       mulDataToReceiver,
		})
	}

	uniqueKeep := &UniqueKeep2to3{
		InstanceKey:   uniqueKept.InstanceKey,
		InstancePoint: uniqueKept.InstancePoint,
		InversionMask: uniqueKept.InversionMask,
		KeyShare:      keyShare,
		PublicShare:   publicShare,
	}

	return uniqueKeep, keep, transmit, nil
}

// Phase3 executes signing phase 3 (Steps 8, 9 from Protocol 3.6)
func (p *Party) Phase3(
	data *SignData,
	uniqueKept *UniqueKeep2to3,
	kept map[uint8]*Phase2ToPhase3Keep,
	received []*Phase2ToPhase3Transmit,
) ([]byte, *Phase3Broadcast, error) {
	// Initialize sums
	expectedPublicKey := uniqueKept.PublicShare
	totalInstancePoint := uniqueKept.InstancePoint

	firstSumUV := uniqueKept.InversionMask

	secondSumU := dkls23.NewScalar()
	secondSumV := dkls23.NewScalar()

	for _, msg := range received {
		counterparty := msg.Sender
		currentKept := kept[counterparty]

		// Verify commitment
		if !dkls23.VerifyCommitmentPoint(msg.InstancePoint, currentKept.Commitment, msg.Salt) {
			return nil, nil, errors.New("commitment verification failed")
		}

		// Finish multiplication as receiver (roles reversed again)
		mulSID := buildMulSessionID(p.Index, counterparty, p.SessionID, data.SignID)

		mulReceiver := p.MulReceivers[counterparty]
		dValues, err := mulReceiver.RunPhase2(mulSID, currentKept.MulKeep, msg.MulData)
		if err != nil {
			return nil, nil, err
		}

		dU := dValues[0]
		dV := dValues[1]

		// Consistency checks
		// Check: instancePoint * chi == G * dU + gammaU
		lhs := dkls23.ScalarMult(msg.InstancePoint, currentKept.Chi)
		rhs := dkls23.PointAdd(dkls23.ScalarBaseMult(dU), msg.GammaU)
		if !dkls23.PointEqual(lhs, rhs) {
			return nil, nil, errors.New("u-variable consistency check failed")
		}

		// Check: publicShare * chi == G * dV + gammaV
		lhs = dkls23.ScalarMult(msg.PublicShare, currentKept.Chi)
		rhs = dkls23.PointAdd(dkls23.ScalarBaseMult(dV), msg.GammaV)
		if !dkls23.PointEqual(lhs, rhs) {
			return nil, nil, errors.New("v-variable consistency check failed")
		}

		// Update sums
		expectedPublicKey = dkls23.PointAdd(expectedPublicKey, msg.PublicShare)
		totalInstancePoint = dkls23.PointAdd(totalInstancePoint, msg.InstancePoint)

		firstSumUV = dkls23.ScalarAdd(firstSumUV, msg.Psi)

		secondSumU = dkls23.ScalarAdd(secondSumU, dkls23.ScalarAdd(currentKept.CU, dU))
		secondSumV = dkls23.ScalarAdd(secondSumV, dkls23.ScalarAdd(currentKept.CV, dV))
	}

	// Verify public key reconstruction
	if !dkls23.PointEqual(expectedPublicKey, p.PublicKey) {
		return nil, nil, errors.New("public key reconstruction failed")
	}

	// Check instance point is not identity
	if dkls23.IsIdentity(totalInstancePoint) {
		return nil, nil, errors.New("instance point is identity (very improbable)")
	}

	// Get compressed point (33 bytes: 1 byte parity + 32 bytes x-coordinate)
	// The parity byte (0x02=even, 0x03=odd) is needed for recovery ID
	compressedR := dkls23.PointToBytes(totalInstancePoint)
	xCoord := compressedR[1:33]

	// Compute u, v, w
	// u = instanceKey * firstSumUV + secondSumU
	u := dkls23.ScalarAdd(dkls23.ScalarMul(uniqueKept.InstanceKey, firstSumUV), secondSumU)

	// v = keyShare * firstSumUV + secondSumV
	v := dkls23.ScalarAdd(dkls23.ScalarMul(uniqueKept.KeyShare, firstSumUV), secondSumV)

	// w = messageHash * inversionMask + v * r
	// In ECDSA, r is the x-coordinate used directly as a scalar (mod n), NOT hashed
	// ScalarFromBytes performs modular reduction via secp256k1 SetBytes.
	// xCoord (32 bytes from compressed point) and msgHash (32 bytes from SHA-256)
	// are always valid inputs. Values >= group order are reduced mod n, matching
	// standard ECDSA behavior (see SEC 1 v2, Section 4.1.3).
	xScalar, _ := dkls23.ScalarFromBytes(xCoord)
	msgScalar, _ := dkls23.ScalarFromBytes(data.MessageHash[:])
	w := dkls23.ScalarAdd(
		dkls23.ScalarMul(msgScalar, uniqueKept.InversionMask),
		dkls23.ScalarMul(v, xScalar),
	)

	broadcast := &Phase3Broadcast{U: u, W: w}

	// Return full compressed point (33 bytes) so Phase4 can extract y-parity for recovery ID
	return compressedR, broadcast, nil
}

// Phase4 executes signing phase 4 (Step 10 from Protocol 3.6)
// compressedR is the 33-byte compressed nonce point (parity byte + 32-byte x-coordinate)
func (p *Party) Phase4(
	data *SignData,
	compressedR []byte,
	received []*Phase3Broadcast,
	normalize bool,
) (*Signature, error) {
	// Extract x-coordinate and y-parity from compressed point
	if len(compressedR) != 33 {
		return nil, errors.New("compressedR must be 33 bytes")
	}
	parityByte := compressedR[0]
	xCoord := compressedR[1:33]

	// Sum all u and w values
	numerator := dkls23.NewScalar()
	denominator := dkls23.NewScalar()

	for _, msg := range received {
		numerator = dkls23.ScalarAdd(numerator, msg.W)
		denominator = dkls23.ScalarAdd(denominator, msg.U)
	}

	// s = w / u
	denominatorInv, err := dkls23.ScalarInvert(denominator)
	if err != nil {
		return nil, err
	}
	s := dkls23.ScalarMul(numerator, denominatorInv)

	// Compute recovery ID from y-parity BEFORE normalization
	// Recovery ID: 0 if y is even (parity byte 0x02), 1 if y is odd (parity byte 0x03)
	var recoveryID uint8 = 0
	if parityByte == 0x03 {
		recoveryID = 1
	}

	// Normalize to low S form if requested
	// When we negate S, we also need to flip the recovery ID
	if normalize {
		sBytes := s.Bytes()
		halfOrder := new(big.Int).Rsh(secp256k1Order(), 1)
		sInt := new(big.Int).SetBytes(sBytes)
		if sInt.Cmp(halfOrder) > 0 {
			// s = n - s
			s = dkls23.ScalarNeg(s)
			// Flip recovery ID when negating S
			recoveryID ^= 1
		}
	}

	// Verify signature
	if !verifyECDSA(data.MessageHash, p.PublicKey, xCoord, s) {
		return nil, errors.New("invalid ECDSA signature")
	}

	var rBytes, sBytes [32]byte
	copy(rBytes[:], xCoord)
	copy(sBytes[:], s.Bytes())

	return &Signature{
		R:          rBytes,
		S:          sBytes,
		RecoveryID: recoveryID,
	}, nil
}

// Helper functions

func buildMulSessionID(sender, receiver uint8, sessionID, signID []byte) []byte {
	sid := []byte("Multiplication protocol")
	sid = append(sid, sender, receiver)
	sid = append(sid, sessionID...)
	sid = append(sid, signID...)
	return sid
}

func computeLagrangeCoeff(partyIndex uint8, counterparties []uint8) (group.Scalar, error) {
	numerator := dkls23.NewScalar()
	denominator := dkls23.NewScalar()
	one := dkls23.NewScalar()
	one.SetBytes([]byte{1})
	numerator.Set(one)
	denominator.Set(one)

	for _, cp := range counterparties {
		cpScalar := dkls23.NewScalar()
		cpScalar.SetBytes([]byte{cp})

		partyScalar := dkls23.NewScalar()
		partyScalar.SetBytes([]byte{partyIndex})

		numerator = dkls23.ScalarMul(numerator, cpScalar)
		denominator = dkls23.ScalarMul(denominator, dkls23.ScalarSub(cpScalar, partyScalar))
	}

	denomInv, err := dkls23.ScalarInvert(denominator)
	if err != nil {
		return nil, errors.New("lagrange coefficient: zero denominator (duplicate party indices?)")
	}
	return dkls23.ScalarMul(numerator, denomInv), nil
}

var secp256k1OrderValue = func() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("failed to parse secp256k1 order")
	}
	return n
}()

func secp256k1Order() *big.Int {
	return secp256k1OrderValue
}

func verifyECDSA(msgHash dkls23.HashOutput, pk group.Point, rBytes []byte, s group.Scalar) bool {
	// Parse r and verify range
	r := new(big.Int).SetBytes(rBytes)
	n := secp256k1Order()
	if r.Cmp(big.NewInt(0)) <= 0 || r.Cmp(n) >= 0 {
		return false
	}

	sBytes := s.Bytes()
	sInt := new(big.Int).SetBytes(sBytes)
	if sInt.Cmp(big.NewInt(0)) <= 0 || sInt.Cmp(n) >= 0 {
		return false
	}

	// Compute s^-1
	sInv, err := dkls23.ScalarInvert(s)
	if err != nil {
		return false
	}

	// Compute u1 = msgHash * s^-1, u2 = r * s^-1
	// ScalarFromBytes performs modular reduction via secp256k1 SetBytes.
	// Hash outputs and x-coordinates (32 bytes each) are always valid inputs.
	msgScalar, _ := dkls23.ScalarFromBytes(msgHash[:])
	rScalar, _ := dkls23.ScalarFromBytes(rBytes)

	u1 := dkls23.ScalarMul(msgScalar, sInv)
	u2 := dkls23.ScalarMul(rScalar, sInv)

	// Compute R = u1 * G + u2 * pk
	point := dkls23.PointAdd(dkls23.ScalarBaseMult(u1), dkls23.ScalarMult(pk, u2))

	if dkls23.IsIdentity(point) {
		return false
	}

	// Compare x-coordinate
	pointBytes := dkls23.PointToBytes(point)
	pointX := pointBytes[1:33]

	return new(big.Int).SetBytes(pointX).Cmp(r) == 0
}
