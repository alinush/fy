package ot

import (
	"bytes"
	"errors"
	"slices"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

// OT Extension constants from DKLs23
const (
	// Kappa is the computational security parameter (256 bits)
	Kappa = dkls23.RawSecurity
	// OTSecurity is the statistical security for KOS (128 + 80 = 208 bits)
	OTSecurity = 128 + dkls23.StatSecurity
	// BatchSize is the number of OTs per extension (256 + 2*80 = 416)
	BatchSize = dkls23.RawSecurity + 2*dkls23.StatSecurity
	// ExtendedBatchSize is BatchSize + OTSecurity (416 + 208 = 624)
	ExtendedBatchSize = BatchSize + OTSecurity
)

// PRGOutput is the output of the pseudo-random generator
type PRGOutput = [ExtendedBatchSize / 8]byte

// FieldElement is an element in GF(2^OTSecurity)
type FieldElement = [OTSecurity / 8]byte

// ExtSender holds the OT extension sender's state
type ExtSender struct {
	Correlation []bool              // Choice bits (KAPPA bits)
	Seeds       []dkls23.HashOutput // Seeds from base OT
}

// ExtReceiver holds the OT extension receiver's state
type ExtReceiver struct {
	Seeds0 []dkls23.HashOutput // Seeds for bit=0
	Seeds1 []dkls23.HashOutput // Seeds for bit=1
}

// DataToSender is the data transmitted from receiver to sender
type DataToSender struct {
	U       []PRGOutput    // Matrix U (KAPPA rows)
	VerifyX FieldElement   // Verification value x
	VerifyT []FieldElement // Verification values t (KAPPA elements)
}

// InitExtSenderPhase1 starts the extension sender initialization
// Note: Extension sender acts as base OT receiver (roles reversed)
func InitExtSenderPhase1(sessionID []byte) (*Receiver, []bool, []group.Scalar, []*dkls23.EncProof, error) {
	otReceiver, err := NewReceiver()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Sample random correlation bits
	correlation := make([]bool, Kappa)
	randBytes, err := dkls23.RandBytes(Kappa / 8)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for i := 0; i < Kappa; i++ {
		correlation[i] = (randBytes[i/8]>>(i%8))&1 == 1
	}

	vecR, encProofs, err := otReceiver.Phase1Batch(sessionID, correlation)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return otReceiver, correlation, vecR, encProofs, nil
}

// InitExtSenderPhase2 finishes the extension sender initialization
func InitExtSenderPhase2(
	otReceiver *Receiver,
	sessionID []byte,
	correlation []bool,
	vecR []group.Scalar,
	dlogProof *dkls23.DLogProof,
) (*ExtSender, error) {
	seeds, err := otReceiver.Phase2Batch(sessionID, vecR, dlogProof)
	if err != nil {
		return nil, err
	}

	return &ExtSender{
		Correlation: correlation,
		Seeds:       seeds,
	}, nil
}

// InitExtReceiverPhase1 starts the extension receiver initialization
// Note: Extension receiver acts as base OT sender (roles reversed)
func InitExtReceiverPhase1(sessionID []byte) (*Sender, *dkls23.DLogProof, error) {
	otSender, err := NewSender(sessionID)
	if err != nil {
		return nil, nil, err
	}

	dlogProof := otSender.Phase1()
	return otSender, dlogProof, nil
}

// InitExtReceiverPhase2 finishes the extension receiver initialization
func InitExtReceiverPhase2(
	otSender *Sender,
	sessionID []byte,
	seed *Seed,
	encProofs []*dkls23.EncProof,
) (*ExtReceiver, error) {
	seeds0, seeds1, err := otSender.Phase2Batch(sessionID, seed, encProofs)
	if err != nil {
		return nil, err
	}

	return &ExtReceiver{
		Seeds0: seeds0,
		Seeds1: seeds1,
	}, nil
}

// RunPhase1 runs the first phase of the receiver's protocol
func (r *ExtReceiver) RunPhase1(sessionID []byte, choiceBits []bool) ([]PRGOutput, *DataToSender, error) {
	// Extend choice bits with random noise
	randomBits := make([]bool, OTSecurity)
	randBytes, err := dkls23.RandBytes(OTSecurity / 8)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < OTSecurity; i++ {
		randomBits[i] = (randBytes[i/8]>>(i%8))&1 == 1
	}
	extendedBits := append(choiceBits, randomBits...)

	// Compress extended bits to bytes
	compressedBits := bitsToBytes(extendedBits)

	// Extend seeds with PRG
	extSeeds0 := make([]PRGOutput, Kappa)
	extSeeds1 := make([]PRGOutput, Kappa)
	for i := 0; i < Kappa; i++ {
		extSeeds0[i] = prgExpand(r.Seeds0[i], uint16(i), sessionID)
		extSeeds1[i] = prgExpand(r.Seeds1[i], uint16(i), sessionID)
	}

	// Compute matrix U: u[i] = seed0[i] XOR seed1[i] XOR compressed_bits
	u := make([]PRGOutput, Kappa)
	for i := 0; i < Kappa; i++ {
		for j := 0; j < ExtendedBatchSize/8; j++ {
			u[i][j] = extSeeds0[i][j] ^ extSeeds1[i][j] ^ compressedBits[j]
		}
	}

	// Compute verification values using Fiat-Shamir
	msgConcat := make([]byte, 0, Kappa*len(u[0]))
	for i := 0; i < Kappa; i++ {
		msgConcat = append(msgConcat, u[i][:]...)
	}

	// Compute chi1 and chi2 (challenges)
	salt1 := slices.Concat([]byte{1}, sessionID)
	salt2 := slices.Concat([]byte{2}, sessionID)
	chi1Hash := dkls23.Hash(msgConcat, salt1)
	chi2Hash := dkls23.Hash(msgConcat, salt2)
	var chi1, chi2 FieldElement
	copy(chi1[:], chi1Hash[:OTSecurity/8])
	copy(chi2[:], chi2Hash[:OTSecurity/8])

	// Compute verify_x
	prodX1 := fieldMul(compressedBits[0:OTSecurity/8], chi1[:])
	prodX2 := fieldMul(compressedBits[OTSecurity/8:2*OTSecurity/8], chi2[:])
	var verifyX FieldElement
	for k := 0; k < OTSecurity/8; k++ {
		verifyX[k] = prodX1[k] ^ prodX2[k] ^ compressedBits[2*OTSecurity/8+k]
	}

	// Compute verify_t for each i
	verifyT := make([]FieldElement, Kappa)
	for i := 0; i < Kappa; i++ {
		prodT1 := fieldMul(extSeeds0[i][0:OTSecurity/8], chi1[:])
		prodT2 := fieldMul(extSeeds0[i][OTSecurity/8:2*OTSecurity/8], chi2[:])
		for k := 0; k < OTSecurity/8; k++ {
			verifyT[i][k] = prodT1[k] ^ prodT2[k] ^ extSeeds0[i][2*OTSecurity/8+k]
		}
	}

	return extSeeds0, &DataToSender{
		U:       u,
		VerifyX: verifyX,
		VerifyT: verifyT,
	}, nil
}

// RunPhase2 finishes the receiver's protocol
func (r *ExtReceiver) RunPhase2(
	sessionID []byte,
	otWidth uint8,
	choiceBits []bool,
	extendedSeeds []PRGOutput,
	vectorOfTau [][]group.Scalar,
) ([][]group.Scalar, error) {
	if len(vectorOfTau) != int(otWidth) {
		return nil, errors.New("vector of tau has wrong size")
	}

	// Transpose and cut
	transposedT := cutAndTranspose(extendedSeeds)

	// Compute v for each iteration
	vectorOfV := make([][]group.Scalar, otWidth)
	for iteration := uint8(0); iteration < otWidth; iteration++ {
		v := make([]group.Scalar, BatchSize)
		for j := 0; j < BatchSize; j++ {
			salt := buildSalt(uint16(j), sessionID, iteration)
			v[j] = dkls23.HashAsScalar(transposedT[j][:], salt)
		}
		vectorOfV[iteration] = v
	}

	// Compute t_B for each iteration
	vectorOfTB := make([][]group.Scalar, otWidth)
	for iteration := uint8(0); iteration < otWidth; iteration++ {
		v := vectorOfV[iteration]
		tau := vectorOfTau[iteration]
		tB := make([]group.Scalar, BatchSize)
		for j := 0; j < BatchSize; j++ {
			// t_b[j] = -v[j] if bit=0, or tau[j] - v[j] if bit=1
			tB[j] = dkls23.ScalarNeg(v[j])
			if choiceBits[j] {
				tB[j] = dkls23.ScalarAdd(tau[j], tB[j])
			}
		}
		vectorOfTB[iteration] = tB
	}

	return vectorOfTB, nil
}

// Run runs the sender's protocol
func (s *ExtSender) Run(
	sessionID []byte,
	otWidth uint8,
	inputCorrelations [][]group.Scalar,
	data *DataToSender,
) ([][]group.Scalar, [][]group.Scalar, error) {
	if len(inputCorrelations) != int(otWidth) {
		return nil, nil, errors.New("input correlations has wrong size")
	}

	// Extend seeds with PRG
	extendedSeeds := make([]PRGOutput, Kappa)
	for i := 0; i < Kappa; i++ {
		extendedSeeds[i] = prgExpand(s.Seeds[i], uint16(i), sessionID)
	}

	// Compute q: q[i] = correlation[i] * u[i] XOR extended_seeds[i]
	q := make([]PRGOutput, Kappa)
	for i := 0; i < Kappa; i++ {
		for j := 0; j < ExtendedBatchSize/8; j++ {
			var mask byte
			if s.Correlation[i] {
				mask = data.U[i][j]
			}
			q[i][j] = mask ^ extendedSeeds[i][j]
		}
	}

	// Consistency check using Fiat-Shamir
	msgConcat := make([]byte, 0, Kappa*len(data.U[0]))
	for i := 0; i < Kappa; i++ {
		msgConcat = append(msgConcat, data.U[i][:]...)
	}

	salt1 := slices.Concat([]byte{1}, sessionID)
	salt2 := slices.Concat([]byte{2}, sessionID)
	chi1Hash := dkls23.Hash(msgConcat, salt1)
	chi2Hash := dkls23.Hash(msgConcat, salt2)
	var chi1, chi2 FieldElement
	copy(chi1[:], chi1Hash[:OTSecurity/8])
	copy(chi2[:], chi2Hash[:OTSecurity/8])

	// Compute verify_q and verify_sender
	verifyQ := make([]FieldElement, Kappa)
	verifySender := make([]FieldElement, Kappa)
	for i := 0; i < Kappa; i++ {
		prodQ1 := fieldMul(q[i][0:OTSecurity/8], chi1[:])
		prodQ2 := fieldMul(q[i][OTSecurity/8:2*OTSecurity/8], chi2[:])
		for k := 0; k < OTSecurity/8; k++ {
			verifyQ[i][k] = prodQ1[k] ^ prodQ2[k] ^ q[i][2*OTSecurity/8+k]
		}

		for k := 0; k < OTSecurity/8; k++ {
			var mask byte
			if s.Correlation[i] {
				mask = data.VerifyX[k]
			}
			verifySender[i][k] = data.VerifyT[i][k] ^ mask
		}
	}

	// Verify consistency
	for i := 0; i < Kappa; i++ {
		if !bytes.Equal(verifyQ[i][:], verifySender[i][:]) {
			return nil, nil, errors.New("receiver cheated: consistency check failed")
		}
	}

	// Transpose and randomize
	transposedQ := cutAndTranspose(q)

	// Compress correlation
	compressedCorr := bitsToBytes(s.Correlation)

	// Compute v0 and v1 for each iteration
	vectorOfV0 := make([][]group.Scalar, otWidth)
	vectorOfV1 := make([][]group.Scalar, otWidth)
	for iteration := uint8(0); iteration < otWidth; iteration++ {
		v0 := make([]group.Scalar, BatchSize)
		v1 := make([]group.Scalar, BatchSize)
		for j := 0; j < BatchSize; j++ {
			// v1 needs q[j] XOR correlation
			qPlusCorr := make([]byte, Kappa/8)
			for k := 0; k < Kappa/8; k++ {
				qPlusCorr[k] = transposedQ[j][k] ^ compressedCorr[k]
			}

			salt := buildSalt(uint16(j), sessionID, iteration)
			v0[j] = dkls23.HashAsScalar(transposedQ[j][:], salt)
			v1[j] = dkls23.HashAsScalar(qPlusCorr, salt)
		}
		vectorOfV0[iteration] = v0
		vectorOfV1[iteration] = v1
	}

	// Transfer phase: compute tau
	vectorOfTau := make([][]group.Scalar, otWidth)
	for iteration := uint8(0); iteration < otWidth; iteration++ {
		v0 := vectorOfV0[iteration]
		v1 := vectorOfV1[iteration]
		corr := inputCorrelations[iteration]
		tau := make([]group.Scalar, BatchSize)
		for j := 0; j < BatchSize; j++ {
			// tau[j] = v1[j] - v0[j] + correlation[j]
			tau[j] = dkls23.ScalarAdd(dkls23.ScalarSub(v1[j], v0[j]), corr[j])
		}
		vectorOfTau[iteration] = tau
	}

	return vectorOfV0, vectorOfTau, nil
}

// Helper functions

func bitsToBytes(bits []bool) []byte {
	numBytes := (len(bits) + 7) / 8
	result := make([]byte, numBytes)
	for i, bit := range bits {
		if bit {
			result[i/8] |= 1 << (i % 8)
		}
	}
	return result
}

func prgExpand(seed dkls23.HashOutput, index uint16, sessionID []byte) PRGOutput {
	var result PRGOutput
	var count uint16
	pos := 0

	for pos < ExtendedBatchSize/8 {
		salt := slices.Concat(uint16ToBytes(index), uint16ToBytes(count))
		salt = slices.Concat(salt, sessionID)
		chunk := dkls23.Hash(seed[:], salt)
		remaining := ExtendedBatchSize/8 - pos
		if remaining > len(chunk) {
			remaining = len(chunk)
		}
		copy(result[pos:pos+remaining], chunk[:remaining])
		pos += remaining
		count++
	}

	return result
}

func cutAndTranspose(input []PRGOutput) [][Kappa / 8]byte {
	output := make([][Kappa / 8]byte, BatchSize)

	for rowByte := 0; rowByte < Kappa/8; rowByte++ {
		for rowBit := 0; rowBit < 8; rowBit++ {
			for colByte := 0; colByte < BatchSize/8; colByte++ {
				for colBit := 0; colBit < 8; colBit++ {
					rowIdx := rowByte*8 + rowBit
					colIdx := colByte*8 + colBit

					entry := (input[rowIdx][colByte] >> colBit) & 0x01
					shiftedEntry := entry << rowBit
					output[colIdx][rowByte] |= shiftedEntry
				}
			}
		}
	}

	return output
}

func buildSalt(j uint16, sessionID []byte, iteration uint8) []byte {
	salt := slices.Concat(uint16ToBytes(j), sessionID)
	salt = append(salt, []byte("Iteration number:")...)
	salt = append(salt, iteration)
	return salt
}

// fieldMul multiplies two elements in GF(2^OTSecurity)
// Uses the irreducible polynomial f(X) = X^208 + X^9 + X^3 + X + 1
func fieldMul(left, right []byte) []byte {
	const W = 64
	const T = 4

	if len(left) < OTSecurity/8 || len(right) < OTSecurity/8 {
		return make([]byte, OTSecurity/8)
	}

	a := make([]uint64, T)
	b := make([]uint64, T+1)
	c := make([]uint64, 2*T)

	// Convert bytes to uint64s (little-endian within the field)
	for i := 0; i < OTSecurity/8; i++ {
		a[i/8] |= uint64(left[i]) << ((i % 8) * 8)
		b[i/8] |= uint64(right[i]) << ((i % 8) * 8)
	}

	// Right-to-left comb method
	for k := 0; k < W; k++ {
		for j := 0; j < T; j++ {
			if (a[j]>>k)%2 == 1 {
				for i := 0; i <= T; i++ {
					c[j+i] ^= b[i]
				}
			}
		}
		if k != W-1 {
			for i := T; i > 0; i-- {
				b[i] = b[i]<<1 | b[i-1]>>63
			}
		}
		b[0] <<= 1
	}

	// Reduction modulo f(X) = X^208 + X^9 + X^3 + X + 1
	for i := 2*T - 1; i >= T; i-- {
		t := c[i]
		c[i-4] ^= (t << 57) ^ (t << 51) ^ (t << 49) ^ (t << 48)
		c[i-3] ^= (t >> 7) ^ (t >> 13) ^ (t >> 15) ^ (t >> 16)
		c[i] = 0
	}

	t := c[T-1] >> 16
	c[0] ^= (t << 9) ^ (t << 3) ^ (t << 1) ^ t
	c[T-1] &= 0xFFFF

	// Convert back to bytes
	result := make([]byte, OTSecurity/8)
	for i := 0; i < OTSecurity/8; i++ {
		result[i] = byte((c[i/8] >> ((i % 8) * 8)) & 0xFF)
	}

	return result
}
