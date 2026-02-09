// Package mta implements the Multiplicative-to-Additive conversion
// using Oblivious Transfer as described in DKLs23.
//
// This realizes Functionality 3.5 in DKLs23 (https://eprint.iacr.org/2023/765.pdf).
// It is based on Protocol 1 of DKLs19 (https://eprint.iacr.org/2019/523.pdf).
package mta

import (
	"bytes"
	"errors"
	"slices"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/ot"
	"github.com/f3rmion/fy/group"
)

// Constants from DKLs23
const (
	// L is the parameter from Functionality 3.5 in DKLs23 used for signing
	L = 2
	// OTWidth is the number of times OT extension is called (2 * L)
	OTWidth = 2 * L
)

// Sender holds the sender's state for the multiplication protocol
type Sender struct {
	PublicGadget []group.Scalar
	OTESender    *ot.ExtSender
}

// Receiver holds the receiver's state for the multiplication protocol
type Receiver struct {
	PublicGadget []group.Scalar
	OTEReceiver  *ot.ExtReceiver
}

// DataToReceiver is data transmitted from sender to receiver
type DataToReceiver struct {
	VectorOfTau [][]group.Scalar
	VerifyR     dkls23.HashOutput
	VerifyU     []group.Scalar
	GammaSender []group.Scalar
}

// DataToKeepReceiver is data kept by the receiver between phases
type DataToKeepReceiver struct {
	B             group.Scalar
	ChoiceBits    []bool
	ExtendedSeeds []ot.PRGOutput
	ChiTilde      []group.Scalar
	ChiHat        []group.Scalar
}

// ErrMul is returned when the multiplication protocol fails
var ErrMul = errors.New("multiplication protocol failed")

// InitSenderPhase1 starts the sender initialization
// Returns OT receiver state, correlation bits, scalars, and encryption proofs
func InitSenderPhase1(sessionID []byte) (*ot.Receiver, []bool, []group.Scalar, []*dkls23.EncProof, error) {
	return ot.InitExtSenderPhase1(sessionID)
}

// InitSenderPhase2 finishes the sender initialization
func InitSenderPhase2(
	otReceiver *ot.Receiver,
	sessionID []byte,
	correlation []bool,
	vecR []group.Scalar,
	dlogProof *dkls23.DLogProof,
	nonce group.Scalar,
) (*Sender, error) {
	oteSender, err := ot.InitExtSenderPhase2(otReceiver, sessionID, correlation, vecR, dlogProof)
	if err != nil {
		return nil, err
	}

	// Compute public gadget vector from the nonce
	publicGadget := computePublicGadget(nonce, sessionID)

	return &Sender{
		PublicGadget: publicGadget,
		OTESender:    oteSender,
	}, nil
}

// InitReceiverPhase1 starts the receiver initialization
// Returns OT sender state, DLog proof, and nonce for public gadget
func InitReceiverPhase1(sessionID []byte) (*ot.Sender, *dkls23.DLogProof, group.Scalar, error) {
	otSender, dlogProof, err := ot.InitExtReceiverPhase1(sessionID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sample nonce for public gadget vector
	nonce, err := dkls23.RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}

	return otSender, dlogProof, nonce, nil
}

// InitReceiverPhase2 finishes the receiver initialization
func InitReceiverPhase2(
	otSender *ot.Sender,
	sessionID []byte,
	seed *ot.Seed,
	encProofs []*dkls23.EncProof,
	nonce group.Scalar,
) (*Receiver, error) {
	oteReceiver, err := ot.InitExtReceiverPhase2(otSender, sessionID, seed, encProofs)
	if err != nil {
		return nil, err
	}

	// Compute public gadget vector from the nonce
	publicGadget := computePublicGadget(nonce, sessionID)

	return &Receiver{
		PublicGadget: publicGadget,
		OTEReceiver:  oteReceiver,
	}, nil
}

// computePublicGadget derives the public gadget vector from a nonce
func computePublicGadget(nonce group.Scalar, sessionID []byte) []group.Scalar {
	gadget := make([]group.Scalar, ot.BatchSize)
	one := dkls23.NewScalar()
	one.SetBytes([]byte{1})

	counter := dkls23.NewScalar().Set(nonce)
	for i := 0; i < ot.BatchSize; i++ {
		counter = dkls23.ScalarAdd(counter, one)
		counterBytes := counter.Bytes()
		gadget[i] = dkls23.HashAsScalar(counterBytes, sessionID)
	}
	return gadget
}

// Run executes the sender's protocol
// Input: L scalars (sender's input) and OT data from receiver
// Output: L scalars (sender's output) and data for receiver
func (s *Sender) Run(
	sessionID []byte,
	input []group.Scalar,
	data *ot.DataToSender,
) ([]group.Scalar, *DataToReceiver, error) {
	if len(input) != L {
		return nil, nil, errors.New("input must have L elements")
	}

	// Step 2: Sample pads a_tilde and check values a_hat
	aTilde := make([]group.Scalar, L)
	aHat := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		var err error
		aTilde[i], err = dkls23.RandomScalar()
		if err != nil {
			return nil, nil, err
		}
		aHat[i], err = dkls23.RandomScalar()
		if err != nil {
			return nil, nil, err
		}
	}

	// Create correlations: L copies of a_tilde, then L copies of a_hat
	correlations := make([][]group.Scalar, OTWidth)
	for i := 0; i < L; i++ {
		correlations[i] = make([]group.Scalar, ot.BatchSize)
		for j := 0; j < ot.BatchSize; j++ {
			correlations[i][j] = aTilde[i]
		}
	}
	for i := 0; i < L; i++ {
		correlations[L+i] = make([]group.Scalar, ot.BatchSize)
		for j := 0; j < ot.BatchSize; j++ {
			correlations[L+i][j] = aHat[i]
		}
	}

	// Step 3: Execute OT extension
	oteSID := slices.Concat([]byte("OT Extension protocol"), sessionID)
	vectorOfV0, vectorOfTau, err := s.OTESender.Run(oteSID, OTWidth, correlations, data)
	if err != nil {
		return nil, nil, err
	}

	// Split outputs: first L are z_tilde, next L are z_hat
	zTilde := vectorOfV0[:L]
	zHat := vectorOfV0[L:]

	// Step 4: Compute shared random values
	transcript := buildTranscript(data)
	chiTilde := make([]group.Scalar, L)
	chiHat := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		saltTilde := slices.Concat([]byte{1, byte(i)}, sessionID)
		saltHat := slices.Concat([]byte{2, byte(i)}, sessionID)
		chiTilde[i] = dkls23.HashAsScalar(transcript, saltTilde)
		chiHat[i] = dkls23.HashAsScalar(transcript, saltHat)
	}

	// Step 5: Compute verification values
	var rowsR bytes.Buffer
	verifyU := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		for j := 0; j < ot.BatchSize; j++ {
			// entry = chi_tilde[i] * z_tilde[i][j] + chi_hat[i] * z_hat[i][j]
			term1 := dkls23.ScalarMul(chiTilde[i], zTilde[i][j])
			term2 := dkls23.ScalarMul(chiHat[i], zHat[i][j])
			entry := dkls23.ScalarAdd(term1, term2)
			rowsR.Write(entry.Bytes())
		}
		// u[i] = chi_tilde[i] * a_tilde[i] + chi_hat[i] * a_hat[i]
		term1 := dkls23.ScalarMul(chiTilde[i], aTilde[i])
		term2 := dkls23.ScalarMul(chiHat[i], aHat[i])
		verifyU[i] = dkls23.ScalarAdd(term1, term2)
	}
	verifyR := dkls23.Hash(rowsR.Bytes(), sessionID)

	// Step 7: Compute gamma (difference)
	gamma := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		gamma[i] = dkls23.ScalarSub(input[i], aTilde[i])
	}

	// Step 8: Compute output
	output := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		sum := dkls23.NewScalar()
		for j := 0; j < ot.BatchSize; j++ {
			prod := dkls23.ScalarMul(s.PublicGadget[j], zTilde[i][j])
			sum = dkls23.ScalarAdd(sum, prod)
		}
		output[i] = sum
	}

	dataToReceiver := &DataToReceiver{
		VectorOfTau: vectorOfTau,
		VerifyR:     verifyR,
		VerifyU:     verifyU,
		GammaSender: gamma,
	}

	return output, dataToReceiver, nil
}

// RunPhase1 runs the first phase of the receiver's protocol
// Returns: random factor b, data to keep, data for sender, and an error
func (r *Receiver) RunPhase1(sessionID []byte) (group.Scalar, *DataToKeepReceiver, *ot.DataToSender, error) {
	// Step 1: Sample choice bits and compute b
	choiceBits := make([]bool, ot.BatchSize)
	randBytes, err := dkls23.RandBytes(ot.BatchSize / 8)
	if err != nil {
		return nil, nil, nil, err
	}
	b := dkls23.NewScalar()
	for i := 0; i < ot.BatchSize; i++ {
		choiceBits[i] = (randBytes[i/8]>>(i%8))&1 == 1
		if choiceBits[i] {
			b = dkls23.ScalarAdd(b, r.PublicGadget[i])
		}
	}

	// Step 3: Start OT extension
	oteSID := slices.Concat([]byte("OT Extension protocol"), sessionID)
	extendedSeeds, dataToSender, err := r.OTEReceiver.RunPhase1(oteSID, choiceBits)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 4: Compute shared random values
	transcript := buildTranscript(dataToSender)
	chiTilde := make([]group.Scalar, L)
	chiHat := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		saltTilde := slices.Concat([]byte{1, byte(i)}, sessionID)
		saltHat := slices.Concat([]byte{2, byte(i)}, sessionID)
		chiTilde[i] = dkls23.HashAsScalar(transcript, saltTilde)
		chiHat[i] = dkls23.HashAsScalar(transcript, saltHat)
	}

	dataToKeep := &DataToKeepReceiver{
		B:             b,
		ChoiceBits:    choiceBits,
		ExtendedSeeds: extendedSeeds,
		ChiTilde:      chiTilde,
		ChiHat:        chiHat,
	}

	return b, dataToKeep, dataToSender, nil
}

// RunPhase2 finishes the receiver's protocol
// Returns: L output scalars
func (r *Receiver) RunPhase2(
	sessionID []byte,
	dataKept *DataToKeepReceiver,
	dataReceived *DataToReceiver,
) ([]group.Scalar, error) {
	// Step 3 (Conclusion): Finish OT extension
	oteSID := slices.Concat([]byte("OT Extension protocol"), sessionID)
	otOutputs, err := r.OTEReceiver.RunPhase2(
		oteSID,
		OTWidth,
		dataKept.ChoiceBits,
		dataKept.ExtendedSeeds,
		dataReceived.VectorOfTau,
	)
	if err != nil {
		return nil, err
	}

	// Split outputs: first L are z_tilde, next L are z_hat
	zTilde := otOutputs[:L]
	zHat := otOutputs[L:]

	// Step 6: Verify consistency
	var rowsR bytes.Buffer
	for i := 0; i < L; i++ {
		for j := 0; j < ot.BatchSize; j++ {
			// entry = -(chi_tilde[i] * z_tilde[i][j]) - (chi_hat[i] * z_hat[i][j])
			term1 := dkls23.ScalarMul(dataKept.ChiTilde[i], zTilde[i][j])
			term2 := dkls23.ScalarMul(dataKept.ChiHat[i], zHat[i][j])
			entry := dkls23.ScalarNeg(dkls23.ScalarAdd(term1, term2))
			if dataKept.ChoiceBits[j] {
				entry = dkls23.ScalarAdd(entry, dataReceived.VerifyU[i])
			}
			rowsR.Write(entry.Bytes())
		}
	}
	expectedVerifyR := dkls23.Hash(rowsR.Bytes(), sessionID)

	if expectedVerifyR != dataReceived.VerifyR {
		return nil, errors.New("sender cheated: consistency check failed")
	}

	// Step 8: Compute output
	output := make([]group.Scalar, L)
	for i := 0; i < L; i++ {
		sum := dkls23.NewScalar()
		for j := 0; j < ot.BatchSize; j++ {
			prod := dkls23.ScalarMul(r.PublicGadget[j], zTilde[i][j])
			sum = dkls23.ScalarAdd(sum, prod)
		}
		// output[i] = b * gamma_sender[i] + sum
		bGamma := dkls23.ScalarMul(dataKept.B, dataReceived.GammaSender[i])
		output[i] = dkls23.ScalarAdd(bGamma, sum)
	}

	return output, nil
}

// buildTranscript creates the transcript for Fiat-Shamir
func buildTranscript(data *ot.DataToSender) []byte {
	var buf bytes.Buffer
	for i := 0; i < len(data.U); i++ {
		buf.Write(data.U[i][:])
	}
	buf.Write(data.VerifyX[:])
	for i := 0; i < len(data.VerifyT); i++ {
		buf.Write(data.VerifyT[i][:])
	}
	return buf.Bytes()
}
