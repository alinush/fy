package golden

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"

	"github.com/f3rmion/fy/group"
)

// maxProofSize is the maximum allowed size for a serialized PLONK proof.
// BN254 PLONK proofs are typically ~600 bytes; 4096 gives ample headroom.
const maxProofSize = 4096

var (
	evrfSetupOnce sync.Once
	evrfCCS       constraint.ConstraintSystem
	evrfPK        plonk.ProvingKey
	evrfVK        plonk.VerifyingKey
	evrfSetupErr  error
)

// initEVRFKeys compiles the eVRF circuit and generates PLONK keys.
// Called once via sync.Once. Uses unsafekzg SRS for the POC.
//
// WARNING: The unsafekzg SRS has known toxic waste. This breaks proof soundness
// in an adversarial setting. For production, replace with a trusted setup ceremony
// or universal SRS. See https://docs.gnark.consensys.io/HowTo/setup for guidance.
func initEVRFKeys() {
	evrfSetupOnce.Do(func() {
		// Compile the circuit.
		evrfCCS, evrfSetupErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			scs.NewBuilder,
			&EVRFCircuit{},
		)
		if evrfSetupErr != nil {
			evrfSetupErr = fmt.Errorf("golden: compiling eVRF circuit: %w", evrfSetupErr)
			return
		}

		// Generate SRS (unsafe, for testing/POC only -- toxic waste is known).
		canonical, lagrange, err := unsafekzg.NewSRS(evrfCCS)
		if err != nil {
			evrfSetupErr = fmt.Errorf("golden: generating KZG SRS: %w", err)
			return
		}

		// PLONK setup.
		evrfPK, evrfVK, err = plonk.Setup(evrfCCS, canonical, lagrange)
		if err != nil {
			evrfSetupErr = fmt.Errorf("golden: PLONK setup: %w", err)
			return
		}
	})
}

// bjjPointCoords extracts the (X, Y) coordinates from a BJJ group.Point
// as big.Int values. BJJ coordinates are in BN254 Fr (native field).
func bjjPointCoords(p group.Point) (x, y *big.Int) {
	// BJJ Point has UncompressedBytes() returning 64 bytes: X || Y
	type uncompressor interface {
		UncompressedBytes() []byte
	}
	uc, ok := p.(uncompressor)
	if !ok {
		panic("golden: bjjPointCoords: point does not implement UncompressedBytes")
	}
	data := uc.UncompressedBytes()
	x = new(big.Int).SetBytes(data[0:32])
	y = new(big.Int).SetBytes(data[32:64])
	return
}

// g1PointCoords extracts the (X, Y) coordinates from a BN254 G1 group.Point
// as big.Int values. G1 coordinates are in BN254 Fp (base field).
func g1PointCoords(p group.Point) (x, y *big.Int) {
	// BN254 G1 Point.Bytes() returns Marshal() = 64 bytes: X || Y (uncompressed).
	data := p.Bytes()
	x = new(big.Int).SetBytes(data[0:32])
	y = new(big.Int).SetBytes(data[32:64])
	return
}

// generateEVRFProofPLONK generates a PLONK proof for the eVRF circuit.
func generateEVRFProofPLONK(
	bjjGroup group.Group,
	_ group.Group,
	dealerSK group.Scalar,
	dealerPK group.Point,
	recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	padResult *PadResult,
) ([]byte, error) {
	// Ensure keys are initialized.
	initEVRFKeys()
	if evrfSetupErr != nil {
		return nil, evrfSetupErr
	}

	// Extract BJJ point coordinates.
	dealerPKX, dealerPKY := bjjPointCoords(dealerPK)
	recipientPKX, recipientPKY := bjjPointCoords(recipientPK)

	// Compute H1, H2 from session data.
	h1, err := H1(bjjGroup, sessionData...)
	if err != nil {
		return nil, fmt.Errorf("golden: H1 for proof: %w", err)
	}
	h2, err := H2(bjjGroup, sessionData...)
	if err != nil {
		return nil, fmt.Errorf("golden: H2 for proof: %w", err)
	}
	h1X, h1Y := bjjPointCoords(h1)
	h2X, h2Y := bjjPointCoords(h2)

	// Alpha as big.Int.
	alphaBigInt := new(big.Int).SetBytes(alpha.Bytes())

	// R commitment coordinates (BN254 G1 Fp coordinates).
	rX, rY := g1PointCoords(padResult.RCommitment)

	// Dealer SK as big.Int. Zero after witness creation.
	skBigInt := new(big.Int).SetBytes(dealerSK.Bytes())

	// Construct the full witness assignment.
	assignment := &EVRFCircuit{
		DealerPKX:    dealerPKX,
		DealerPKY:    dealerPKY,
		RecipientPKX: recipientPKX,
		RecipientPKY: recipientPKY,
		H1X:          h1X,
		H1Y:          h1Y,
		H2X:          h2X,
		H2Y:          h2Y,
		Alpha:        alphaBigInt,
		R: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](rX),
			Y: emulated.ValueOf[emulated.BN254Fp](rY),
		},
		DealerSK: skBigInt,
	}

	// Create the witness.
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	// Zero the secret key big.Int immediately after witness creation.
	// Overwrite the backing array words before resetting, since SetInt64(0) only
	// sets the length to zero without clearing the underlying memory.
	skWords := skBigInt.Bits()
	for i := range skWords {
		skWords[i] = 0
	}
	skBigInt.SetInt64(0)

	if err != nil {
		return nil, fmt.Errorf("golden: creating witness: %w", err)
	}

	// Generate the proof.
	proof, err := plonk.Prove(evrfCCS, evrfPK, witness)
	if err != nil {
		return nil, fmt.Errorf("golden: PLONK prove: %w", err)
	}

	// Serialize the proof.
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("golden: serializing proof: %w", err)
	}

	return buf.Bytes(), nil
}

// verifyEVRFProofPLONK verifies a PLONK proof for the eVRF circuit.
func verifyEVRFProofPLONK(
	bjjGroup group.Group,
	_ group.Group,
	dealerPK group.Point,
	recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	rCommitment group.Point,
	proofBytes []byte,
) error {
	// Check proof size before any processing.
	if len(proofBytes) > maxProofSize {
		return ErrProofTooLarge
	}

	// Ensure keys are initialized.
	initEVRFKeys()
	if evrfSetupErr != nil {
		return evrfSetupErr
	}

	// Extract BJJ point coordinates for public inputs.
	dealerPKX, dealerPKY := bjjPointCoords(dealerPK)
	recipientPKX, recipientPKY := bjjPointCoords(recipientPK)

	// Compute H1, H2 from session data.
	h1, err := H1(bjjGroup, sessionData...)
	if err != nil {
		return fmt.Errorf("golden: H1 for verify: %w", err)
	}
	h2, err := H2(bjjGroup, sessionData...)
	if err != nil {
		return fmt.Errorf("golden: H2 for verify: %w", err)
	}
	h1X, h1Y := bjjPointCoords(h1)
	h2X, h2Y := bjjPointCoords(h2)

	// Alpha as big.Int.
	alphaBigInt := new(big.Int).SetBytes(alpha.Bytes())

	// R commitment coordinates.
	rX, rY := g1PointCoords(rCommitment)

	// Construct the witness assignment with all fields populated.
	// gnark requires all fields (including private) to be non-nil when creating
	// the witness object. We set DealerSK to a dummy value; it gets stripped
	// when we extract the public witness below.
	assignment := &EVRFCircuit{
		DealerPKX:    dealerPKX,
		DealerPKY:    dealerPKY,
		RecipientPKX: recipientPKX,
		RecipientPKY: recipientPKY,
		H1X:          h1X,
		H1Y:          h1Y,
		H2X:          h2X,
		H2Y:          h2Y,
		Alpha:        alphaBigInt,
		R: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](rX),
			Y: emulated.ValueOf[emulated.BN254Fp](rY),
		},
		DealerSK: 0, // dummy value, stripped when extracting public witness
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("golden: creating witness for verification: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("golden: extracting public witness: %w", err)
	}

	// Deserialize the proof.
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("golden: deserializing proof: %w", err)
	}

	// Verify.
	if err := plonk.Verify(proof, evrfVK, publicWitness); err != nil {
		return fmt.Errorf("golden: PLONK verify: %w", err)
	}

	return nil
}
