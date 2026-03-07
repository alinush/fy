package golden

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/f3rmion/fy/group"
)

// maxProofSize is the maximum allowed size for a serialized PLONK proof.
// BN254 PLONK proofs are typically ~600 bytes; 2048 gives ample headroom
// while limiting the attack surface for oversized proof parsing.
const maxProofSize = 2048

var (
	evrfSetupOnce sync.Once
	evrfCCS       constraint.ConstraintSystem
	evrfPK        plonk.ProvingKey
	evrfVK        plonk.VerifyingKey
	evrfSetupErr  error
)

// testingSRSProvider, when non-nil, overrides the default ceremony SRS
// for testing. This MUST only be set from _test.go init() functions.
// Production code always uses LoadCeremonySRS (Aztec Ignition ceremony).
var testingSRSProvider func(constraint.ConstraintSystem) (kzg.SRS, kzg.SRS, error)

// initEVRFKeys compiles the eVRF circuit and generates PLONK keys.
// Called once via sync.Once.
//
// Uses the Aztec Ignition ceremony SRS (downloaded and cached on first use).
// Tests override via testingSRSProvider set in _test.go init().
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

		var canonical, lagrange kzg.SRS
		var err error

		if testingSRSProvider != nil {
			// Safety: testingSRSProvider must only be set from _test.go init().
			// Verify we are running inside a test binary by checking for the
			// standard "test.v" flag that Go's testing framework registers.
			if flag.Lookup("test.v") == nil {
				panic("golden: testingSRSProvider set in non-test binary - this is a security violation")
			}
			canonical, lagrange, err = testingSRSProvider(evrfCCS)
			if err != nil {
				evrfSetupErr = fmt.Errorf("golden: test SRS provider: %w", err)
				return
			}
		} else {
			// Production path: Aztec Ignition ceremony SRS.
			canonical, lagrange, err = LoadCeremonySRS(evrfCCS)
			if err != nil {
				evrfSetupErr = fmt.Errorf("golden: loading ceremony SRS: %w", err)
				return
			}
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
func bjjPointCoords(p group.Point) (x, y *big.Int, err error) {
	// BJJ Point has UncompressedBytes() returning 64 bytes: X || Y
	type uncompressor interface {
		UncompressedBytes() []byte
	}
	uc, ok := p.(uncompressor)
	if !ok {
		return nil, nil, fmt.Errorf("golden: bjjPointCoords: point %T does not implement UncompressedBytes", p)
	}
	data := uc.UncompressedBytes()
	x = new(big.Int).SetBytes(data[0:32])
	y = new(big.Int).SetBytes(data[32:64])
	return x, y, nil
}

// g1PointCoords extracts the (X, Y) coordinates from a BN254 G1 group.Point
// as big.Int values. G1 coordinates are in BN254 Fp (base field).
func g1PointCoords(p group.Point) (x, y *big.Int, err error) {
	// BN254 G1 Point.Bytes() returns Marshal() = 64 bytes: X || Y (uncompressed).
	data := p.Bytes()
	if len(data) < 64 {
		return nil, nil, fmt.Errorf("golden: g1PointCoords: expected 64 bytes, got %d", len(data))
	}
	x = new(big.Int).SetBytes(data[0:32])
	y = new(big.Int).SetBytes(data[32:64])
	return x, y, nil
}

// generateEVRFProofPLONK generates a PLONK proof for the eVRF circuit.
//
// This function is BN254/BJJ-specific: it uses hashToCurveTryAndIncrement directly
// (rather than suite.H1/H2) because the PLONK circuit is compiled for the BN254/BJJ
// curve pair. Alternative curve pairs require their own proof implementation.
func generateEVRFProofPLONK(
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
	dealerPKX, dealerPKY, err := bjjPointCoords(dealerPK)
	if err != nil {
		return nil, fmt.Errorf("golden: dealer PK coords: %w", err)
	}
	recipientPKX, recipientPKY, err := bjjPointCoords(recipientPK)
	if err != nil {
		return nil, fmt.Errorf("golden: recipient PK coords: %w", err)
	}

	// Compute H1, H2 from session data.
	h1, err := hashToCurveTryAndIncrement(h1Domain, sessionData...)
	if err != nil {
		return nil, fmt.Errorf("golden: H1 for proof: %w", err)
	}
	h2, err := hashToCurveTryAndIncrement(h2Domain, sessionData...)
	if err != nil {
		return nil, fmt.Errorf("golden: H2 for proof: %w", err)
	}
	h1X, h1Y, err := bjjPointCoords(h1)
	if err != nil {
		return nil, fmt.Errorf("golden: H1 coords: %w", err)
	}
	h2X, h2Y, err := bjjPointCoords(h2)
	if err != nil {
		return nil, fmt.Errorf("golden: H2 coords: %w", err)
	}

	// Alpha as big.Int.
	alphaBigInt := new(big.Int).SetBytes(alpha.Bytes())

	// R commitment coordinates (BN254 G1 Fp coordinates).
	rX, rY, err := g1PointCoords(padResult.RCommitment)
	if err != nil {
		return nil, fmt.Errorf("golden: R commitment coords: %w", err)
	}

	// Dealer SK as big.Int. Zero both the byte slice and big.Int after witness creation.
	skBytes := dealerSK.Bytes()
	skBigInt := new(big.Int).SetBytes(skBytes)

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

	// Zero all secret key material immediately after witness creation.
	// Overwrite the backing array words before resetting, since SetInt64(0) only
	// sets the length to zero without clearing the underlying memory.
	skWords := skBigInt.Bits()
	for i := range skWords {
		skWords[i] = 0
	}
	skBigInt.SetInt64(0)
	for i := range skBytes {
		skBytes[i] = 0
	}
	// Prevent the compiler from optimizing away the zeroing by ensuring
	// the variables are considered live until after the overwrite completes.
	runtime.KeepAlive(skBigInt)
	runtime.KeepAlive(skBytes)

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
//
// This function is BN254/BJJ-specific (see generateEVRFProofPLONK).
func verifyEVRFProofPLONK(
	dealerPK group.Point,
	recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	rCommitment group.Point,
	proofBytes []byte,
) error {
	// Check proof size before any processing.
	if len(proofBytes) == 0 {
		return errors.New("golden: empty proof bytes")
	}
	if len(proofBytes) > maxProofSize {
		return ErrProofTooLarge
	}

	// Ensure keys are initialized.
	initEVRFKeys()
	if evrfSetupErr != nil {
		return evrfSetupErr
	}

	// Extract BJJ point coordinates for public inputs.
	dealerPKX, dealerPKY, err := bjjPointCoords(dealerPK)
	if err != nil {
		return fmt.Errorf("golden: dealer PK coords: %w", err)
	}
	recipientPKX, recipientPKY, err := bjjPointCoords(recipientPK)
	if err != nil {
		return fmt.Errorf("golden: recipient PK coords: %w", err)
	}

	// Compute H1, H2 from session data.
	h1, err := hashToCurveTryAndIncrement(h1Domain, sessionData...)
	if err != nil {
		return fmt.Errorf("golden: H1 for verify: %w", err)
	}
	h2, err := hashToCurveTryAndIncrement(h2Domain, sessionData...)
	if err != nil {
		return fmt.Errorf("golden: H2 for verify: %w", err)
	}
	h1X, h1Y, err := bjjPointCoords(h1)
	if err != nil {
		return fmt.Errorf("golden: H1 coords: %w", err)
	}
	h2X, h2Y, err := bjjPointCoords(h2)
	if err != nil {
		return fmt.Errorf("golden: H2 coords: %w", err)
	}

	// Alpha as big.Int.
	alphaBigInt := new(big.Int).SetBytes(alpha.Bytes())

	// R commitment coordinates.
	rX, rY, err := g1PointCoords(rCommitment)
	if err != nil {
		return fmt.Errorf("golden: R commitment coords: %w", err)
	}

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
