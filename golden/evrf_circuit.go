package golden

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/emulated"
)

// EVRFCircuit is the gnark circuit for proving correct eVRF pad derivation.
//
// It proves (without revealing sk):
//  1. PK_dealer = sk * G_bjj (BJJ public key ownership)
//  2. S = sk * PK_recipient (DH shared secret on BJJ)
//  3. pad = f(S, H1, H2, alpha) (pad derived from DH via x-extraction and LHL)
//  4. R = pad * G_bn254 (pad commitment matches)
//
// All BJJ operations are native (BJJ base field = BN254 Fr = circuit field).
// The R commitment verification uses emulated BN254 G1 arithmetic.
type EVRFCircuit struct {
	// Public inputs: BJJ point coordinates (in Fr = native field)
	DealerPKX    frontend.Variable `gnark:",public"`
	DealerPKY    frontend.Variable `gnark:",public"`
	RecipientPKX frontend.Variable `gnark:",public"`
	RecipientPKY frontend.Variable `gnark:",public"`
	H1X          frontend.Variable `gnark:",public"`
	H1Y          frontend.Variable `gnark:",public"`
	H2X          frontend.Variable `gnark:",public"`
	H2Y          frontend.Variable `gnark:",public"`
	Alpha        frontend.Variable `gnark:",public"`

	// Public input: R commitment (BN254 G1 point, coordinates in emulated Fp).
	R sw_emulated.AffinePoint[emulated.BN254Fp] `gnark:",public"`

	// Private witness
	DealerSK frontend.Variable
}

// Define implements frontend.Circuit for the eVRF proof.
func (c *EVRFCircuit) Define(api frontend.API) error {
	// Initialize BJJ curve gadget (native operations).
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	// Get BJJ generator coordinates.
	params, err := twistededwards.GetCurveParams(tedwards.BN254)
	if err != nil {
		return err
	}
	generator := twistededwards.Point{X: params.Base[0], Y: params.Base[1]}

	// Step 1: Verify PK_dealer = sk * G_bjj
	dealerPK := twistededwards.Point{X: c.DealerPKX, Y: c.DealerPKY}
	computedPK := curve.ScalarMul(generator, c.DealerSK)
	curve.AssertIsOnCurve(dealerPK)
	api.AssertIsEqual(computedPK.X, dealerPK.X)
	api.AssertIsEqual(computedPK.Y, dealerPK.Y)

	// Step 2: Compute S = sk * PK_recipient (DH)
	recipientPK := twistededwards.Point{X: c.RecipientPKX, Y: c.RecipientPKY}
	curve.AssertIsOnCurve(recipientPK)
	S := curve.ScalarMul(recipientPK, c.DealerSK)

	// Step 3: s = S.X (x-coordinate extraction, native since BJJ coords are in Fr)
	// Note: The out-of-circuit code reduces s mod l (BJJ subgroup order) before
	// scalar multiplication. Here we use s directly as a native Fr variable.
	// These are algebraically equivalent because H1, H2 are in the prime-order
	// subgroup of order l, so [s]H = [s mod l]H for any point H of order l.
	// The gnark twistededwards ScalarMul gadget correctly handles this.
	s := S.X

	// Step 4: P1 = s * H1, P2 = s * H2
	h1 := twistededwards.Point{X: c.H1X, Y: c.H1Y}
	h2 := twistededwards.Point{X: c.H2X, Y: c.H2Y}
	curve.AssertIsOnCurve(h1)
	curve.AssertIsOnCurve(h2)
	P1 := curve.ScalarMul(h1, s)
	P2 := curve.ScalarMul(h2, s)

	// Step 5: pad = P1.X + alpha * P2.X (LHL combination, native Fr)
	alphaX2 := api.Mul(c.Alpha, P2.X)
	pad := api.Add(P1.X, alphaX2)

	// Step 6: Verify R = pad * G_bn254 using emulated BN254 G1 arithmetic.
	bn254Curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](
		api, sw_emulated.GetCurveParams[emulated.BN254Fp](),
	)
	if err != nil {
		return err
	}

	scalarField, err := emulated.NewField[emulated.BN254Fr](api)
	if err != nil {
		return err
	}

	// Convert native pad to emulated Fr scalar via bit decomposition.
	// Native Fr and emulated BN254Fr represent the same field, but the emulated
	// representation uses 4 limbs of 64 bits. Direct NewElement fails because
	// a single native variable doesn't match the expected limb count.
	// Decompose into bits (little-endian) and reconstruct as emulated element.
	padBits := api.ToBinary(pad, 254)
	padScalar := scalarField.FromBits(padBits...)

	// Compute pad * G_bn254 using the emulated curve.
	computedR := bn254Curve.ScalarMulBase(padScalar)

	// Assert the computed R matches the public R input.
	bn254Curve.AssertIsEqual(computedR, &c.R)

	return nil
}
