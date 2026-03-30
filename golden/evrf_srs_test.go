package golden

import (
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/test/unsafekzg"
)

// init overrides the SRS provider for tests to use unsafekzg (known toxic waste).
// This is safe for testing but MUST NEVER be used in production.
func init() {
	testingSRSProvider = func(ccs constraint.ConstraintSystem) (kzg.SRS, kzg.SRS, error) {
		return unsafekzg.NewSRS(ccs)
	}
}
