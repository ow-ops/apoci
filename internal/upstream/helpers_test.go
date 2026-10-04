package upstream

import (
	"testing"

	"git.ow-ops.eu/ow-ops/apoci/internal/validate"
)

func TestMain(m *testing.M) {
	validate.AllowPrivateIPs.Store(true)
	m.Run()
}
