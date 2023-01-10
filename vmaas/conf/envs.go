package conf

import (
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

var Env = &Envs{}

type Envs struct {
	OvalUnfixedEvalEnabled bool
	MaxGoroutines          int
}

func init() {
	Env.OvalUnfixedEvalEnabled = utils.GetBoolEnvOrDefault("OVAL_UNFIXED_EVAL_ENABLED", false)
	Env.MaxGoroutines = utils.GetIntEnvOrDefault("VMAAS_LIB_MAX_GOROUTINES", 1)
}
