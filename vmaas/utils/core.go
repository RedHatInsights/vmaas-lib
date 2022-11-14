package utils

import (
	"os"
	"strconv"
	"time"
)

// GetBoolEnvOrDefault Parse bool value from env variable
func GetBoolEnvOrDefault(envname string, defval bool) bool {
	value := os.Getenv(envname)
	if value == "" {
		return defval
	}

	parsedBool, err := strconv.ParseBool(value)
	if err != nil {
		panic(err)
	}

	return parsedBool
}

func TimeTrack(start time.Time, eventName string) {
	elapsed := time.Since(start)
	Log("event", eventName, "elapsed", elapsed).Info()
}
