package utils

import (
	"fmt"
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

// GetIntEnvOrDefault Load int environment variable or load default
func GetIntEnvOrDefault(envname string, defval int) int {
	valueStr := os.Getenv(envname)
	if valueStr == "" {
		return defval
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Unable convert '%s' env var '%s' to int!", envname, valueStr))
	}

	return value
}
