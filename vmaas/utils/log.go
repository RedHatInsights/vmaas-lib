package utils

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

func processArgs(args []any) (log.Fields, any) {
	nArgs := len(args)
	fields := log.Fields{}
	for i := 1; i < nArgs; i += 2 {
		fields[args[i-1].(string)] = args[i]
	}
	var msg any
	if nArgs%2 != 0 {
		msg = args[nArgs-1]
	} else {
		msg = ""
	}
	return fields, msg
}

// implement LogXXXX functions to enable additional log fields
// usage: utils.LogInfo("my_field_1", 1, "my_field_2", 4.3, "Testing logging")
func logLevel(level log.Level, args ...any) {
	if !log.IsLevelEnabled(level) {
		return
	}
	fields, msg := processArgs(args)

	// using standard Log at Fatal or Panic level will not properly exit or panic
	entry := log.WithFields(fields)
	switch level {
	case log.FatalLevel:
		entry.Fatal(msg)
	case log.PanicLevel:
		entry.Panic(msg)
	default:
		entry.Log(level, msg)
	}
}

func LogTrace(args ...any) {
	logLevel(log.TraceLevel, args...)
}

func LogDebug(args ...any) {
	logLevel(log.DebugLevel, args...)
}

func LogInfo(args ...any) {
	logLevel(log.InfoLevel, args...)
}

func LogWarn(args ...any) {
	logLevel(log.WarnLevel, args...)
}

func LogError(args ...any) {
	logLevel(log.ErrorLevel, args...)
}

func LogFatal(args ...any) {
	logLevel(log.FatalLevel, args...)
}

func LogPanic(args ...any) {
	logLevel(log.PanicLevel, args...)
}

func TimeTrack(start time.Time, eventName string) {
	elapsed := fmt.Sprint(time.Since(start))
	LogInfo("event", eventName, "elapsed", elapsed)
}
