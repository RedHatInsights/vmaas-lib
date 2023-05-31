package utils

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

func processArgs(args []interface{}) (log.Fields, interface{}) {
	nArgs := len(args)
	fields := log.Fields{}
	for i := 1; i < nArgs; i += 2 {
		fields[args[i-1].(string)] = args[i]
	}
	var msg interface{}
	if nArgs%2 != 0 {
		msg = args[nArgs-1]
	} else {
		msg = ""
	}
	return fields, msg
}

// implement LogXXXX functions to enable additional log fields
// usage: utils.LogInfo("my_field_1", 1, "my_field_2", 4.3, "Testing logging")
func logLevel(level log.Level, args ...interface{}) {
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

func LogTrace(args ...interface{}) {
	logLevel(log.TraceLevel, args...)
}

func LogDebug(args ...interface{}) {
	logLevel(log.DebugLevel, args...)
}

func LogInfo(args ...interface{}) {
	logLevel(log.InfoLevel, args...)
}

func LogWarn(args ...interface{}) {
	logLevel(log.WarnLevel, args...)
}

func LogError(args ...interface{}) {
	logLevel(log.ErrorLevel, args...)
}

func LogFatal(args ...interface{}) {
	logLevel(log.FatalLevel, args...)
}

func LogPanic(args ...interface{}) {
	logLevel(log.PanicLevel, args...)
}

func TimeTrack(start time.Time, eventName string) {
	elapsed := fmt.Sprint(time.Since(start))
	LogInfo("event", eventName, "elapsed", elapsed)
}
