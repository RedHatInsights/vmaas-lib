package utils

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestProcessArgs_EvenArgs(t *testing.T) {
	args := []any{"key1", "value1", "key2", 42}

	fields, msg := processArgs(args)

	expectedFields := log.Fields{
		"key1": "value1",
		"key2": 42,
	}
	assert.Equal(t, expectedFields, fields)
	assert.Equal(t, "", msg)
}

func TestProcessArgs_OddArgs(t *testing.T) {
	args := []any{"key1", "value1", "key2", 42, "final message"}

	fields, msg := processArgs(args)

	expectedFields := log.Fields{
		"key1": "value1",
		"key2": 42,
	}
	assert.Equal(t, expectedFields, fields)
	assert.Equal(t, "final message", msg)
}

func TestProcessArgs_EmptyArgs(t *testing.T) {
	args := []any{}

	fields, msg := processArgs(args)

	assert.Equal(t, log.Fields{}, fields)
	assert.Equal(t, "", msg)
}

func TestProcessArgs_SingleArg(t *testing.T) {
	args := []any{"only message"}

	fields, msg := processArgs(args)

	assert.Equal(t, log.Fields{}, fields)
	assert.Equal(t, "only message", msg)
}

func TestLogTrace(t *testing.T) {
	// Set log level to trace to ensure the function executes
	originalLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	defer log.SetLevel(originalLevel)

	// This should not panic or error
	assert.NotPanics(t, func() {
		LogTrace("test_key", "test_value", "trace message")
	})
}

func TestLogDebug(t *testing.T) {
	// Set log level to debug to ensure the function executes
	originalLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	defer log.SetLevel(originalLevel)

	// This should not panic or error
	assert.NotPanics(t, func() {
		LogDebug("test_key", "test_value", "debug message")
	})
}

func TestLogInfo(t *testing.T) {
	// This should not panic or error
	assert.NotPanics(t, func() {
		LogInfo("test_key", "test_value", "info message")
	})
}

func TestLogWarn(t *testing.T) {
	// This should not panic or error
	assert.NotPanics(t, func() {
		LogWarn("test_key", "test_value", "warn message")
	})
}

func TestLogError(t *testing.T) {
	// This should not panic or error
	assert.NotPanics(t, func() {
		LogError("test_key", "test_value", "error message")
	})
}

func TestTimeTrack(t *testing.T) {
	start := time.Now()
	time.Sleep(1 * time.Millisecond) // Small delay to ensure elapsed time > 0

	// This should not panic or error
	assert.NotPanics(t, func() {
		TimeTrack(start, "test_event")
	})
}

func TestTimeTrack_InstantCall(t *testing.T) {
	start := time.Now()

	// Even with no delay, this should work
	assert.NotPanics(t, func() {
		TimeTrack(start, "instant_event")
	})
}

// Note: LogFatal and LogPanic are not tested as they would exit/panic the test process
// In production code, these would need integration tests or special testing frameworks
// that can handle process exit/panic scenarios
