package utils

import (
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMemTrack(t *testing.T) {
	// Set log level to debug to ensure the function executes
	originalLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(originalLevel)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// This should not panic or error
	assert.NotPanics(t, func() {
		MemTrack(&m1, "test_event")
	})
}

func TestMemUsage(t *testing.T) {
	// Set log level to debug to ensure the function executes
	originalLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(originalLevel)

	// Create two memory stats with different values
	m1 := &runtime.MemStats{
		Alloc:      1000,
		TotalAlloc: 2000,
		HeapAlloc:  1500,
	}
	m2 := &runtime.MemStats{
		Alloc:      1200,
		TotalAlloc: 2500,
		HeapAlloc:  1800,
	}

	// This should not panic or error
	assert.NotPanics(t, func() {
		MemUsage(m1, m2, "test_message", "+")
	})
}

func TestSizeStr(t *testing.T) {
	tests := []struct {
		size     uint64
		expected string
	}{
		{0, "0B"},
		{1024, "1KiB"},
		{1048576, "1MiB"},
		{1073741824, "1GiB"},
		{500, "500B"},
	}

	for _, test := range tests {
		result := SizeStr(test.size)
		assert.Contains(t, result, strings.Split(test.expected, "B")[0])
		assert.True(t, strings.HasSuffix(result, strings.Split(test.expected, "B")[1]+"B"))
	}
}

func TestRunGC(t *testing.T) {
	// Set log level to debug to ensure the function executes
	originalLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(originalLevel)

	// This should not panic or error
	assert.NotPanics(t, func() {
		RunGC()
	})
}
