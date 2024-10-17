package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTryExpandRegexPattern(t *testing.T) {
	regexLabel := []string{`CVE-2024-1\d+`}
	inLabels := []string{"CVE-2024-1234", "CVE-2024-21345"}
	labelDetails := map[string]int{
		"CVE-2024-1234":  0,
		"CVE-2024-12345": 0,
		"CVE-2024-21345": 0,
	}

	// empty slice
	outLabels := TryExpandRegexPattern([]string{}, labelDetails)
	assert.Equal(t, 0, len(outLabels))

	// with a single lable that is not a regex pattern
	outLabels = TryExpandRegexPattern(inLabels[0:1], labelDetails)
	assert.Equal(t, inLabels[0], outLabels[0])

	// more labels in inLabels
	outLabels = TryExpandRegexPattern(inLabels, labelDetails)
	assert.Equal(t, len(inLabels), len(outLabels))

	// with regex
	outLabels = TryExpandRegexPattern(regexLabel, labelDetails)
	assert.Equal(t, 2, len(outLabels))
}
