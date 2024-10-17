package utils

import (
	"regexp"
	"strings"
)

// TryExpandRegexPattern treats the item in a single-label slice like a regex pattern
// and returns all matching labels from dataByLabels, otherwise it returns inLabels.
func TryExpandRegexPattern[T any](inLabels []string, dataByLabels map[string]T) []string {
	if len(inLabels) != 1 {
		return inLabels
	}

	pattern := inLabels[0]
	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern += "$"
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return inLabels
	}

	outLabels := make([]string, 0, len(dataByLabels))
	for label := range dataByLabels {
		matched := re.Match([]byte(label))
		if matched {
			outLabels = append(outLabels, label)
		}
	}
	return outLabels
}
