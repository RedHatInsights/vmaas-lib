package utils //nolint:var-naming

import (
	"regexp"
	"strings"
)

// TryExpandRegexPattern treats the item in a single-label slice like a regex pattern
// and returns all matching labels from dataByLabels, otherwise it returns inLabels.
func TryExpandRegexPattern[T any](inLabels []string, dataByLabels map[string]T) ([]string, error) {
	if len(inLabels) != 1 {
		return inLabels, nil
	}

	pattern := inLabels[0]

	// Check pattern before adding ^ and $.
	// For example, go implementation errors out on `*`, but doesn't on `^*$`.
	_, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern += "$"
	}

	re := regexp.MustCompile(pattern)

	outLabels := make([]string, 0, len(dataByLabels))
	for label := range dataByLabels {
		matched := re.Match([]byte(label))
		if matched {
			outLabels = append(outLabels, label)
		}
	}
	if len(outLabels) == 0 {
		return inLabels, nil
	}
	return outLabels, nil
}
