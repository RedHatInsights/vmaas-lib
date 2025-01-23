package utils

import (
	"strings"
)

func StripPrefixes(repos []string, prefixes []string) []string {
	processed := make([]string, 0, len(repos))
	for _, repo := range repos {
		for _, prefix := range prefixes {
			if strings.HasPrefix(repo, prefix) {
				processed = append(processed, repo[len(prefix):])
			}
		}
	}
	return processed
}
