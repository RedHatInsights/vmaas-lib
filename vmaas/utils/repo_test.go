package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripPrefixes(t *testing.T) {
	prefixes := []string{"abc-", "foo-"}
	repos := []string{"abc-rhel-6-server-rpms", "foo-rhel-6-server-rpms"}
	repos = StripPrefixes(repos, prefixes)
	assert.Equal(t, "rhel-6-server-rpms", repos[0])
	assert.Equal(t, "rhel-6-server-rpms", repos[1])
}
