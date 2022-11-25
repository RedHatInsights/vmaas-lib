package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCveMapKeysValues(t *testing.T) {
	cve := "CVE-1234-5678"
	packages := []string{"bash", "kernel"}
	errata := []string{"RHBA-1234-5678"}
	cves := map[string]VulnerabilityDetail{
		cve: {
			CVE:      cve,
			Packages: packages,
			Errata:   errata,
		},
	}

	keys := cveMapKeys(cves)
	assert.Equal(t, []Vulnerability{"CVE-1234-5678"}, keys)
	values := cveMapValues(cves)
	assert.Equal(t, cve, values[0].CVE)
	assert.Equal(t, packages, values[0].Packages)
	assert.Equal(t, errata, values[0].Errata)
}
