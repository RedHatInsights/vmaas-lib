package vmaas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testingCachePath = "../example/vmaas.db"

	requestJSONBPFTool = `{
		"package_list": [
		   "bpftool-4.18.0-80.el8.x86_64.rpm"
		],
		"repository_list": [
			"rhel-8-for-x86_64-baseos-rpms"
		],
		"repository_paths": [],
		"extended": true,
		"basearch": "x86_64"
	}`
)

var api *API

// load "../example/vmaas.db" dump only where it is really necessary
// we should avoid using vmaas.db for testing
func loadDump() {
	api, _ = InitFromFile(testingCachePath, &defaultCfg)
}

func TestVulnerabilitiesExtendedManuallyFixableCVEs(t *testing.T) {
	loadDump()
	var req Request
	assert.Nil(t, json.Unmarshal([]byte(requestJSONBPFTool), &req))

	res, err := api.VulnerabilitiesExtended(&req)
	assert.Nil(t, err)

	assert.Equal(t, 1, len(res.ManuallyFixableCVEs))
	cve := res.ManuallyFixableCVEs[0]
	assert.Equal(t, "CVE-2019-5108", cve.CVE)
	assert.Equal(t, 1, len(cve.Packages))
	assert.Equal(t, "bpftool-4.18.0-80.el8.x86_64.rpm", cve.Packages[0])
	assert.Equal(t, 1, len(cve.Errata))
	assert.Equal(t, "RHSA-2020:1769", cve.Errata[0])
}

func TestUpdateCvesNilErratum(t *testing.T) {
	loadDump()
	vulns := map[string]VulnerabilityDetail{}
	updateCves(vulns, "CVE", Package{String: "pkg"}, nil, "")
	assert.Equal(t, len(vulns), 1)
}
