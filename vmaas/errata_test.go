package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrata(t *testing.T) {
	c := mockCache()
	req := &ErrataRequest{}

	// empty errata list
	_, err := req.errata(c)
	assert.Error(t, err)
}

func TestFilterInputErrata(t *testing.T) {
	c := mockCache()
	req := mockErrataRequest()
	errata := filterInputErrata(c, req.Errata, req)
	assert.Equal(t, 2, len(errata))
}

func TestErratumID2Releasevers(t *testing.T) {
	c := mockCache()
	relVers := c.erratumID2Releasevers(1)
	assert.Equal(t, "8.2", relVers[0])

	relVers = c.erratumID2Releasevers(2)
	assert.Equal(t, 3, len(relVers))
}

func TestGetErrataDetails(t *testing.T) {
	c := mockCache()
	errata := []string{"RHSA-2024:0042", "RHSA-2024:1111"}
	errataDetails := c.getErrataDetails(errata)
	assert.Equal(t, 2, len(errataDetails))
	ed := errataDetails["RHSA-2024:0042"]
	assert.Equal(t, 1, len(ed.PackageList))
	assert.Equal(t, 1, len(ed.SourcePackageList))
}

func mockErrataRequest() *ErrataRequest {
	severities := []string{LowCveImpact, ModerateCveImpact, ImportantCveImpact, CriticalCveImpact}
	return &ErrataRequest{
		Errata:     []string{"RHSA-2024:0042", "RHSA-2024:1111", "RHSA-2024:1111", "RHSA-2024:9999"},
		ThirdParty: true,
		Type:       []string{"security", "bugfix"},
		Severity:   []*string{&severities[0], &severities[1], &severities[2], &severities[3]},
	}
}
