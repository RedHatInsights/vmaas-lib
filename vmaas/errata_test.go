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

func TestGetSortedErrata(t *testing.T) {
	req := mockErrataRequest()
	emptyReq := &ErrataRequest{}
	c := mockCache()

	errata, err := req.getSortedErrata(c)
	assert.NoError(t, err)
	assert.Equal(t, "RHSA-2024:0042", errata[0])
	assert.Equal(t, "RHSA-2024:1111", errata[1])
	assert.Equal(t, "RHSA-2024:9999", errata[3])

	_, err = emptyReq.getSortedErrata(c)
	assert.Error(t, err)
}

func TestFilterInputErrata(t *testing.T) {
	c := mockCache()
	req := mockErrataRequest()
	errata := filterInputErrata(c, req.Errata, req)
	assert.Equal(t, 2, len(errata))
}

func TestLoadErrataReleaseVersions(t *testing.T) {
	c := mockCache()
	relVers := c.erratumID2Releasevers(1)
	assert.Equal(t, "8.2", relVers[0])

	relVers = c.erratumID2Releasevers(2)
	assert.Equal(t, 3, len(relVers))
}

func TestLoadErrataDetails(t *testing.T) {
	c := mockCache()
	errata := []string{"RHSA-2024:0042", "RHSA-2024:1111"}
	errataDetails := c.loadErrataDetails(errata)
	assert.Equal(t, 2, len(errataDetails))
	ed := errataDetails["RHSA-2024:0042"]
	assert.Equal(t, 1, len(ed.PackageList))
	assert.Equal(t, 1, len(ed.SourcePackageList))
}

func mockErrataRequest() *ErrataRequest {
	severities := []string{"Low", "Moderate", "Important", "Critical"}
	return &ErrataRequest{
		Errata:     []string{"RHSA-2024:0042", "RHSA-2024:1111", "RHSA-2024:1111", "RHSA-2024:9999"},
		ThirdParty: true,
		Type:       []string{"security", "bugfix"},
		Severity:   []*string{&severities[0], &severities[1], &severities[2], &severities[3]},
	}
}
