package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterInputCves(t *testing.T) {
	cves := []string{"CVE-2024-1234", "CVE-2024-21345", ""}
	c := mockCache()

	// usual case
	filteredIDs := filterInputCves(c, cves, &CvesRequest{})
	assert.Equal(t, 2, len(filteredIDs))

	// RHOnly
	req := &CvesRequest{RHOnly: true}
	filteredIDs = filterInputCves(c, cves, req)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-21345", filteredIDs[0])

	// With some errata associated only
	req = &CvesRequest{AreErrataAssociated: true}
	filteredIDs = filterInputCves(c, cves, req)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])

	// With modified date before req.ModifiedSince
	testTime, _ := time.Parse(time.RFC3339, "2024-10-03T15:01:01Z")
	req = &CvesRequest{ModifiedSince: &testTime}
	filteredIDs = filterInputCves(c, cves, req)
	assert.Equal(t, 0, len(filteredIDs))

	// With published date before req.PublishedSince
	req = &CvesRequest{PublishedSince: &testTime}
	filteredIDs = filterInputCves(c, cves, req)
	assert.Equal(t, 0, len(filteredIDs))
}

func TestLoadCveDetails(t *testing.T) {
	c := mockCache()
	cve := "CVE-2024-1111111"
	cvePropertiesMap := c.loadCveDetails([]string{cve})
	assert.Equal(t, 1, len(cvePropertiesMap))
	assert.Equal(t, cve, cvePropertiesMap[cve].Name)
}

func TestCves(t *testing.T) {
	req := &CvesRequest{}
	c := mockCache()

	// empty cve list
	_, err := req.cves(c)
	assert.Error(t, err)
}
