package vmaas

import (
	"testing"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
)

func TestPkgDetail2Nevra(t *testing.T) {
	c := mockCache()
	pkgDetail := c.PackageDetails[PkgID(1)]
	nevra := c.pkgDetail2Nevra(pkgDetail)
	assert.Equal(t, "kernel-1:1-1.x86_64", nevra)
}

func TestErrataIDs2Names(t *testing.T) {
	c := mockCache()
	errataNames := c.errataIDs2Names([]int{1, 2})
	assert.Equal(t, 2, len(errataNames))
}

func TestPackageIDs2Nevras(t *testing.T) {
	c := mockCache()
	binPackages, sourcePackages := c.packageIDs2Nevras([]int{1, 3})
	assert.Equal(t, 1, len(binPackages))
	assert.Equal(t, 1, len(sourcePackages))
	assert.Equal(t, "kernel-1:1-1.x86_64", binPackages[0])
	assert.Equal(t, "kernel-devel-1:1-1.src", sourcePackages[0])
}

func TestGetSortedCves(t *testing.T) {
	req := mockCvesRequest()
	reqWithoutReq := &CvesRequest{}
	c := mockCache()

	cves, err := req.getSortedCves(c)
	assert.NoError(t, err)
	assert.Equal(t, "CVE-2024-1111111", cves[0])
	assert.Equal(t, "CVE-2024-1234", cves[1])
	assert.Equal(t, "CVE-2024-21345", cves[2])

	_, err = reqWithoutReq.getSortedCves(c)
	assert.Error(t, err)
}

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
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])

	// With published date before req.PublishedSince
	req = &CvesRequest{PublishedSince: &testTime}
	filteredIDs = filterInputCves(c, cves, req)
	assert.Equal(t, 1, len(filteredIDs))
	assert.Equal(t, "CVE-2024-1234", filteredIDs[0])
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

func mockCache() *Cache {
	modifiedDate, _ := time.Parse(time.RFC3339, "2024-10-03T11:44:00+02:00")
	publishedDate, _ := time.Parse(time.RFC3339, "2024-10-03T11:44:00+02:00")
	return &Cache{
		ID2Packagename: map[NameID]string{1: "kernel", 2: "kernel-devel"},

		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 1, Version: "1", Release: "1"},
			2: {Epoch: 0, Version: "2", Release: "2"},
		},

		Arch2ID: map[string]ArchID{
			"x86_64": 1,
			"src":    2,
		},
		ID2Arch: map[ArchID]string{
			1: "x86_64",
			2: "src",
		},

		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1}, // kernel-1:1-1
			2: {NameID: 1, EvrID: 2, ArchID: 1}, // kernel-0:2-2
			3: {NameID: 2, EvrID: 1, ArchID: 2}, // kernel-devel-1:1-1
		},

		ErratumID2Name: map[ErratumID]string{
			1: "RHSA-2024:0042",
			2: "RHSA-2024:1111",
		},

		CveDetail: map[string]CveDetail{
			"CVE-2024-21345": {
				Source:        "Red Hat",
				ModifiedDate:  &modifiedDate,
				PublishedDate: &publishedDate,
			},
			"CVE-2024-1234": {
				ErrataIDs: []int{1, 2},
			},
			"CVE-2024-1111111": {},
		},

		DBChange: DBChange{LastChange: "2024-10-02T16:08:00+02:00"},
	}
}

func mockCvesRequest() *CvesRequest {
	modifiedSince, _ := time.Parse(time.RFC3339, "2024-10-02T16:08:00+02:00")
	publishedSince, _ := time.Parse(time.RFC3339, "2024-10-02T16:08:00+02:00")
	return &CvesRequest{
		Cves:                []string{"CVE-2024-21345", "CVE-2024-1234", "CVE-2024-1111111"},
		ModifiedSince:       &modifiedSince,
		PublishedSince:      &publishedSince,
		RHOnly:              false,
		AreErrataAssociated: false,
		PageNumber:          1,
		PageSize:            5000,
	}
}
