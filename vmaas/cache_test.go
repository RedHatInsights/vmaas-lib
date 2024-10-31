package vmaas

import (
	"testing"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
)

func TestErrataIDs2Names(t *testing.T) {
	c := mockCache()
	errataNames := c.errataIDs2Names([]int{1, 2})
	assert.Equal(t, 2, len(errataNames))
}

func TestPkgDetail2Nevra(t *testing.T) {
	c := mockCache()
	pkgDetail := c.PackageDetails[PkgID(1)]
	nevra := c.pkgDetail2Nevra(pkgDetail)
	assert.Equal(t, "kernel-1:1-1.x86_64", nevra)
}

func TestPackageIDs2Nevras(t *testing.T) {
	c := mockCache()
	binPackages, sourcePackages := c.packageIDs2Nevras([]int{1, 3})
	assert.Equal(t, 1, len(binPackages))
	assert.Equal(t, 1, len(sourcePackages))
	assert.Equal(t, "kernel-1:1-1.x86_64", binPackages[0])
	assert.Equal(t, "kernel-devel-1:1-1.src", sourcePackages[0])
}

//nolint:funlen
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

		ErratumDetails: map[string]ErratumDetail{
			"RHSA-2024:0042": {
				ThirdParty: false,
				Type:       "security",
				Severity:   "Important",
				PkgIDs:     []int{2, 3},
			},
			"RHSA-2024:1111": {
				ThirdParty: true,
				Type:       "bugfix",
				Severity:   "Low",
			},
		},

		ErratumID2Name: map[ErratumID]string{
			1: "RHSA-2024:0042",
			2: "RHSA-2024:1111",
		},

		ErratumID2RepoIDs: map[ErratumID]map[RepoID]bool{
			1: {
				41: true,
				42: true,
			},
			2: {
				42: true,
				43: true,
				44: true,
			},
		},

		RepoDetails: map[RepoID]RepoDetail{
			41: {},
			42: {Releasever: "8.2"},
			43: {Releasever: "8.3"},
			44: {Releasever: "8.4"},
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
