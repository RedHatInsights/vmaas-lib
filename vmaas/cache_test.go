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

func TestPackageIDs2Nevras(t *testing.T) {
	c := mockCache()
	binPackages, sourcePackages := c.packageIDs2Nevras([]int{1, 3})
	assert.Equal(t, 1, len(binPackages))
	assert.Equal(t, 1, len(sourcePackages))
	assert.Equal(t, "kernel-1:1-1.x86_64", binPackages[0])
	assert.Equal(t, "kernel-devel-1:1-1.src", sourcePackages[0])
}

func TestBuildRepoID2ErratumIDs(t *testing.T) {
	c := mockCache()
	modifiedSince, _ := time.Parse(time.RFC3339, "2020-12-15T07:00:00+01:00")

	// missing modifiedSince
	repoID2ErratumIDsMap := c.buildRepoID2ErratumIDs(nil)
	assert.Nil(t, repoID2ErratumIDsMap)

	// usual case
	repoID2ErratumIDsMap = c.buildRepoID2ErratumIDs(&time.Time{})
	assert.Equal(t, 4, len(repoID2ErratumIDsMap))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[41]))
	assert.Equal(t, 2, len(repoID2ErratumIDsMap[42]))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[43]))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[44]))

	// filter by modifiedSince
	repoID2ErratumIDsMap = c.buildRepoID2ErratumIDs(&modifiedSince)
	assert.Equal(t, 3, len(repoID2ErratumIDsMap))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[42]))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[43]))
	assert.Equal(t, 1, len(repoID2ErratumIDsMap[44]))
}

func TestErratumIDs2PackageNames(t *testing.T) {
	c := mockCache()
	erratumIDs := []ErratumID{1, 2, 2}
	pkgNames := c.erratumIDs2PackageNames(erratumIDs)
	assert.Equal(t, 2, len(pkgNames))
}

func TestIsPkgThirdParty(t *testing.T) {
	c := mockCache()
	val := c.isPkgThirdParty(5)
	assert.True(t, val)
	val = c.isPkgThirdParty(6)
	assert.False(t, val)
}

func TestNevra2PkgID(t *testing.T) {
	c := mockCache()
	nevra := utils.Nevra{
		Name:    "bash",
		Epoch:   0,
		Version: "4.2.46",
		Release: "20.el7_2",
		Arch:    "x86_64",
	}
	pkgID := c.nevra2PkgID(nevra)
	assert.Equal(t, 4, int(pkgID))

	emptyNevra := utils.Nevra{
		Name:    "",
		Epoch:   0,
		Version: "",
		Release: "",
		Arch:    "",
	}
	pkgID = c.nevra2PkgID(emptyNevra)
	assert.Equal(t, 0, int(pkgID))
}

func TestSrcPkgID2Pkg(t *testing.T) {
	c := mockCache()
	var srcPkgID PkgID = 1
	pkg := c.srcPkgID2Pkg(&srcPkgID)
	assert.Equal(t, "kernel-1:1-1.x86_64", pkg)

	pkg = c.srcPkgID2Pkg(nil)
	assert.Equal(t, "", pkg)
}

func TestPkgID2Repos(t *testing.T) {
	c := mockCache()
	repoDetails := c.pkgID2Repos(4)
	assert.Equal(t, 2, len(repoDetails))

	repoDetails = c.pkgID2Repos(99)
	assert.Equal(t, 0, len(repoDetails))
}

func TestPkgID2BuiltBinaryPkgs(t *testing.T) {
	c := mockCache()
	bbp := c.pkgID2BuiltBinaryPkgs(42)
	assert.Equal(t, 3, len(bbp))
}

func TestNameID2ContentSetIDs(t *testing.T) {
	c := mockCache()
	csIDs := c.nameID2ContentSetIDs(2)
	assert.Equal(t, 3, len(csIDs))
}

//nolint:funlen
func mockCache() *Cache {
	modifiedDate, _ := time.Parse(time.RFC3339, "2024-10-03T11:44:00+02:00")
	publishedDate, _ := time.Parse(time.RFC3339, "2024-10-03T11:44:00+02:00")
	important := ImportantCveImpact
	low := LowCveImpact
	lastChange, _ := time.Parse(time.RFC3339, "2024-11-18T17:58:00+01:00")
	updated1, _ := time.Parse(time.RFC3339, "2020-10-10T11:00:45+02:00")
	updated2, _ := time.Parse(time.RFC3339, "2021-10-10T11:00:45+02:00")
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

		Packagename2ID: map[string]NameID{
			"bash":        3,
			"python-perf": 4,
			"vim-common":  5,
		},

		ContentSetID2PkgNameIDs: map[ContentSetID][]NameID{
			101: {1, 2},
			102: {1, 2, 3},
			103: {2},
			104: {},
		},

		Evr2ID: map[utils.Evr]EvrID{
			{Epoch: 0, Version: "4.2.46", Release: "20.el7_2"}: 3,
			{Epoch: 0, Version: "3.10.0", Release: "693.el7"}:  4,
			{Epoch: 2, Version: "7.4.160", Release: "1.el7"}:   5,
		},

		Nevra2PkgID: map[Nevra]PkgID{
			{NameID: 3, EvrID: 3, ArchID: 1}: 4,
			{NameID: 4, EvrID: 4, ArchID: 1}: 5,
			{NameID: 5, EvrID: 5, ArchID: 1}: 6,
		},

		PkgID2RepoIDs: map[PkgID][]RepoID{
			4: {41, 42},
			5: {43},
			6: {44},
		},

		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1, Modified: &modifiedDate}, // kernel-1:1-1
			2: {NameID: 1, EvrID: 2, ArchID: 1},                          // kernel-0:2-2
			3: {NameID: 2, EvrID: 1, ArchID: 2},                          // kernel-devel-1:1-1
			4: {},
			5: {},
			6: {},
		},

		ErratumDetails: map[string]ErratumDetail{
			"RHSA-2024:0042": {
				ID:         1,
				ThirdParty: false,
				Type:       "security",
				Severity:   &important,
				PkgIDs:     []int{2, 3},
				Updated:    &updated1,
				Issued:     &updated1,
			},
			"RHSA-2024:1111": {
				ID:         2,
				ThirdParty: true,
				Type:       "bugfix",
				Severity:   &low,
				Updated:    &updated2,
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
			42: {RepoDetailCommon: RepoDetailCommon{Releasever: "8.2"}},
			43: {RepoDetailCommon: RepoDetailCommon{Releasever: "8.3"}, ThirdParty: true},
			44: {RepoDetailCommon: RepoDetailCommon{Releasever: "8.4"}, LastChange: &lastChange},
		},

		CveDetail: map[string]CveDetail{
			"CVE-2024-21345": {
				Source:        "Red Hat",
				ModifiedDate:  &modifiedDate,
				PublishedDate: &publishedDate,
			},
			"CVE-2024-1234": {
				ErrataIDs: []ErratumID{1, 2},
			},
			"CVE-2024-1111111": {},
		},

		RepoLabel2IDs: map[string][]RepoID{
			"rhel-6-server-rpms": {41, 42},
			"rhel-7-server-rpms": {43},
			"rhel-8-server-rpms": {44},
		},

		CpeID2Label: map[CpeID]CpeLabel{
			1:  "foo",
			2:  "bar",
			3:  "baz",
			4:  "qux",
			5:  "quux",
			44: "this",
		},

		RepoID2CpeIDs: map[RepoID][]CpeID{
			41: {1, 2},
			42: {2, 3},
			43: {3, 4},
			44: {4, 5, 44},
		},

		ContentSetID2CpeIDs: map[ContentSetID][]CpeID{
			111: {1, 2, 3},
		},

		SrcPkgID2PkgID: map[PkgID][]PkgID{
			42: {1, 2, 3},
		},

		PkgID2ErrataIDs: map[PkgID][]ErratumID{
			4: {1, 2},
		},

		DBChange: DBChange{LastChange: "2024-10-02T16:08:00+02:00"},
	}
}
