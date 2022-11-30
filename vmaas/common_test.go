package vmaas

import (
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
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

func TestGetModules(t *testing.T) {
	c := Cache{}
	empty := []ModuleStream{}
	emptyRes := getModules(&c, empty)
	assert.Equal(t, 0, len(emptyRes))

	c.Module2IDs = map[ModuleStream][]int{
		{"firefox", "1"}: {1, 2, 3},
		{"kernel", "1"}:  {2, 3, 4},
	}
	c.ModuleRequires = map[int][]int{
		1: {2, 3},
		2: {3},
		3: {5},
		4: {3, 5},
	}
	modules := []ModuleStream{{"firefox", "1"}, {"kernel", "1"}}
	res := getModules(&c, modules)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, map[int]bool{1: true, 2: true}, res)
}

func TestFilterReposByBasearch(t *testing.T) {
	c := Cache{}
	repos := []RepoID{}

	// nil baserarch, return input repos
	res := filterReposByBasearch(&c, nil, repos)
	assert.Equal(t, repos, res)
	repos = []RepoID{1, 2, 3}
	res = filterReposByBasearch(&c, nil, repos)
	assert.Equal(t, repos, res)

	// filter by basearch
	x8664 := "x86_64"
	s390 := "s390"
	x8664input := "x86_64" // use new variable to make sure we are not comparing pointers in function
	c.RepoDetails = map[RepoID]RepoDetail{
		1: {BaseArch: nil},
		2: {BaseArch: &x8664},
		3: {BaseArch: &s390},
	}

	// empty repo list
	repos = []RepoID{}
	res = filterReposByBasearch(&c, &x8664input, repos)
	assert.Equal(t, repos, res)

	// repos = {1,2,3}
	// result = {2}
	repos = []RepoID{1, 2, 3}
	res = filterReposByBasearch(&c, &x8664input, repos)
	assert.Equal(t, []RepoID{2}, res)

	// invalid repo id
	repos = []RepoID{99}
	res = filterReposByBasearch(&c, &x8664input, repos)
	assert.Equal(t, []RepoID{}, res)
}

func TestFilterReposByReleasever(t *testing.T) {
	c := Cache{}
	repos := []RepoID{}

	// nil baserarch, return input repos
	res := filterReposByReleasever(&c, nil, repos)
	assert.Equal(t, repos, res)
	repos = []RepoID{1, 2, 3}
	res = filterReposByReleasever(&c, nil, repos)
	assert.Equal(t, repos, res)

	// filter by Releasever
	el8 := "el8"
	el9 := "el9"
	el8input := "el8" // use new variable to make sure we are not comparing pointers in function
	c.RepoDetails = map[RepoID]RepoDetail{
		1: {ReleaseVer: nil},
		2: {ReleaseVer: &el8},
		3: {ReleaseVer: &el9},
	}

	// empty repo list
	repos = []RepoID{}
	res = filterReposByReleasever(&c, &el8input, repos)
	assert.Equal(t, repos, res)

	// repos = {1,2,3}
	// result = {2}
	repos = []RepoID{1, 2, 3}
	res = filterReposByReleasever(&c, &el8input, repos)
	assert.Equal(t, []RepoID{2}, res)

	// invalid repo id
	repos = []RepoID{99}
	res = filterReposByReleasever(&c, &el8input, repos)
	assert.Equal(t, []RepoID{}, res)
}

func TestGetRepoIDs(t *testing.T) {
	repos := []string{}
	c := Cache{RepoDetails: map[RepoID]RepoDetail{1: {}, 2: {}, 3: {}}}

	// empty repos, return all repos available in cache
	res := getRepoIDs(&c, repos)
	assert.Equal(t, []RepoID{1, 2, 3}, res)

	// labels to ids
	c.RepoLabel2IDs = map[string][]RepoID{
		"repo1": {1, 2},
		"repo2": {2, 3},
	}
	repos = []string{"repo1", "repo2"}
	res = getRepoIDs(&c, repos)
	assert.Equal(t, []RepoID{1, 2, 3}, res)

	// invalid label
	repos = []string{"invalid"}
	res = getRepoIDs(&c, repos)
	assert.Equal(t, []RepoID{}, res)
}

func TestFilterPkgList(t *testing.T) {
	pkgs := []string{}

	// empty pkg list
	res := filterPkgList(pkgs, false)
	assert.Equal(t, pkgs, res)
	res = filterPkgList(pkgs, true)
	assert.Equal(t, pkgs, res)

	pkgs = []string{
		"bash-0:4.4.20-1.el8_4.x86_64",
		"bash-4.4.20-1.el8_4.x86_64",
		"bash-0:5.4.20-1.el8_4.x86_64",
		"bash-0:3.4.20-1.el8_4.x86_64",
	}

	// latestOnly=false
	res = filterPkgList(pkgs, false)
	assert.Equal(t, pkgs, res)

	// latestOnly=true
	res = filterPkgList(pkgs, true)
	assert.Equal(t, []string{"bash-0:5.4.20-1.el8_4.x86_64"}, res)
}

func TestExtractNevraIDs(t *testing.T) {
	// test nil
	res := extractNevraIDs(nil, nil)
	assert.Equal(t, NevraIDs{}, res)

	// test with nevra
	nevra, _ := utils.ParseNevra("bash-0:5.4.20-1.el8_4.x86_64")
	evr := utils.Evr{
		Epoch:   nevra.Epoch,
		Version: nevra.Version,
		Release: nevra.Release,
	}
	c := Cache{
		Packagename2ID: map[string]NameID{"bash": 1},
		Evr2ID:         map[utils.Evr]EvrID{evr: 2},
		Arch2ID:        map[string]ArchID{"x86_64": 3},
		UpdatesIndex:   map[NameID]map[EvrID][]int{1: {2: []int{5, 6, 7}}},
	}

	ids := extractNevraIDs(&c, &nevra)
	assert.Equal(t, NameID(1), ids.NameID)
	assert.Equal(t, []int{5, 6, 7}, ids.EvrIDs)
	assert.Equal(t, ArchID(3), ids.ArchID)

	// test empty nevra ids
	ids = extractNevraIDs(&c, &utils.Nevra{})
	assert.Equal(t, NevraIDs{}, ids)
}

func TestNevraPkgID(t *testing.T) {
	// test nil
	res := nevraPkgID(nil, nil)
	assert.Equal(t, PkgID(0), res)

	// test with nevra
	nevra, _ := utils.ParseNevra("bash-0:5.4.20-1.el8_4.x86_64")
	evr := utils.Evr{
		Epoch:   nevra.Epoch,
		Version: nevra.Version,
		Release: nevra.Release,
	}
	c := Cache{
		Updates: map[NameID][]PkgID{1: {1, 2, 3, 4, 5, 6, 7}},
		PackageDetails: map[PkgID]PackageDetail{
			1: {ArchID: 3},
			2: {ArchID: 3},
			3: {ArchID: 3},
			4: {ArchID: 3},
			5: {ArchID: 3},
			6: {ArchID: 3},
			7: {ArchID: 3},
		},
		Packagename2ID: map[string]NameID{"bash": 1},
		Evr2ID:         map[utils.Evr]EvrID{evr: 2},
		Arch2ID:        map[string]ArchID{"x86_64": 3},
		UpdatesIndex:   map[NameID]map[EvrID][]int{1: {2: []int{5, 6, 7}}},
	}
	ids := extractNevraIDs(&c, &nevra) // returns ids=[5,6,7]
	res = nevraPkgID(&c, &ids)
	// the update should be 5th (first of ids) index in c.Updates -> PkgID=6
	assert.Equal(t, PkgID(6), res)

	// test with empty ids
	res = nevraPkgID(&c, &NevraIDs{})
	assert.Equal(t, PkgID(0), res)
}

func TestPkgReleasevers(t *testing.T) {
	el7 := "el7"
	el8 := "el8"
	el9 := "el9"
	c := Cache{
		PkgID2RepoIDs: map[PkgID][]RepoID{1: {1, 2, 3}, 2: {2, 3, 4}},
		RepoDetails: map[RepoID]RepoDetail{
			1: {ReleaseVer: nil},
			2: {ReleaseVer: &el7},
			3: {ReleaseVer: &el8},
			4: {ReleaseVer: &el9},
		},
	}

	res := pkgReleasevers(&c, 0)
	assert.Equal(t, map[string]bool{}, res)

	res = pkgReleasevers(&c, 1)
	assert.Equal(t, map[string]bool{"el7": true, "el8": true}, res)

	res = pkgReleasevers(&c, 2)
	assert.Equal(t, map[string]bool{"el7": true, "el8": true, "el9": true}, res)
}
