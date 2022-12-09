package vmaas

import (
	"fmt"
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
)

func hasDuplicities(in ...interface{}) bool {
	seen := map[string]bool{}
	for _, v := range in {
		vstring := fmt.Sprint(v)
		if seen[vstring] {
			return true
		}
		seen[vstring] = true
	}
	return false
}

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

func TestPassBasearch(t *testing.T) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Basearch: "x86_64"},
			3: {Basearch: "s390"},
		},
	}

	// nil baserarch, return input repos
	res := passBasearch(&c, nil, 0)
	assert.False(t, res)
	res = passBasearch(&c, nil, 1)
	assert.True(t, res)

	// filter by basearch
	x8664input := "x86_64" // use new variable to make sure we are not comparing pointers in function
	// repoID=0
	res = passBasearch(&c, &x8664input, 0)
	assert.False(t, res)

	// repos = {1,2,3}
	// filtered = {2}
	repos := []RepoID{1, 2, 3}
	for _, r := range repos {
		res = passBasearch(&c, &x8664input, r)
		if r == 2 {
			assert.True(t, res)
		} else {
			assert.False(t, res)
		}
	}

	// repo id which is not in cache
	res = passBasearch(&c, &x8664input, 99)
	assert.False(t, res)

	res = passBasearch(&c, nil, 99)
	assert.False(t, res)
}

func TestPassReleasever(t *testing.T) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el8"},
			3: {Releasever: "el9"},
		},
	}

	// nil releasever, return input repos
	res := passReleasever(&c, nil, 0)
	assert.False(t, res)
	res = passReleasever(&c, nil, 1)
	assert.True(t, res)

	// filter by Releasever
	el8input := "el8" // use new variable to make sure we are not comparing pointers in function
	// repoID=0
	res = passReleasever(&c, &el8input, 0)
	assert.False(t, res)

	// repos = {1,2,3}
	// filtered = {2}
	repos := []RepoID{1, 2, 3}
	for _, r := range repos {
		res = passReleasever(&c, &el8input, r)
		if r == 2 {
			assert.True(t, res)
		} else {
			assert.False(t, res)
		}
	}

	// repo id which is not in cache
	res = passReleasever(&c, &el8input, 99)
	assert.False(t, res)

	res = passReleasever(&c, nil, 99)
	assert.False(t, res)
}

func TestGetRepoIDs(t *testing.T) {
	updates := Updates{}
	x8664 := "x86_64"
	el9 := "el9"
	other := "other"
	c := Cache{
		RepoIDs: []RepoID{1, 2, 3},
		RepoDetails: map[RepoID]RepoDetail{
			1: {Releasever: x8664, Basearch: el9},
			2: {Releasever: x8664, Basearch: el9},
			3: {Releasever: x8664, Basearch: el9},
		},
	}

	// empty repolist, return all repos available in cache
	res := getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))

	// empty repolist, with releasever
	updates.Releasever = &x8664
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))
	updates.Releasever = nil

	// labels to ids
	c.RepoLabel2IDs = map[string][]RepoID{
		"repo1": {1, 2},
		"repo2": {2, 3},
	}
	updates.RepoList = []string{"repo1", "repo2"}
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))

	// releasever & basearch
	updates.Releasever = &x8664
	updates.Basearch = &el9
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))

	updates.Basearch = nil
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))

	updates.Basearch = &other
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 0, len(res))
	assert.False(t, hasDuplicities(res))

	// repository paths
	c.RepoIDs = append(c.RepoIDs, 4)
	c.RepoDetails[4] = RepoDetail{
		Releasever: x8664,
		Basearch:   el9,
		URL:        "http://example.com/content/dist/rhel/rhui/server/7/7Server/x86_64/os/repodata",
	}
	c.RepoPath2IDs = map[string][]RepoID{
		"/content/dist/rhel/rhui/server/7/7Server/x86_64/os": {4},
	}
	updates.Releasever = nil
	updates.Basearch = nil
	updates.RepoPaths = []string{"/content/dist/rhel/rhui/server/7/7Server/x86_64/os/"}
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 4, len(res))
	assert.False(t, hasDuplicities(res))
	updates.RepoPaths = []string{}

	// invalid label
	updates.RepoList = []string{"invalid"}
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, []RepoID{}, res)

	updates.Basearch = nil
	updates.Releasever = nil
	updates.RepoList = []string{"invalid"}
	res = getRepoIDs(&c, &updates)
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
	ids := extractNevraIDs(&c, &nevra) // ids.EvrIDs=[5, 6, 7]
	res = nevraPkgID(&c, &ids)
	// the update should be 5th (first of ids) index in c.Updates -> PkgID=6
	assert.Equal(t, PkgID(6), res)

	// test with empty ids
	res = nevraPkgID(&c, &NevraIDs{})
	assert.Equal(t, PkgID(0), res)
}

func TestPkgReleasevers(t *testing.T) {
	c := Cache{
		PkgID2RepoIDs: map[PkgID][]RepoID{1: {1, 2, 3}, 2: {2, 3, 4}},
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el7"},
			3: {Releasever: "el8"},
			4: {Releasever: "el9"},
		},
	}

	res := pkgReleasevers(&c, 0)
	assert.Equal(t, map[string]bool{}, res)

	res = pkgReleasevers(&c, 1)
	assert.Equal(t, map[string]bool{"": true, "el7": true, "el8": true}, res)

	res = pkgReleasevers(&c, 2)
	assert.Equal(t, map[string]bool{"el7": true, "el8": true, "el9": true}, res)
}

func TestNevraUpdates(t *testing.T) {
	updates, releasevers := nevraUpdates(nil, nil)
	assert.Nil(t, updates)
	assert.Nil(t, releasevers)

	// cache init
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
		UpdatesIndex:   map[NameID]map[EvrID][]int{1: {2: []int{2, 3, 4}}},
		PkgID2RepoIDs:  map[PkgID][]RepoID{1: {1, 2, 3}, 2: {2, 3, 4}, 3: {3, 4}},
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el7"},
			3: {Releasever: "el8"},
			4: {Releasever: "el9"},
		},
	}

	ids := extractNevraIDs(&c, &nevra) // ids.NameID=1, EvrIDs=[2, 3, 4], ArchID=3
	updates, releasevers = nevraUpdates(&c, &ids)
	// releasevers for PkgID=3
	assert.Equal(t, map[string]bool{"el8": true, "el9": true}, releasevers)
	// update for PkgID=3
	assert.Equal(t, []PkgID{6, 7}, updates)
}

func TestOptimisticUpdates(t *testing.T) {
	nevra, _ := utils.ParseNevra("pkg-0:1.1.2-1.el8.x86_64")
	nevraIDs := NevraIDs{NameID: 1, EvrIDs: []int{2, 3, 4}}
	c := Cache{
		Updates: map[NameID][]PkgID{1: {1, 2, 3, 4}},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 3},
			2: {NameID: 1, EvrID: 2, ArchID: 3},
			3: {NameID: 1, EvrID: 3, ArchID: 3},
			4: {NameID: 1, EvrID: 4, ArchID: 3},
		},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1.1.1", Release: "1"},
			2: {Epoch: 0, Version: "1.1.2", Release: "1"},
			3: {Epoch: 0, Version: "1.1.3", Release: "1"},
			4: {Epoch: 0, Version: "1.1.4", Release: "1"},
		},
	}
	res := optimisticUpdates(&c, &nevraIDs, &nevra)
	assert.Equal(t, []PkgID{3, 4}, res)
}

func TestBuildNevra(t *testing.T) {
	c := Cache{
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1},
			2: {NameID: 1, EvrID: 2, ArchID: 2},
			3: {NameID: 2, EvrID: 1, ArchID: 1},
			4: {NameID: 2, EvrID: 2, ArchID: 2},
		},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1.1.1", Release: "1"},
			2: {Epoch: 0, Version: "1.1.2", Release: "1"},
		},
		ID2Packagename: map[NameID]string{1: "bash", 2: "kernel"},
		ID2Arch:        map[ArchID]string{1: "x86_64", 2: "aarch64"},
	}

	res := buildNevra(&c, 0)
	assert.Equal(t, utils.Nevra{}, res)

	res = buildNevra(&c, 3)
	nevra := utils.Nevra{
		Name:    "kernel",
		Epoch:   0,
		Version: "1.1.1",
		Release: "1",
		Arch:    "x86_64",
	}
	assert.Equal(t, nevra, res)

}

func TestIsRepoValid(t *testing.T) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el9"},
		},
	}

	res := isRepoValid(&c, 0, nil)
	assert.False(t, res)

	res = isRepoValid(&c, 0, map[string]bool{"el8": true})
	assert.False(t, res)

	res = isRepoValid(&c, 0, map[string]bool{"el9": true})
	assert.False(t, res)

	res = isRepoValid(&c, 1, map[string]bool{"el8": true})
	assert.False(t, res)

	res = isRepoValid(&c, 2, map[string]bool{"el8": true})
	assert.False(t, res)

	res = isRepoValid(&c, 2, map[string]bool{"el9": true})
	assert.True(t, res)

	res = isRepoValid(&c, 2, nil)
	assert.True(t, res)
}

func TestFilterRepositories(t *testing.T) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el7"},
			3: {Releasever: "el8"},
			4: {Releasever: "el9"},
		},
		ErrataID2RepoIDs: map[ErrataID][]RepoID{
			1: {1, 2},
			2: {2, 3, 4},
		},
		PkgID2RepoIDs: map[PkgID][]RepoID{
			1: {1, 2},
			2: {3, 4},
		},
	}

	repos := []RepoID{1, 2, 3, 4}
	releasevers := map[string]bool{"el7": true, "el9": true}
	res := filterRepositories(&c, 0, 0, []RepoID{}, nil)
	assert.Equal(t, 0, len(res))

	res = filterRepositories(&c, 1, 1, repos, releasevers)
	// only el7 repo for pkg=1, erratum=1
	assert.Equal(t, []RepoID{2}, res)

	res = filterRepositories(&c, 2, 2, repos, releasevers)
	// only el9 repo for pkg=2, erratum=2, because of el7, el9 in releasevers
	assert.Equal(t, []RepoID{4}, res)

	res = filterRepositories(&c, 2, 2, repos, nil)
	// el8, el9 repo for pkg=2, erratum=2
	assert.Equal(t, []RepoID{3, 4}, res)
}

func TestFilterNonSecurity(t *testing.T) {
	res := filterNonSecurity(ErrataDetail{}, false)
	assert.False(t, res)

	res = filterNonSecurity(ErrataDetail{}, true)
	assert.True(t, res)

	res = filterNonSecurity(ErrataDetail{Type: "security"}, true)
	assert.False(t, res)

	res = filterNonSecurity(ErrataDetail{CVEs: []string{"cve"}}, true)
	assert.False(t, res)

	res = filterNonSecurity(ErrataDetail{Type: "bugfix"}, true)
	assert.True(t, res)

	res = filterNonSecurity(ErrataDetail{Type: "bugfix", CVEs: []string{"cve"}}, true)
	assert.False(t, res)
}

func TestProcessInputPackages(t *testing.T) {
	c := Cache{
		Packagename2ID: map[string]NameID{
			"invalid": 1,
			"bash":    2,
		},
		UpdatesIndex: map[NameID]map[EvrID][]int{
			1: {1: []int{2, 3, 4}},
			2: {1: []int{2, 3, 4}},
		},
	}

	pkgs, updates := processInputPackages(&c, nil)
	assert.Equal(t, 0, len(pkgs))
	assert.Equal(t, 0, len(updates))

	pkgs, updates = processInputPackages(&c, &Request{})
	assert.Equal(t, 0, len(pkgs))
	assert.Equal(t, 0, len(updates))

	req := Request{
		Packages: []string{
			"invalid", // invalid, should not be in pkgs list but it should be in update list with empty updates
			"bash-0:4.4.20-1.el8_4.x86_64",
			"bash-0:5.4.20-1.el8_4.x86_64",
		},
	}
	pkgs, updates = processInputPackages(&c, &req)
	assert.Equal(t, 2, len(pkgs))
	_, ok := pkgs["bash-0:4.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)
	_, ok = pkgs["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)

	assert.Equal(t, 3, len(updates))
	_, ok = updates["invalid"]
	assert.True(t, ok)
	_, ok = updates["bash-0:4.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)
	_, ok = updates["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)

	req.LatestOnly = true
	pkgs, updates = processInputPackages(&c, &req)
	assert.Equal(t, 1, len(pkgs))
	assert.Equal(t, 1, len(updates))
	_, ok = pkgs["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)
	_, ok = updates["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)
}
