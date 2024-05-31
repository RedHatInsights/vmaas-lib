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
	packages := map[string]bool{"bash": true, "kernel": true}
	errata := map[string]bool{"RHBA-1234-5678": true}
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

func testReleaseverBasearch(t *testing.T, f func(*Cache, *string, RepoID) bool, input string) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Basearch: "x86_64", Releasever: "el8"},
			3: {Basearch: "s390", Releasever: "el9"},
		},
	}

	// nil basearch/releasever, return input repos
	res := f(&c, nil, 0)
	assert.False(t, res)
	res = f(&c, nil, 1)
	assert.True(t, res)

	// filter by basearch/releasever
	// repoID=0
	res = f(&c, &input, 0)
	assert.False(t, res)

	// repos = {1,2,3}
	// filtered = {2}
	repos := []RepoID{1, 2, 3}
	for _, r := range repos {
		res = f(&c, &input, r)
		if r == 2 {
			assert.True(t, res)
		} else {
			assert.False(t, res)
		}
	}

	// repo id which is not in cache
	res = f(&c, &input, 99)
	assert.False(t, res)

	res = f(&c, nil, 99)
	assert.False(t, res)
}

func TestPassBasearch(t *testing.T) {
	testReleaseverBasearch(t, passBasearch, "x86_64")
}

func TestPassReleasever(t *testing.T) {
	testReleaseverBasearch(t, passReleasever, "el8")
}

//nolint:funlen
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

	// missing repolist, return all repos available in cache
	res := getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))

	// missing repolist, with releasever
	updates.Releasever = &x8664
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 3, len(res))
	assert.False(t, hasDuplicities(res))
	updates.Releasever = nil

	// empty repolist, empty response
	repolist := []string{}
	updates.RepoList = &repolist
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 0, len(res))

	// labels to ids
	c.RepoLabel2IDs = map[string][]RepoID{
		"repo1": {1, 2},
		"repo2": {2, 3},
	}
	repolist = []string{"repo1", "repo2"}
	updates.RepoList = &repolist
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
	invalidRepolist := []string{"invalid"}
	updates.RepoList = &invalidRepolist
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 0, len(res))

	updates.Basearch = nil
	updates.Releasever = nil
	updates.RepoList = &invalidRepolist
	res = getRepoIDs(&c, &updates)
	assert.Equal(t, 0, len(res))
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
	nevra, _ := utils.ParseNevra("bash-0:5.4.20-1.el8_4.x86_64", false)
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
	nevra, _ := utils.ParseNevra("bash-0:5.4.20-1.el8_4.x86_64", false)
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

func TestNevraUpdates(t *testing.T) {
	updates, _ := nevraUpdates(nil, nil, nil, nil)
	assert.Nil(t, updates)

	// cache init
	nevra, _ := utils.ParseNevra("bash-0:5.4.20-1.el8_4.x86_64", false)
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
	updates, _ = nevraUpdates(&c, &ids, nil, nil)
	// update for PkgID=3
	assert.Equal(t, []PkgID{6, 7}, updates)
}

func TestOptimisticUpdates(t *testing.T) {
	nevra, _ := utils.ParseNevra("pkg-0:1.1.2-1.el8.x86_64", false)
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

func TestFilterRepositories(t *testing.T) {
	c := Cache{
		RepoDetails: map[RepoID]RepoDetail{
			1: {},
			2: {Releasever: "el7"},
			3: {Releasever: "el8"},
			4: {Releasever: "el9"},
		},
		ErratumID2RepoIDs: map[ErratumID]map[RepoID]bool{
			1: {1: true, 2: true},
			2: {2: true, 3: true, 4: true},
		},
		PkgID2RepoIDs: map[PkgID][]RepoID{
			1: {1, 2},
			2: {3, 4},
		},
	}

	repos := map[RepoID]bool{1: true, 2: true, 3: true, 4: true}
	repoIDs := repositoriesByPkgs(&c, &defaultOpts, []PkgID{0}, map[RepoID]bool{})
	res := filterErrataRepos(&c, 0, repoIDs)
	assert.Equal(t, 0, len(res))

	repoIDs = repositoriesByPkgs(&c, &defaultOpts, []PkgID{1}, repos)
	res = filterErrataRepos(&c, 1, repoIDs)
	// el7 repo and repo without releasever for pkg=1, erratum=1
	assert.Equal(t, []RepoID{1, 2}, res)

	repoIDs = repositoriesByPkgs(&c, &defaultOpts, []PkgID{2}, repos)
	res = filterErrataRepos(&c, 2, repoIDs)
	// el8, el9 repo for pkg=2, erratum=2
	assert.Equal(t, []RepoID{3, 4}, res)
}

func TestFilterNonSecurity(t *testing.T) {
	res := filterNonSecurity(ErratumDetail{}, false)
	assert.False(t, res)

	res = filterNonSecurity(ErratumDetail{}, true)
	assert.True(t, res)

	res = filterNonSecurity(ErratumDetail{Type: "security"}, true)
	assert.False(t, res)

	res = filterNonSecurity(ErratumDetail{CVEs: []string{"cve"}}, true)
	assert.False(t, res)

	res = filterNonSecurity(ErratumDetail{Type: "bugfix"}, true)
	assert.True(t, res)

	res = filterNonSecurity(ErratumDetail{Type: "bugfix", CVEs: []string{"cve"}}, true)
	assert.False(t, res)
}

//nolint:funlen
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

	pkgs, updates, err := processInputPackages(&c, nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(pkgs))
	assert.Equal(t, 0, len(updates))

	pkgs, updates, err = processInputPackages(&c, &Request{})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(pkgs))
	assert.Equal(t, 0, len(updates))

	req := Request{
		Packages: []string{
			"invalid", // invalid, should not be in pkgs list but it should be in update list with empty updates
			"bash-0:5.4.20-1.el8_4.x86_64",
			"bash-0:4.4.20-1.el8_4.x86_64",
		},
		EpochRequired: true,
	}
	pkgs, updates, err = processInputPackages(&c, &req)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(pkgs))
	// should be sorted in the result list
	assert.Equal(t, pkgs[0].Pkg, "bash-0:4.4.20-1.el8_4.x86_64")
	assert.Equal(t, pkgs[1].Pkg, "bash-0:5.4.20-1.el8_4.x86_64")

	assert.Equal(t, 3, len(updates))
	_, ok := updates["invalid"]
	assert.True(t, ok)
	_, ok = updates["bash-0:4.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)
	_, ok = updates["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)

	req.LatestOnly = true
	pkgs, updates, err = processInputPackages(&c, &req)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(pkgs))
	assert.Equal(t, 1, len(updates))
	assert.Equal(t, pkgs[0].Pkg, "bash-0:5.4.20-1.el8_4.x86_64")
	_, ok = updates["bash-0:5.4.20-1.el8_4.x86_64"]
	assert.True(t, ok)

	req = Request{
		Packages: []string{
			"invalid", // invalid, should not be in pkgs list but it should be in update list with empty updates
			"bash-4.4.20-1.el8_4.x86_64",
			"bash-5.4.20-1.el8_4.x86_64",
		},
		EpochRequired: true,
	}
	pkgs, updates, err = processInputPackages(&c, &req)
	assert.Error(t, err)
	assert.Equal(t, 0, len(pkgs))
	assert.Equal(t, 0, len(updates))

	req = Request{
		Packages: []string{
			"invalid", // invalid, should not be in pkgs list but it should be in update list with empty updates
			"bash-4.4.20-1.el8_4.x86_64",
			"bash-5.4.20-1.el8_4.x86_64",
		},
		EpochRequired: false,
	}
	pkgs, updates, err = processInputPackages(&c, &req)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(pkgs))
	assert.Equal(t, 3, len(updates))
}

func TestPkgID2Nevra(t *testing.T) {
	c := Cache{
		ID2Arch:        map[ArchID]string{1: "x86_64"},
		ID2Packagename: map[NameID]string{1: "kernel"},
		ID2Evr:         map[EvrID]utils.Evr{1: {Epoch: 0, Version: "1", Release: "2"}},
		PackageDetails: map[PkgID]PackageDetail{1: {NameID: 1, EvrID: 1, ArchID: 1}},
	}

	expected := utils.Nevra{Name: "kernel", Epoch: 0, Version: "1", Release: "2", Arch: "x86_64"}
	nevra := pkgID2Nevra(&c, 1)
	assert.Equal(t, expected, nevra)
}

func TestIsApplicabe(t *testing.T) {
	c := Cache{
		Arch2ID: map[string]ArchID{"noarch": 1, "x86_64": 2, "aarch64": 3},
		ID2Arch: map[ArchID]string{1: "noarch", 2: "x86_64", 3: "aarch64"},
		ArchCompat: map[ArchID]map[ArchID]bool{
			1: {1: true, 2: true, 3: true},
			2: {1: true, 2: true},
			3: {1: true, 3: true},
		},
		ID2Packagename: map[NameID]string{1: "kernel", 2: "bash"},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1", Release: "1"},
			2: {Epoch: 0, Version: "2", Release: "2"},
		},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1}, // kernel, noarch
			2: {NameID: 1, EvrID: 1, ArchID: 2}, // kernel, x86_64
			3: {NameID: 1, EvrID: 1, ArchID: 3}, // kernel, aarch64
			4: {NameID: 1, EvrID: 2, ArchID: 1}, // kernel, noarch, newer
			5: {NameID: 1, EvrID: 2, ArchID: 2}, // kernel, x86_64, newer
			6: {NameID: 1, EvrID: 2, ArchID: 3}, // kernel, aarch64, newer
			7: {NameID: 2, EvrID: 2, ArchID: 1}, // bash
		},
	}

	kernelNoarch := pkgID2Nevra(&c, 1)
	kernelX86 := pkgID2Nevra(&c, 2)
	kernelAarch := pkgID2Nevra(&c, 3)
	kernelNoarchNew := pkgID2Nevra(&c, 4)
	kernelX86New := pkgID2Nevra(&c, 5)
	kernelAarchNew := pkgID2Nevra(&c, 6)
	bash := pkgID2Nevra(&c, 7)

	// newer noarch is applicable to all other archs
	assert.True(t, isApplicable(&c, &kernelNoarchNew, &kernelNoarch))
	assert.True(t, isApplicable(&c, &kernelNoarchNew, &kernelX86))
	assert.True(t, isApplicable(&c, &kernelNoarchNew, &kernelAarch))
	// newer x86_64 kernel can be applied only on x86_64 or noarch
	assert.True(t, isApplicable(&c, &kernelX86New, &kernelX86))
	assert.True(t, isApplicable(&c, &kernelX86New, &kernelNoarch))
	// x86_64 cannot be applied on aarch64 and vice versa
	assert.False(t, isApplicable(&c, &kernelX86New, &kernelAarch))
	assert.False(t, isApplicable(&c, &kernelAarchNew, &kernelX86))
	// same or older version cannot be applied
	assert.False(t, isApplicable(&c, &kernelNoarch, &kernelNoarch))
	assert.False(t, isApplicable(&c, &kernelX86, &kernelX86))
	assert.False(t, isApplicable(&c, &kernelAarch, &kernelAarch))
	assert.False(t, isApplicable(&c, &kernelNoarch, &kernelNoarchNew))
	assert.False(t, isApplicable(&c, &kernelX86, &kernelX86New))
	assert.False(t, isApplicable(&c, &kernelAarch, &kernelAarchNew))
	assert.False(t, isApplicable(&c, &kernelNoarch, &kernelX86))
	assert.False(t, isApplicable(&c, &kernelNoarch, &kernelAarchNew))
	// bash cannot be update for kernel or kernel for bash
	assert.False(t, isApplicable(&c, &bash, &kernelNoarch))
	assert.False(t, isApplicable(&c, &kernelNoarchNew, &bash))
}
