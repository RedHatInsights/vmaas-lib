package vmaas

import (
	"fmt"
	"sort"
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

//nolint:funlen
func TestCSAF(t *testing.T) {
	ms := ModuleStream{Module: "name", Stream: "stream"}
	unfixed1 := CSAFProduct{CpeID: 1, PackageNameID: 1, VariantSuffix: DefaultVariantSuffix}
	unfixed2 := CSAFProduct{CpeID: 2, PackageNameID: 1, ModuleStream: ms, VariantSuffix: DefaultVariantSuffix}
	fixed1 := CSAFProduct{CpeID: 1, PackageNameID: 1, PackageID: 1, VariantSuffix: DefaultVariantSuffix}
	fixed2 := CSAFProduct{CpeID: 2, PackageNameID: 1, PackageID: 2, ModuleStream: ms, VariantSuffix: DefaultVariantSuffix}
	var one PkgID = 1

	c := Cache{
		Arch2ID:        map[string]ArchID{"x86_64": 1},
		ID2Arch:        map[ArchID]string{1: "x86_64"},
		ID2Packagename: map[NameID]string{1: "kernel", 2: "kernel-devel"},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1", Release: "1"},
			2: {Epoch: 0, Version: "2", Release: "2"},
		},
		Evr2ID: map[utils.Evr]EvrID{
			{Epoch: 0, Version: "1", Release: "1"}: 1,
			{Epoch: 0, Version: "2", Release: "2"}: 2,
		},
		Nevra2PkgID: map[Nevra]PkgID{
			{NameID: 1, EvrID: 1, ArchID: 1}: 1,
			{NameID: 1, EvrID: 2, ArchID: 1}: 2,
			{NameID: 2, EvrID: 1, ArchID: 1}: 3,
		},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1, SrcPkgID: nil},  // kernel-0:1-1
			2: {NameID: 1, EvrID: 2, ArchID: 1, SrcPkgID: nil},  // kernel-0:2-2
			3: {NameID: 2, EvrID: 1, ArchID: 1, SrcPkgID: &one}, // kernel-devel-0:1-1
		},
		CSAFProduct2ID: map[CSAFProduct]CSAFProductID{
			unfixed1: 1,
			unfixed2: 2,
			fixed1:   3,
			fixed2:   4,
		},
		CSAFProductID2Product: map[CSAFProductID]CSAFProduct{
			1: unfixed1,
			2: unfixed2,
			3: fixed1,
			4: fixed2,
		},
		CSAFCVEs: map[VariantSuffix]map[CpeIDNameID]map[CSAFProductID]CSAFCVEs{
			DefaultVariantSuffix: {
				{CpeID: 1, NameID: 1}: {
					1: {Unfixed: []CVEID{1, 2}},
					3: {Fixed: []CVEID{3, 4}},
				},
				{CpeID: 2, NameID: 1}: {
					2: {Unfixed: []CVEID{1, 2}},
					4: {Fixed: []CVEID{5}},
				},
			},
		},
		CveNames: map[int]string{
			1: "CVE-1", 2: "CVE-2", 3: "CVE-3", 4: "CVE-4", 5: "CVE-5",
		},
	}

	type expected struct {
		pkg     NevraString
		nameID  NameID
		pkgID   PkgID
		fixed   []CSAFProductID
		unfixed []CSAFProductID
	}
	pkg1 := utils.Nevra{Name: "kernel", Epoch: 0, Version: "1", Release: "1", Arch: "x86_64"}
	pkg2 := utils.Nevra{Name: "kernel", Epoch: 0, Version: "2", Release: "2", Arch: "x86_64"}
	pkg3 := utils.Nevra{Name: "kernel-devel", Epoch: 0, Version: "1", Release: "1", Arch: "x86_64"}
	matrix := []expected{
		{
			pkg:     NevraString{Nevra: pkg1, Pkg: pkg1.String()},
			nameID:  1,
			pkgID:   1,
			unfixed: []CSAFProductID{1, 2},
			fixed:   []CSAFProductID{3, 4},
		},
		{
			pkg:     NevraString{Nevra: pkg2, Pkg: pkg2.String()},
			nameID:  1,
			pkgID:   2,
			unfixed: []CSAFProductID{1, 2},
			fixed:   []CSAFProductID{3, 4},
		},
		{
			pkg:     NevraString{Nevra: pkg3, Pkg: pkg3.String()},
			nameID:  2,
			pkgID:   3,
			unfixed: []CSAFProductID{1, 2},
			fixed:   []CSAFProductID{},
		}, // match source package
	}

	products := make([]ProductsPackage, 0, len(matrix))
	for _, m := range matrix {
		pp := cpes2products(&c, []VariantSuffix{DefaultVariantSuffix}, []CpeID{1, 2}, m.nameID, m.pkgID,
			[]ModuleStream{ms}, m.pkg, &defaultOpts)
		assert.Equal(t, m.fixed, pp.ProductsFixed)
		assert.Equal(t, m.unfixed, pp.ProductsUnfixed)
		// duplicate products to cover code handling duplicates
		pp.ProductsFixed = append(pp.ProductsFixed, pp.ProductsFixed...)
		pp.ProductsUnfixed = append(pp.ProductsUnfixed, pp.ProductsUnfixed...)
		products = append(products, pp)
	}

	cves := VulnerabilitiesCvesDetails{
		Cves:          make(map[string]VulnerabilityDetail),
		ManualCves:    make(map[string]VulnerabilityDetail),
		UnpatchedCves: make(map[string]VulnerabilityDetail),
	}
	evaluateUnpatchedCves(&c, products, &cves)
	evaluateManualCves(&c, products, &cves, map[string]VulnerabilityDetail{}, &defaultOpts)

	unpatchedCves := maps.Keys(cves.UnpatchedCves)
	manualCves := maps.Keys(cves.ManualCves)
	sort.Slice(unpatchedCves, func(i, j int) bool { return unpatchedCves[i] < unpatchedCves[j] })
	sort.Slice(manualCves, func(i, j int) bool { return manualCves[i] < manualCves[j] })
	// CVEs from `unfixed` product
	assert.Equal(t, []string{"CVE-1", "CVE-2"}, unpatchedCves)
	// CVEs from `fixed2` product, `fixed1` is not an update (kernel-1.1-1 to kernel-1.1-1)
	assert.Equal(t, []string{"CVE-5"}, manualCves)
}

func TestCPEMatch(t *testing.T) {
	type cpeTest struct {
		pattern  CpeLabel
		repoCpe  CpeLabel
		expected bool
	}
	el := CpeLabel("cpe:/o:redhat:enterprise_linux")
	el8 := CpeLabel("cpe:/o:redhat:enterprise_linux:8")
	el9 := CpeLabel("cpe:/o:redhat:enterprise_linux:9")
	el9Baseos := CpeLabel("cpe:/o:redhat:enterprise_linux:9::baseos")
	el9BaseosA := CpeLabel("cpe:/a:redhat:enterprise_linux:9::baseos")
	eus := CpeLabel("cpe:/o:redhat:rhel_eus")
	sat6 := CpeLabel("cpe:/a:redhat:satellite:6")
	sat610el7 := CpeLabel("cpe:/a:redhat:satellite:6.10::el7")
	cpeO := CpeLabel("cpe:/o")
	cpeMissingPart := CpeLabel("cpe:/")
	cpeRh := CpeLabel("cpe:/o:redhat")
	cpeNotRh := CpeLabel("cpe:/o:not_redhat")
	cpeUpdate1 := CpeLabel("cpe:/o::::update1")
	cpeUpdate2 := CpeLabel("cpe:/o::::update2")

	cpeTests := []cpeTest{
		{el, el8, true},
		{el, el9, true},
		{el, el9Baseos, true},
		{el, el9BaseosA, true},
		{el, eus, false},
		{el8, el, false},
		{el8, el9, false},
		{el8, el9Baseos, false},
		{el8, el9BaseosA, false},
		{el8, el8, true},
		{el9, el9Baseos, true},
		{el9, el9BaseosA, true},
		{el9, el, false},
		{el9, el8, false},
		{el9Baseos, el, false},
		{el9Baseos, el9, false},
		{el9BaseosA, el, false},
		{el9BaseosA, el8, false},
		{el9BaseosA, el9, false},
		{el9BaseosA, el9Baseos, false},
		{sat6, sat610el7, true},
		{sat610el7, sat6, false},
		{cpeO, cpeMissingPart, false},
		{cpeRh, cpeNotRh, false},
		{cpeUpdate1, cpeUpdate2, false},
	}
	for _, test := range cpeTests {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			res := cpeMatch(test.pattern, test.repoCpe)
			assert.Equal(t, test.expected, res)
		})
	}
}

//nolint:funlen
func TestManualCvesNewerRelease(t *testing.T) {
	ms := ModuleStream{Module: "name", Stream: "stream"}
	productCveFixed := CSAFProduct{CpeID: 1, PackageNameID: 1, PackageID: 1, VariantSuffix: DefaultVariantSuffix}
	productCve1 := CSAFProduct{CpeID: 1, PackageNameID: 1, PackageID: 2, VariantSuffix: DefaultVariantSuffix}
	productCve3 := CSAFProduct{CpeID: 1, PackageNameID: 1, PackageID: 5, VariantSuffix: DefaultVariantSuffix}
	productCveFixedNewer := CSAFProduct{
		CpeID: 2, PackageNameID: 1, PackageID: 3, ModuleStream: ms,
		VariantSuffix: DefaultVariantSuffix,
	}
	productCve1Newer := CSAFProduct{
		CpeID: 2, PackageNameID: 1, PackageID: 4, ModuleStream: ms,
		VariantSuffix: DefaultVariantSuffix,
	}
	productCve2Newer := CSAFProduct{
		CpeID: 2, PackageNameID: 1, PackageID: 5, ModuleStream: ms,
		VariantSuffix: DefaultVariantSuffix,
	}
	currentReleaseCPE := CpeLabel("cpe:/o:redhat:rhel_eus:8.6")
	newerReleaseCPE := CpeLabel("cpe:/o:redhat:rhel_eus:8.8")
	c := Cache{
		Arch2ID:        map[string]ArchID{"x86_64": 1},
		ID2Arch:        map[ArchID]string{1: "x86_64"},
		ArchCompat:     map[ArchID]map[ArchID]bool{1: {1: true}},
		ID2Packagename: map[NameID]string{1: "pkg"},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1", Release: "0"},
			2: {Epoch: 0, Version: "1", Release: "1"},
			3: {Epoch: 0, Version: "1", Release: "2"},
			4: {Epoch: 0, Version: "1", Release: "3"},
			5: {Epoch: 0, Version: "1", Release: "4"},
		},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1, SummaryID: 1, DescriptionID: 1},
			2: {NameID: 1, EvrID: 2, ArchID: 1, SummaryID: 1, DescriptionID: 1},
			3: {NameID: 1, EvrID: 3, ArchID: 1, SummaryID: 1, DescriptionID: 1},
			4: {NameID: 1, EvrID: 4, ArchID: 1, SummaryID: 1, DescriptionID: 1},
			5: {NameID: 1, EvrID: 5, ArchID: 1, SummaryID: 1, DescriptionID: 1},
		},

		CpeID2Label: map[CpeID]CpeLabel{1: currentReleaseCPE, 2: newerReleaseCPE},
		CveNames:    map[int]string{1: "CVE-1", 2: "CVE-2", 3: "CVE-3", 4: "CVE-4", 5: "CVE-FIXED"},
		CSAFProduct2ID: map[CSAFProduct]CSAFProductID{
			productCve1:          1,
			productCve3:          2,
			productCve1Newer:     3,
			productCve2Newer:     4,
			productCveFixed:      5,
			productCveFixedNewer: 6,
		},
		CSAFProductID2Product: map[CSAFProductID]CSAFProduct{
			1: productCve1,
			2: productCve3,
			3: productCve1Newer,
			4: productCve2Newer,
			5: productCveFixed,
			6: productCveFixedNewer,
		},
		CSAFCVEProduct2Erratum: map[CSAFCVEProduct]string{
			{1, 1}: "RHSA-1",
			{3, 2}: "RHSA-2",
			{1, 3}: "RHSA-3",
			{2, 4}: "RHSA-4",
		},
		CSAFCVEs: map[VariantSuffix]map[CpeIDNameID]map[CSAFProductID]CSAFCVEs{
			DefaultVariantSuffix: {
				{1, 1}: {
					1: {Fixed: []CVEID{1}},
					2: {Fixed: []CVEID{3}},
					5: {Fixed: []CVEID{5}},
				},
				{2, 1}: {
					3: {Fixed: []CVEID{1}},
					4: {Fixed: []CVEID{2}},
					6: {Fixed: []CVEID{5}},
				},
			},
		},
	}
	products := []ProductsPackage{
		{
			ProductsFixed: []CSAFProductID{
				5, // productCveFixed - fixing CVE-FIXED, should not show up as it is already fixed in current release
				1, // productCve1 - fixing CVE-1, RHSA-1
				2, // productCve3 - fixing CVE-3, RHSA-2
			},
			ProductsFixedNewerRelease: []CSAFProductID{
				6, // productCveFixedNewer - CVE-FIXED, fixed pkg has higher NEVRA but it is already fixed
				3, // productCve1Newer - fixing CVE-1, RHSA-3
				4, // productCve2Newer - fixing CVE-2, RHSA-4
			},
			Package: Package{
				Nevra:  utils.Nevra{Name: "pkg", Epoch: 0, Version: "1", Release: "0", Arch: "x86_64"},
				String: "pkg-0:1.0.x86_64", NameID: 1,
			},
		},
	}
	newerReleaseReposCves := map[string]VulnerabilityDetail{
		// ingored, CVE-FIXED is already fixed in the current release
		"CVE-FIXED": {
			CVE: "CVE-FIXED", Packages: map[string]bool{"pkg-0:1.0.x86_64": true},
			Errata: map[string]bool{"RHSA-5": true},
		},
		// updated, CVE-1 is found as fixed from CSAF in current release, it is updated with erratum from repos
		"CVE-1": {
			CVE: "CVE-1", Packages: map[string]bool{"pkg-0:1.0.x86_64": true},
			Errata: map[string]bool{"RHSA-6": true},
		},
		// appended, CVE-4 is not found by CSAF
		"CVE-4": {
			CVE: "CVE-4", Packages: map[string]bool{"pkg-0:1.0.x86_64": true},
			Errata: map[string]bool{"RHSA-8": true},
		},
	}

	cves := VulnerabilitiesCvesDetails{
		Cves:          make(map[string]VulnerabilityDetail),
		ManualCves:    make(map[string]VulnerabilityDetail),
		UnpatchedCves: make(map[string]VulnerabilityDetail),
	}
	evaluateManualCves(&c, products, &cves, newerReleaseReposCves, &defaultOpts)

	expectedCves := []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4"}
	assert.Empty(t, cves.Cves)
	assert.Empty(t, cves.UnpatchedCves)
	assert.Len(t, cves.ManualCves, len(expectedCves))
	// CVE-FIXED is not affecting the system, it is fixed by already installed package
	assert.NotContains(t, cves.ManualCves, "CVE-FIXED")
	// CVE-1, CVE-2, CVE-3, CVE-4 should be reported
	for _, cve := range expectedCves {
		assert.Contains(t, cves.ManualCves, cve)
	}
	// CVE-1 is reported from both (current, newer) CPEs and is fixed by
	// RHSA-1 (current release CSAF), RHSA-3 (newer release CSAF), RHSA-5 (newer release Repos)
	require.Len(t, cves.ManualCves["CVE-1"].Errata, 3)
	assert.Contains(t, cves.ManualCves["CVE-1"].Errata, "RHSA-1")
	assert.Contains(t, cves.ManualCves["CVE-1"].Errata, "RHSA-3")
	assert.Contains(t, cves.ManualCves["CVE-1"].Errata, "RHSA-6")
	assert.Len(t, cves.ManualCves["CVE-1"].Affected, 2)
	assert.Equal(t, cves.ManualCves["CVE-1"].Affected[0].Cpe, currentReleaseCPE)
	assert.Equal(t, cves.ManualCves["CVE-1"].Affected[1].Cpe, newerReleaseCPE)
	assert.Equal(t, *cves.ManualCves["CVE-1"].Affected[1].Module, ms.Module)
	assert.Equal(t, *cves.ManualCves["CVE-1"].Affected[1].Stream, ms.Stream)
	// CVE-2 is reported from newer release CPE (CSAF) and is fixed by RHSA-4
	assert.Len(t, cves.ManualCves["CVE-2"].Errata, 1)
	assert.Contains(t, cves.ManualCves["CVE-2"].Errata, "RHSA-4")
	assert.Len(t, cves.ManualCves["CVE-2"].Affected, 1)
	assert.Equal(t, cves.ManualCves["CVE-2"].Affected[0].Cpe, newerReleaseCPE)
	assert.Equal(t, *cves.ManualCves["CVE-2"].Affected[0].Module, ms.Module)
	assert.Equal(t, *cves.ManualCves["CVE-2"].Affected[0].Stream, ms.Stream)
	// CVE-3 is reported from current release CPE (CSAF) and is fixed by RHSA-2
	assert.Len(t, cves.ManualCves["CVE-3"].Errata, 1)
	assert.Contains(t, cves.ManualCves["CVE-3"].Errata, "RHSA-2")
	assert.Len(t, cves.ManualCves["CVE-3"].Affected, 1)
	assert.Equal(t, cves.ManualCves["CVE-3"].Affected[0].Cpe, currentReleaseCPE)
	// CVE-4 is reported from newer release CPE (Repos) and is fixed by RHSA-8
	assert.Len(t, cves.ManualCves["CVE-4"].Errata, 1)
	assert.Contains(t, cves.ManualCves["CVE-4"].Errata, "RHSA-8")
	// CVE-4 comes completely from `newerReleaseReposCves` and nothing is added
	assert.Equal(t, cves.ManualCves["CVE-4"], newerReleaseReposCves["CVE-4"])
}

func cpeMatch(l, r CpeLabel) bool {
	lParsed, err := l.Parse()
	if err != nil {
		utils.LogWarn("cpe", l, "Cannot parse")
		return false
	}
	rParsed, err := r.Parse()
	if err != nil {
		utils.LogWarn("cpe", r, "Cannot parse")
		return false
	}
	return lParsed.Match(rParsed)
}
