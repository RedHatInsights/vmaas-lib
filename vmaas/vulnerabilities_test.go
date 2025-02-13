package vmaas

import (
	"fmt"
	"sort"
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

//nolint:funlen
func TestCSAF(t *testing.T) {
	ms := ModuleStream{Module: "name", Stream: "stream"}
	unfixed := CSAFProduct{CpeID: 1, PackageNameID: 1}
	fixed1 := CSAFProduct{CpeID: 1, PackageNameID: 1, PackageID: 1}
	fixed2 := CSAFProduct{CpeID: 2, PackageNameID: 1, PackageID: 2}
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
		CSAFCVEs: map[CpeIDNameID]map[CSAFProduct]CSAFCVEs{
			{CpeID: 1, NameID: 1}: {
				unfixed: {Unfixed: []CVEID{1, 2}},
				fixed1:  {Fixed: []CVEID{3, 4}},
			},
			{CpeID: 2, NameID: 1}: {fixed2: {Fixed: []CVEID{5}}},
		},
		CveNames: map[int]string{
			1: "CVE-1", 2: "CVE-2", 3: "CVE-3", 4: "CVE-4", 5: "CVE-5",
		},
	}

	type expected struct {
		pkg     NevraString
		nameID  NameID
		pkgID   PkgID
		fixed   []CSAFProduct
		unfixed []CSAFProduct
	}
	pkg1 := utils.Nevra{Name: "kernel", Epoch: 0, Version: "1", Release: "1", Arch: "x86_64"}
	pkg2 := utils.Nevra{Name: "kernel", Epoch: 0, Version: "2", Release: "2", Arch: "x86_64"}
	pkg3 := utils.Nevra{Name: "kernel-devel", Epoch: 0, Version: "1", Release: "1", Arch: "x86_64"}
	matrix := []expected{
		{
			pkg:     NevraString{Nevra: pkg1, Pkg: pkg1.String()},
			nameID:  1,
			pkgID:   1,
			unfixed: []CSAFProduct{unfixed},
			fixed:   []CSAFProduct{fixed1, fixed2},
		},
		{
			pkg:     NevraString{Nevra: pkg2, Pkg: pkg2.String()},
			nameID:  1,
			pkgID:   2,
			unfixed: []CSAFProduct{unfixed},
			fixed:   []CSAFProduct{fixed1, fixed2},
		},
		{
			pkg:     NevraString{Nevra: pkg3, Pkg: pkg3.String()},
			nameID:  2,
			pkgID:   3,
			unfixed: []CSAFProduct{unfixed},
			fixed:   []CSAFProduct{},
		}, // match source package
	}

	products := make([]ProductsPackage, 0, len(matrix))
	for _, m := range matrix {
		pp := cpes2products(&c, []CpeID{1, 2}, m.nameID, m.pkgID, []ModuleStream{ms}, m.pkg, &defaultOpts)
		assert.Equal(t, m.fixed, pp.ProductsFixed)
		assert.Equal(t, m.unfixed, pp.ProductsUnfixed)
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
	}
	for _, test := range cpeTests {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			res := cpeMatch(test.pattern, test.repoCpe)
			assert.Equal(t, test.expected, res)
		})
	}
}
