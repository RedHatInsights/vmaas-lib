package vmaas

import (
	"fmt"
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
)

// productWithFixedCVEs returns the same SET but a randomized ORDER (map iteration) -> sort needed.
func TestProductWithFixedCVEsOrderIsRandom(t *testing.T) {
	c := Cache{
		CSAFProductID2Product: map[CSAFProductID]CSAFProduct{
			10: {PackageID: 1},
			11: {PackageID: 2},
			12: {PackageID: 3},
			13: {PackageID: 4},
			14: {PackageID: 5},
		},
		CSAFCVEs: map[VariantSuffix]map[CpeIDNameID]map[CSAFProductID]CSAFCVEs{
			DefaultVariantSuffix: {
				{CpeID: 1, NameID: 1}: {
					10: {Fixed: []CVEID{1}},
					11: {Fixed: []CVEID{1}},
					12: {Fixed: []CVEID{1}},
					13: {Fixed: []CVEID{1}},
					14: {Fixed: []CVEID{1}},
				},
			},
		},
	}

	seenOrders := map[string]bool{}
	for i := 0; i < 100; i++ {
		products, ok := productWithFixedCVEs(&c, DefaultVariantSuffix, 1, 1, []ModuleStream{{}})
		assert.True(t, ok)
		assert.Len(t, products, 5) // the SET is always the same
		seenOrders[fmt.Sprint(products)] = true
	}

	// If order were stable we'd see exactly 1 distinct order across 100 calls.
	// Map iteration randomization => we expect many distinct orders.
	t.Logf("distinct orders across 100 calls: %d", len(seenOrders))
	assert.Greater(t, len(seenOrders), 1,
		"productWithFixedCVEs returns the same SET but in a non-deterministic ORDER")
}

// evaluateManualCves must return the same result regardless of fixed-product input order.
// installed 1-1; fix A(id10)=1-0 (<=installed), fix B(id11)=1-2 (>installed) -> CVE-1 suppressed.
func TestEvaluateManualCvesDeterministicOrder(t *testing.T) {
	c := Cache{
		Arch2ID:        map[string]ArchID{"x86_64": 1},
		ID2Arch:        map[ArchID]string{1: "x86_64"},
		ArchCompat:     map[ArchID]map[ArchID]bool{1: {1: true}},
		ID2Packagename: map[NameID]string{1: "pkg"},
		ID2Evr: map[EvrID]utils.Evr{
			1: {Epoch: 0, Version: "1", Release: "0"}, // fix A (<= installed)
			2: {Epoch: 0, Version: "1", Release: "1"}, // installed
			3: {Epoch: 0, Version: "1", Release: "2"}, // fix B (> installed)
		},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, EvrID: 1, ArchID: 1}, // pkg-0:1-0
			2: {NameID: 1, EvrID: 3, ArchID: 1}, // pkg-0:1-2
		},
		CpeID2Label: map[CpeID]CpeLabel{1: "cpe:/o:redhat:enterprise_linux:8"},
		CveNames:    map[int]string{1: "CVE-1"},
		CSAFProductID2Product: map[CSAFProductID]CSAFProduct{
			10: {CpeID: 1, VariantSuffix: DefaultVariantSuffix, PackageNameID: 1, PackageID: 1},
			11: {CpeID: 1, VariantSuffix: DefaultVariantSuffix, PackageNameID: 1, PackageID: 2},
		},
		CSAFCVEProduct2Erratum: map[CSAFCVEProduct]string{
			{CVEID: 1, CSAFProductID: 10}: "RHSA-A",
			{CVEID: 1, CSAFProductID: 11}: "RHSA-B",
		},
		CSAFCVEs: map[VariantSuffix]map[CpeIDNameID]map[CSAFProductID]CSAFCVEs{
			DefaultVariantSuffix: {
				{CpeID: 1, NameID: 1}: {
					10: {Fixed: []CVEID{1}},
					11: {Fixed: []CVEID{1}},
				},
			},
		},
	}

	installed := Package{
		Nevra:  utils.Nevra{Name: "pkg", Epoch: 0, Version: "1", Release: "1", Arch: "x86_64"},
		String: "pkg-0:1-1.x86_64",
		NameID: 1,
	}

	run := func(order []CSAFProductID) []string {
		cves := VulnerabilitiesCvesDetails{
			Cves:          map[string]VulnerabilityDetail{},
			ManualCves:    map[string]VulnerabilityDetail{},
			UnpatchedCves: map[string]VulnerabilityDetail{},
		}
		products := []ProductsPackage{{ProductsFixed: order, Package: installed}}
		evaluateManualCves(&c, products, &cves, map[string]VulnerabilityDetail{}, &defaultOpts)
		out := make([]string, 0, len(cves.ManualCves))
		for k := range cves.ManualCves {
			out = append(out, k)
		}
		return out
	}

	resAB := run([]CSAFProductID{10, 11})
	resBA := run([]CSAFProductID{11, 10})

	t.Logf("order [A,B]: ManualCves=%v", resAB)
	t.Logf("order [B,A]: ManualCves=%v", resBA)

	assert.Equal(t, resAB, resBA,
		"result must not depend on the input order of fixed products")
	assert.Empty(t, resAB,
		"CVE-1 is already fixed by the installed version (1-1 >= fix 1-0), it must be suppressed")
}
