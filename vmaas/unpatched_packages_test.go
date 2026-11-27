package vmaas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unpatchedPackagesFixture() *API {
	sourceID := func(id PkgID) *PkgID { return &id }
	nonmodular := ModuleStream{}
	modular18 := ModuleStream{Module: "nodejs", Stream: "18"}
	modular20 := ModuleStream{Module: "nodejs", Stream: "20"}
	products := map[CSAFProductID]CSAFProduct{
		1: {CpeID: 9, PackageNameID: 1, VariantSuffix: DefaultVariantSuffix, ModuleStream: nonmodular},
		2: {CpeID: 9, PackageNameID: 1, VariantSuffix: DefaultVariantSuffix, ModuleStream: modular18},
		3: {CpeID: 8, PackageNameID: 1, VariantSuffix: DefaultVariantSuffix, ModuleStream: modular20},
		4: {CpeID: 9, PackageNameID: 2, VariantSuffix: DefaultVariantSuffix},
		5: {CpeID: 9, PackageNameID: 3, VariantSuffix: DefaultVariantSuffix},
		6: {CpeID: 9, PackageNameID: 5, VariantSuffix: DefaultVariantSuffix},
		7: {CpeID: 9, PackageNameID: 1, PackageID: 2, VariantSuffix: DefaultVariantSuffix},
		8: {CpeID: 9, PackageNameID: 1, VariantSuffix: "different"},
		9: {CpeID: 9, PackageNameID: 1, VariantSuffix: DefaultVariantSuffix,
			ModuleStream: ModuleStream{Module: "missing", Stream: "1"}},
	}
	c := &Cache{
		ID2Packagename: map[NameID]string{
			1: "nodejs", 2: "nodejs-libs", 3: "openssl", 4: "openssl-libs", 5: "source-only",
		},
		PackageDetails: map[PkgID]PackageDetail{
			1: {NameID: 1, ArchID: 1},
			2: {NameID: 1, ArchID: 2, SrcPkgID: sourceID(1)},
			3: {NameID: 2, ArchID: 2, SrcPkgID: sourceID(1)},
			4: {NameID: 3, ArchID: 1},
			5: {NameID: 4, ArchID: 2, SrcPkgID: sourceID(4)},
			6: {NameID: 5, ArchID: 1},
		},
		CpeID2Label: map[CpeID]CpeLabel{
			8: "cpe:/o:redhat:enterprise_linux:8", 9: "cpe:/o:redhat:enterprise_linux:9",
		},
		CSAFProductID2Product: products,
		CSAFProduct2ID: map[CSAFProduct]CSAFProductID{
			products[1]: 1, products[2]: 2, products[3]: 3, products[4]: 4,
			products[5]: 5, products[6]: 6, products[7]: 7, products[8]: 8, products[9]: 9,
		},
		CSAFCVEs: map[VariantSuffix]map[CpeIDNameID]map[CSAFProductID]CSAFCVEs{
			DefaultVariantSuffix: {
				{CpeID: 9, NameID: 1}: {
					1: {Unfixed: []CVEID{3, 1, 3, 999}},
					2: {Unfixed: []CVEID{1}},
					7: {Fixed: []CVEID{6}},
					9: {Unfixed: []CVEID{999}},
				},
				{CpeID: 8, NameID: 1}: {3: {Unfixed: []CVEID{4}}},
				{CpeID: 9, NameID: 2}: {4: {Unfixed: []CVEID{3, 2}}},
				{CpeID: 9, NameID: 3}: {5: {Unfixed: []CVEID{2}}},
				{CpeID: 9, NameID: 5}: {6: {Unfixed: []CVEID{1}}},
			},
			"different": {{CpeID: 9, NameID: 1}: {8: {Unfixed: []CVEID{6}}}},
		},
		CveNames: map[int]string{1: "CVE-1", 2: "CVE-2", 3: "CVE-3", 4: "CVE-4", 6: "CVE-6"},
		DBChange: DBChange{
			LastChange: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
			Exported:   time.Date(2026, 11, 25, 12, 1, 0, 0, time.UTC),
		},
	}
	c.UnpatchedName2BinaryNameIDs = map[NameID][]NameID{
		1: {1, 2}, // source nodejs maps to its binary names
		2: {2},    // binary nodejs-libs maps to itself
		3: {4},    // source openssl maps to openssl-libs
	}
	return &API{Cache: c}
}

func TestUnpatchedPackages(t *testing.T) {
	api := unpatchedPackagesFixture()
	res, err := api.UnpatchedPackages(&UnpatchedPackagesRequest{PackageNames: []string{".*"}})
	require.NoError(t, err)
	assert.Equal(t, 1, res.PageNumber)
	assert.Equal(t, 7, res.PageSize)
	assert.Equal(t, 1, res.TotalPages)
	assert.Equal(t, api.Cache.DBChange.LastChange, res.LastChange)
	assert.Equal(t, api.Cache.DBChange.Exported, res.Exported)
	assert.Equal(t, UnpatchedPackageList{
		"nodejs": {
			"cpe:/o:redhat:enterprise_linux:8": {"nodejs:20": {"CVE-4"}},
			"cpe:/o:redhat:enterprise_linux:9": {
				"-": {"CVE-1", "CVE-3"}, "nodejs:18": {"CVE-1"},
			},
		},
		"nodejs-libs": {
			"cpe:/o:redhat:enterprise_linux:8": {"nodejs:20": {"CVE-4"}},
			"cpe:/o:redhat:enterprise_linux:9": {
				"-": {"CVE-1", "CVE-2", "CVE-3"}, "nodejs:18": {"CVE-1"},
			},
		},
		"openssl-libs": {"cpe:/o:redhat:enterprise_linux:9": {"-": {"CVE-2"}}},
	}, res.Packages)

	encoded, err := json.Marshal(res)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"unpatched_packages": {"nodejs": {"cpe:/o:redhat:enterprise_linux:9": {
			"-": ["CVE-1", "CVE-3"], "nodejs:18": ["CVE-1"]},
			"cpe:/o:redhat:enterprise_linux:8": {"nodejs:20": ["CVE-4"]}},
			"nodejs-libs": {"cpe:/o:redhat:enterprise_linux:9": {
				"-": ["CVE-1", "CVE-2", "CVE-3"], "nodejs:18": ["CVE-1"]},
				"cpe:/o:redhat:enterprise_linux:8": {"nodejs:20": ["CVE-4"]}},
			"openssl-libs": {"cpe:/o:redhat:enterprise_linux:9": {"-": ["CVE-2"]}}},
		"last_change": "2026-11-25T12:00:00Z", "exported": "2026-11-25T12:01:00Z",
		"page": 1, "page_size": 7, "pages": 1
	}`, string(encoded))
}

func TestUnpatchedPackagesPagination(t *testing.T) {
	api := unpatchedPackagesFixture()
	keys := []unpatchedPackageKey{
		{"nodejs", "cpe:/o:redhat:enterprise_linux:8", "nodejs:20"},
		{"nodejs", "cpe:/o:redhat:enterprise_linux:9", "-"},
		{"nodejs", "cpe:/o:redhat:enterprise_linux:9", "nodejs:18"},
		{"nodejs-libs", "cpe:/o:redhat:enterprise_linux:8", "nodejs:20"},
		{"nodejs-libs", "cpe:/o:redhat:enterprise_linux:9", "-"},
		{"nodejs-libs", "cpe:/o:redhat:enterprise_linux:9", "nodejs:18"},
		{"openssl-libs", "cpe:/o:redhat:enterprise_linux:9", "-"},
	}
	for i, expected := range keys {
		res, err := api.UnpatchedPackages(&UnpatchedPackagesRequest{
			PackageNames: []string{".*"}, PaginationRequest: utils.PaginationRequest{PageNumber: i + 1, PageSize: 1},
		})
		require.NoError(t, err)
		assert.Equal(t, i+1, res.PageNumber)
		assert.Equal(t, 1, res.PageSize)
		assert.Equal(t, 7, res.TotalPages)
		assert.Len(t, res.Packages, 1)
		assert.Len(t, res.Packages[expected.name][expected.cpe], 1)
		assert.NotEmpty(t, res.Packages[expected.name][expected.cpe][expected.module])
		if i == 4 {
			// One page contains the entire merged leaf, not a page of CVEs.
			assert.Equal(t, []string{"CVE-1", "CVE-2", "CVE-3"},
				res.Packages[expected.name][expected.cpe][expected.module])
		}
	}

	res, err := api.UnpatchedPackages(&UnpatchedPackagesRequest{
		PackageNames: []string{".*"}, PaginationRequest: utils.PaginationRequest{PageNumber: 9, PageSize: 2},
	})
	require.NoError(t, err)
	assert.Empty(t, res.Packages)
	assert.Equal(t, 0, res.PageSize)
	assert.Equal(t, 4, res.TotalPages)
}

func TestUnpatchedPackagesFilters(t *testing.T) {
	api := unpatchedPackagesFixture()
	str := func(s string) *string { return &s }
	tests := []struct {
		name     string
		req      UnpatchedPackagesRequest
		expected UnpatchedPackageList
		count    int
	}{
		{
			name: "binary name, CPE and module filters combine with AND",
			req: UnpatchedPackagesRequest{
				PackageNames: []string{"nodejs-libs"}, Cpes: []string{`cpe:/o:redhat:enterprise_linux:9`},
				Modules: []ModuleStreamPtrs{{Module: str("nodejs"), Stream: str("1.*")}},
			},
			expected: UnpatchedPackageList{
				"nodejs-libs": {"cpe:/o:redhat:enterprise_linux:9": {"nodejs:18": {"CVE-1"}}},
			},
			count: 1,
		},
		{
			name: "multiple patterns are ORed, module pairs are kept together",
			req: UnpatchedPackagesRequest{
				PackageNames: []string{"nodejs", "openssl-libs"},
				Cpes:         []string{`.*:8`, `.*:9`},
				Modules: []ModuleStreamPtrs{
					{Module: str("nodejs"), Stream: str("18")},
					{Module: str("other"), Stream: str("20")},
				},
			},
			expected: UnpatchedPackageList{
				"nodejs": {"cpe:/o:redhat:enterprise_linux:9": {"nodejs:18": {"CVE-1"}}},
			},
			count: 1,
		},
		{
			name: "full match is required for package names",
			req: UnpatchedPackagesRequest{
				PackageNames: []string{"nodejs"}, Cpes: []string{`.*:9`},
			},
			expected: UnpatchedPackageList{
				"nodejs": {"cpe:/o:redhat:enterprise_linux:9": {
					"-": {"CVE-1", "CVE-3"}, "nodejs:18": {"CVE-1"},
				}},
			},
			count: 2,
		},
		{
			name:     "explicit empty module list selects nothing",
			req:      UnpatchedPackagesRequest{PackageNames: []string{".*"}, Modules: []ModuleStreamPtrs{}},
			expected: UnpatchedPackageList{},
		},
		{
			name:     "explicit empty CPE list selects nothing",
			req:      UnpatchedPackagesRequest{PackageNames: []string{".*"}, Cpes: []string{}},
			expected: UnpatchedPackageList{},
		},
		{
			name:     "unmatched regex returns empty results",
			req:      UnpatchedPackagesRequest{PackageNames: []string{"no-such-package.*"}},
			expected: UnpatchedPackageList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := api.UnpatchedPackages(&tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, res.Packages)
			assert.Equal(t, tt.count, res.PageSize)
		})
	}
}

func TestUnpatchedPackagesInvalidRequests(t *testing.T) {
	api := unpatchedPackagesFixture()
	str := func(s string) *string { return &s }
	requests := []*UnpatchedPackagesRequest{
		nil,
		{},
		{PackageNames: []string{"*"}},
		{PackageNames: []string{".*"}, Cpes: []string{"*"}},
		{PackageNames: []string{".*"}, Modules: []ModuleStreamPtrs{{Stream: str(".*")}}},
		{PackageNames: []string{".*"}, Modules: []ModuleStreamPtrs{{Module: str(".*")}}},
		{PackageNames: []string{".*"}, Modules: []ModuleStreamPtrs{{Module: str("*"), Stream: str(".*")}}},
		{PackageNames: []string{".*"}, Modules: []ModuleStreamPtrs{{Module: str(".*"), Stream: str("*")}}},
	}
	for _, req := range requests {
		res, err := api.UnpatchedPackages(req)
		assert.Nil(t, res)
		require.ErrorIs(t, err, ErrProcessingInput)
	}
}

func TestUnpatchedPackagesMatchesVulnerabilities(t *testing.T) {
	api := unpatchedPackagesFixture()
	c := api.Cache
	pkg := NevraString{Nevra: utils.Nevra{Name: "nodejs-libs", Arch: "x86_64"}, Pkg: "nodejs-libs-1.x86_64"}
	products := cpes2products(c, nil, []CpeID{9}, 2, 3,
		[]ModuleStream{{Module: "nodejs", Stream: "18"}}, pkg, &defaultOpts)
	cves := &VulnerabilitiesCvesDetails{UnpatchedCves: make(map[string]VulnerabilityDetail)}
	evaluateUnpatchedCves(c, []ProductsPackage{products}, cves)

	result, err := api.UnpatchedPackages(&UnpatchedPackagesRequest{
		PackageNames: []string{"nodejs-libs"}, Cpes: []string{`.*:9`},
	})
	require.NoError(t, err)
	for _, list := range result.Packages["nodejs-libs"]["cpe:/o:redhat:enterprise_linux:9"] {
		for _, cve := range list {
			assert.Contains(t, cves.UnpatchedCves, cve)
		}
	}
	assert.Len(t, cves.UnpatchedCves, 3)
}
