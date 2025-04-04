package vmaas

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterInputPkgs(t *testing.T) {
	c := mockCache()
	pkgs := []string{
		"badnevra", "badnevra", "bash-4.2.46-20.el7_2.x86_64.rpm", "python-perf-3.10.0-693.el7.x86_64",
		"vim-common-2:7.4.160-1.el7.x86_64.rpm",
	}
	req := &PackagesRequest{
		Packages:   pkgs,
		ThirdParty: false,
	}

	filteredOut, pkgs2pkgIDs := filterInputPkgs(c, pkgs, req)
	fmt.Println(filteredOut, pkgs2pkgIDs)
	assert.Equal(t, 2, len(filteredOut))
	assert.Equal(t, 2, len(pkgs2pkgIDs))
}

func TestGetPackageDetails(t *testing.T) {
	c := mockCache()
	packages := map[string]PkgID{"bash-4.2.46-20.el7_2.x86_64.rpm": 4}
	packageDetails := c.getPackageDetails([]string{}, packages)
	assert.Equal(t, 1, len(packageDetails))
	pd, ok := packageDetails["bash-4.2.46-20.el7_2.x86_64.rpm"].(PackageDetailResponse)
	assert.True(t, ok)
	assert.NotEqual(t, 0, len(pd.Repositories))

	packages = map[string]PkgID{"bash-4.2.46-20.el7_2.src.rpm": 0}
	packageDetails = c.getPackageDetails([]string{}, packages)
	assert.Equal(t, 1, len(packageDetails))
	pd, ok = packageDetails["bash-4.2.46-20.el7_2.src.rpm"].(PackageDetailResponse)
	assert.False(t, ok)
}

func TestPackages(t *testing.T) {
	req := &PackagesRequest{}
	// empty package list
	_, err := req.packages(nil)
	assert.Error(t, err)
}
