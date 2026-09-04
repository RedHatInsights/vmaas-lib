package vmaas

import (
	"testing"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateCvesFixedEVRA(t *testing.T) {
	pkg := Package{
		Nevra:  utils.Nevra{Name: "openssl", Epoch: 0, Version: "3.0.7", Release: "1.el9", Arch: "x86_64"},
		String: "openssl-0:3.0.7-1.el9.x86_64",
	}
	cpe := CpeLabel("cpe:/o:redhat:enterprise_linux:9")

	t.Run("repo path records affected with fixed_evra and empty cpe", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		updateCves(cves, "CVE-2024-0001", pkg, []string{"RHSA-2024:0001"}, "", nil, "0:3.0.7-5.el9.x86_64")

		require.Len(t, cves["CVE-2024-0001"].Affected, 1)
		assert.Equal(t, "openssl", cves["CVE-2024-0001"].Affected[0].Name)
		assert.Equal(t, "0:3.0.7-1.el9.x86_64", cves["CVE-2024-0001"].Affected[0].EVRA)
		assert.Equal(t, "0:3.0.7-5.el9.x86_64", cves["CVE-2024-0001"].Affected[0].FixedEVRA)
		assert.Empty(t, cves["CVE-2024-0001"].Affected[0].Cpe)
	})

	t.Run("unpatched cve has no fixed_evra", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		updateCves(cves, "CVE-2024-0002", pkg, nil, cpe, nil, "")

		require.Len(t, cves["CVE-2024-0002"].Affected, 1)
		assert.Empty(t, cves["CVE-2024-0002"].Affected[0].FixedEVRA)
		assert.Equal(t, cpe, cves["CVE-2024-0002"].Affected[0].Cpe)
	})

	t.Run("csaf manual records fixed_evra with cpe", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		updateCves(cves, "CVE-2024-0003", pkg, []string{"RHSA-1"}, cpe, nil, "0:3.0.7-5.el9.x86_64")

		require.Len(t, cves["CVE-2024-0003"].Affected, 1)
		assert.Equal(t, "0:3.0.7-5.el9.x86_64", cves["CVE-2024-0003"].Affected[0].FixedEVRA)
		assert.Equal(t, cpe, cves["CVE-2024-0003"].Affected[0].Cpe)
	})

	t.Run("same package deduplicates to earliest fixed_evra", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		updateCves(cves, "CVE-2024-0004", pkg, []string{"RHSA-1"}, "", nil, "0:3.0.7-6.el9.x86_64")
		updateCves(cves, "CVE-2024-0004", pkg, []string{"RHSA-2"}, "", nil, "0:3.0.7-4.el9.x86_64")

		require.Len(t, cves["CVE-2024-0004"].Affected, 1)
		assert.Equal(t, "0:3.0.7-4.el9.x86_64", cves["CVE-2024-0004"].Affected[0].FixedEVRA)
		assert.Len(t, cves["CVE-2024-0004"].Errata, 2)
	})

	t.Run("different packages are not deduplicated", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		pkg2 := Package{
			Nevra:  utils.Nevra{Name: "libssl", Epoch: 0, Version: "3.0.7", Release: "1.el9", Arch: "x86_64"},
			String: "libssl-0:3.0.7-1.el9.x86_64",
		}
		updateCves(cves, "CVE-2024-0006", pkg, []string{"RHSA-1"}, "", nil, "0:3.0.7-5.el9.x86_64")
		updateCves(cves, "CVE-2024-0006", pkg2, []string{"RHSA-1"}, "", nil, "0:3.0.7-5.el9.x86_64")

		require.Len(t, cves["CVE-2024-0006"].Affected, 2)
	})

	t.Run("no affected without cpe and without fixed_evra", func(t *testing.T) {
		cves := map[string]VulnerabilityDetail{}
		updateCves(cves, "CVE-2024-0005", Package{String: "test-pkg"}, []string{"RHSA-1"}, "", nil, "")

		assert.Empty(t, cves["CVE-2024-0005"].Affected)
	})
}
