package vmaas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestOSCache() *Cache {
	lastChange := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	return &Cache{
		OSReleaseDetails: map[int]OSReleaseDetail{
			1: {
				Name:           "Red Hat Enterprise Linux 8",
				Major:          8,
				Minor:          0,
				LifecyclePhase: "minor",
				SystemProfile: `{"package_list": ["kernel-4.18.0-80.el8.x86_64"], ` +
					`"repository_list": ["rhel-8-server-rpms"], "releasever": "8", "basearch": "x86_64"}`,
			},
			2: {
				Name:           "Red Hat Enterprise Linux 9",
				Major:          9,
				Minor:          0,
				LifecyclePhase: "minor",
				SystemProfile: `{"package_list": ["kernel-5.14.0-70.el9.x86_64"], ` +
					`"repository_list": ["rhel-9-server-rpms"], "releasever": "9", "basearch": "x86_64"}`,
			},
			3: {
				Name:           "Invalid JSON Profile",
				Major:          7,
				Minor:          0,
				LifecyclePhase: "minor",
				SystemProfile:  `{"invalid": json}`, // Invalid JSON for error testing
			},
		},
		DBChange: DBChange{
			LastChange: lastChange,
		},
	}
}

func TestSystemProfileParsing(t *testing.T) {
	t.Run("valid JSON parsing", func(t *testing.T) {
		cache := createTestOSCache()

		release := cache.OSReleaseDetails[1] // RHEL 8 with valid system profile

		// Test that the JSON is parsed correctly
		var request Request
		err := json.Unmarshal([]byte(release.SystemProfile), &request)
		require.NoError(t, err)

		// Verify the request was parsed correctly
		assert.Equal(t, []string{"kernel-4.18.0-80.el8.x86_64"}, request.Packages)
		assert.Equal(t, &[]string{"rhel-8-server-rpms"}, request.Repos)
		assert.Equal(t, "8", *request.Releasever)
		assert.Equal(t, "x86_64", *request.Basearch)
	})

	t.Run("invalid JSON handling", func(t *testing.T) {
		cache := createTestOSCache()

		release := cache.OSReleaseDetails[3] // Invalid JSON profile

		var request Request
		err := json.Unmarshal([]byte(release.SystemProfile), &request)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid character")
	})

	t.Run("empty system profile", func(t *testing.T) {
		emptyProfile := ""

		var request Request
		err := json.Unmarshal([]byte(emptyProfile), &request)
		assert.Error(t, err)
	})

	t.Run("minimal valid JSON", func(t *testing.T) {
		minimalProfile := `{"package_list": []}`

		var request Request
		err := json.Unmarshal([]byte(minimalProfile), &request)
		require.NoError(t, err)
		assert.Empty(t, request.Packages)
		assert.Nil(t, request.Repos)
		assert.Nil(t, request.Releasever)
		assert.Nil(t, request.Basearch)
	})
}

// Helper function to verify release details in vulnerability report tests
func verifyReleaseDetails(t *testing.T, releases []OSReleaseDetail) {
	// Find and verify RHEL 8 release
	var rhel8Release *OSReleaseDetail
	for i := range releases {
		if releases[i].Major == 8 {
			rhel8Release = &releases[i]
			break
		}
	}
	require.NotNil(t, rhel8Release)
	assert.Equal(t, "Red Hat Enterprise Linux 8", rhel8Release.Name)
	assert.Equal(t, 2, rhel8Release.CvesCritical)
	assert.Equal(t, 5, rhel8Release.CvesImportant)
	assert.Equal(t, 1, rhel8Release.CvesUnpatchedCritical)

	// Find and verify RHEL 9 release
	var rhel9Release *OSReleaseDetail
	for i := range releases {
		if releases[i].Major == 9 {
			rhel9Release = &releases[i]
			break
		}
	}
	require.NotNil(t, rhel9Release)
	assert.Equal(t, "Red Hat Enterprise Linux 9", rhel9Release.Name)
	assert.Equal(t, 1, rhel9Release.CvesCritical)
	assert.Equal(t, 3, rhel9Release.CvesModerate)
	assert.Equal(t, 1, rhel9Release.CvesUnpatchedModerate)
}

// Helper function to verify vulnerability report structure and counts
func verifyVulnerabilityReport(t *testing.T, report *VulnerabilityReport, cache *Cache) {
	// Verify report structure
	assert.Equal(t, 3, len(report.OSReleases))
	assert.Equal(t, cache.DBChange.LastChange, report.LastChange)
	assert.IsType(t, VulnerabilityReport{}, *report)

	// Verify that all OS releases are included with proper major versions
	majorVersions := make(map[int]bool)
	for _, release := range report.OSReleases {
		majorVersions[release.Major] = true
	}
	assert.True(t, majorVersions[7])
	assert.True(t, majorVersions[8])
	assert.True(t, majorVersions[9])

	// Verify CVE counts were set by mock
	for _, release := range report.OSReleases {
		totalCves := release.CvesCritical + release.CvesImportant + release.CvesModerate + release.CvesLow
		totalUnpatched := release.CvesUnpatchedCritical + release.CvesUnpatchedImportant +
			release.CvesUnpatchedModerate + release.CvesUnpatchedLow

		switch release.Major {
		case 8:
			assert.Equal(t, 47, totalCves)     // 3+7+12+25
			assert.Equal(t, 3, totalUnpatched) // 1+2+0+0
		case 9:
			assert.Equal(t, 28, totalCves)     // 1+4+8+15
			assert.Equal(t, 3, totalUnpatched) // 0+0+3+0
		case 7:
			assert.Equal(t, 12, totalCves)     // 0+2+0+10
			assert.Equal(t, 5, totalUnpatched) // 0+0+0+5
		}
	}
}

// Helper to setup simple mock CVE counts for prepare vulnerability report tests
func setupSimpleMockCveCounts() {
	evaluateCveCountsFunc = func(_ *Cache, _ *options, release *OSReleaseDetail) error {
		switch release.Major {
		case 8:
			release.CvesCritical = 2
			release.CvesImportant = 5
			release.CvesUnpatchedCritical = 1
		case 9:
			release.CvesCritical = 1
			release.CvesModerate = 3
			release.CvesUnpatchedModerate = 1
		case 7:
			release.CvesLow = 2
		}
		return nil
	}
}

// Helper to setup comprehensive mock CVE counts for vulnerability report tests
func setupComprehensiveMockCveCounts() {
	evaluateCveCountsFunc = func(_ *Cache, _ *options, release *OSReleaseDetail) error {
		switch release.Major {
		case 8:
			release.CvesCritical = 3
			release.CvesImportant = 7
			release.CvesModerate = 12
			release.CvesLow = 25
			release.CvesUnpatchedCritical = 1
			release.CvesUnpatchedImportant = 2
		case 9:
			release.CvesCritical = 1
			release.CvesImportant = 4
			release.CvesModerate = 8
			release.CvesLow = 15
			release.CvesUnpatchedModerate = 3
		case 7:
			release.CvesImportant = 2
			release.CvesLow = 10
			release.CvesUnpatchedLow = 5
		}
		return nil
	}
}

// Test helper for successful preparation scenario
func runSuccessfulPreparationTest(t *testing.T) {
	cache := createTestOSCache()
	setupSimpleMockCveCounts()

	releases, err := prepareVulnerabilityReport(cache, &defaultOpts)
	require.NoError(t, err)
	assert.Equal(t, 3, len(releases))
	verifyReleaseDetails(t, releases)
}

// Test helper for error propagation scenario
func runErrorPropagationTest(t *testing.T) {
	cache := createTestOSCache()
	evaluateCveCountsFunc = func(_ *Cache, _ *options, _ *OSReleaseDetail) error {
		return assert.AnError
	}

	releases, err := prepareVulnerabilityReport(cache, &defaultOpts)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	assert.Empty(t, releases)
}

// Test helper for empty cache scenario
func runEmptyCacheTest(t *testing.T) {
	emptyCache := &Cache{OSReleaseDetails: map[int]OSReleaseDetail{}}
	evaluateCveCountsFunc = func(_ *Cache, _ *options, _ *OSReleaseDetail) error {
		t.Error("evaluateCveCounts should not be called for empty cache")
		return nil
	}

	releases, err := prepareVulnerabilityReport(emptyCache, &defaultOpts)
	require.NoError(t, err)
	assert.Empty(t, releases)
}

// Test helper for successful vulnerability report generation
func runSuccessfulVulnerabilityReportTest(t *testing.T) {
	cache := createTestOSCache()
	setupComprehensiveMockCveCounts()

	report, err := vulnerabilityReport(cache, &defaultOpts)
	require.NoError(t, err)
	require.NotNil(t, report)
	verifyVulnerabilityReport(t, report, cache)
}

// Test helper for vulnerability report error propagation
func runVulnerabilityReportErrorTest(t *testing.T) {
	cache := createTestOSCache()
	evaluateCveCountsFunc = func(_ *Cache, _ *options, _ *OSReleaseDetail) error {
		return assert.AnError
	}

	report, err := vulnerabilityReport(cache, &defaultOpts)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	assert.Nil(t, report)
}

// Test helper for vulnerability report timestamp verification
func runVulnerabilityReportTimestampTest(t *testing.T) {
	cache := createTestOSCache()
	evaluateCveCountsFunc = func(_ *Cache, _ *options, _ *OSReleaseDetail) error {
		return nil
	}

	report, err := vulnerabilityReport(cache, &defaultOpts)
	require.NoError(t, err)
	require.NotNil(t, report)

	// Verify LastChange timestamp is preserved from cache
	expectedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, expectedTime, report.LastChange)
}

func TestPrepareVulnerabilityReport(t *testing.T) {
	originalFunc := evaluateCveCountsFunc
	defer func() { evaluateCveCountsFunc = originalFunc }()

	t.Run("successful preparation with mock CVE counts", runSuccessfulPreparationTest)
	t.Run("error from evaluateCveCounts propagates", runErrorPropagationTest)
	t.Run("empty OS releases in cache", runEmptyCacheTest)
}

func TestVulnerabilityReport(t *testing.T) {
	originalFunc := evaluateCveCountsFunc
	defer func() { evaluateCveCountsFunc = originalFunc }()

	t.Run("successful vulnerability report generation", runSuccessfulVulnerabilityReportTest)
	t.Run("error in prepareVulnerabilityReport propagates", runVulnerabilityReportErrorTest)
	t.Run("verify report timestamp", runVulnerabilityReportTimestampTest)
}
