package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper function to create mock Updates data
func createMockUpdatesForPatches() *Updates {
	return &Updates{
		UpdateList: UpdateList{
			"package1": UpdateDetail{
				AvailableUpdates: []Update{
					{Package: "package1-1.0.0", PackageName: "package1", EVRA: "1.0.0", Erratum: "RHSA-2023-001", Repository: "repo1"},
					{Package: "package1-1.1.0", PackageName: "package1", EVRA: "1.1.0", Erratum: "RHSA-2023-002", Repository: "repo1"},
				},
			},
			"package2": UpdateDetail{
				AvailableUpdates: []Update{
					{Package: "package2-2.0.0", PackageName: "package2", EVRA: "2.0.0", Erratum: "RHSA-2023-003", Repository: "repo2"},
				},
			},
		},
		LastChange: time.Now(),
	}
}

func TestPatches(t *testing.T) {
	mockUpdates := createMockUpdatesForPatches()

	// Store original function variables
	originalUpdatesFunc := updatesFunc
	originalExtractErrataFunc := extractUpdatesErrataFunc
	defer func() {
		updatesFunc = originalUpdatesFunc
		extractUpdatesErrataFunc = originalExtractErrataFunc
	}()

	// Mock updatesFunc to return our test data
	updatesFunc = func(_ *Request, _ *Cache, _ *options) (*Updates, error) {
		return mockUpdates, nil
	}

	// Create a real Request and call the actual patches function
	req := &Request{Packages: []string{"package1", "package2"}}
	cache := &Cache{DBChange: DBChange{LastChange: time.Date(2023, 11, 20, 12, 36, 49, 0, time.UTC)}}

	// Actually call the patches function - this is the key part!
	result, err := req.patches(cache, &options{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify that errata are extracted correctly
	expectedErrata := []string{"RHSA-2023-001", "RHSA-2023-002", "RHSA-2023-003"}
	assert.Equal(t, expectedErrata, result.Errata)
	assert.Equal(t, cache.DBChange.LastChange, result.LastChange)
}
