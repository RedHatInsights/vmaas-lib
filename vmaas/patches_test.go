package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPatches(t *testing.T) {
	// Create mock Updates with errata
	mockUpdates := &Updates{
		UpdateList: UpdateList{
			"package1": UpdateDetail{
				AvailableUpdates: []Update{
					{
						Package:     "package1-1.0.0",
						PackageName: "package1",
						EVRA:        "1.0.0",
						Erratum:     "RHSA-2023-001",
						Repository:  "repo1",
					},
					{
						Package:     "package1-1.1.0",
						PackageName: "package1",
						EVRA:        "1.1.0",
						Erratum:     "RHSA-2023-002",
						Repository:  "repo1",
					},
				},
			},
			"package2": UpdateDetail{
				AvailableUpdates: []Update{
					{
						Package:     "package2-2.0.0",
						PackageName: "package2",
						EVRA:        "2.0.0",
						Erratum:     "RHSA-2023-003",
						Repository:  "repo2",
					},
				},
			},
		},
		LastChange: time.Now(),
	}

	// Store original function variables
	originalUpdatesFunc := updatesFunc
	originalExtractErrataFunc := extractUpdatesErrataFunc

	// Mock updatesFunc to return our test data
	updatesFunc = func(r *Request, c *Cache, opts *options) (*Updates, error) {
		return mockUpdates, nil
	}

	// Keep the real extractUpdatesErrataFunc since it's simple to test directly
	// (but we could mock this too if needed)

	// Restore original functions after test
	defer func() {
		updatesFunc = originalUpdatesFunc
		extractUpdatesErrataFunc = originalExtractErrataFunc
	}()

	// Create a real Request and call the actual patches function
	req := &Request{
		Packages: []string{"package1", "package2"},
	}

	// Mock Cache with DBChange
	cache := &Cache{
		DBChange: DBChange{
			LastChange: time.Date(2023, 11, 20, 12, 36, 49, 0, time.UTC),
		},
	}

	// Actually call the patches function - this is the key part!
	result, err := req.patches(cache, &options{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify that errata are extracted correctly
	expectedErrata := []string{"RHSA-2023-001", "RHSA-2023-002", "RHSA-2023-003"}
	assert.Equal(t, expectedErrata, result.Errata)

	// Verify LastChange is preserved from cache
	assert.Equal(t, cache.DBChange.LastChange, result.LastChange)
}
