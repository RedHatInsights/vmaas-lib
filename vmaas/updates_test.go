package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdates(t *testing.T) {
	// Create mock Updates with mixed manually fixable updates
	mockUpdates := &Updates{
		UpdateList: UpdateList{
			"package1": UpdateDetail{
				AvailableUpdates: []Update{
					{
						Package:         "package1-1.0.0",
						PackageName:     "package1",
						EVRA:            "1.0.0",
						Erratum:         "RHSA-2023-001",
						Repository:      "repo1",
						manuallyFixable: false, // This should be included
					},
					{
						Package:         "package1-1.1.0",
						PackageName:     "package1",
						EVRA:            "1.1.0",
						Erratum:         "RHSA-2023-002",
						Repository:      "repo1",
						manuallyFixable: true, // This should be filtered out
					},
				},
			},
		},
		RepoList:   &[]string{"repo1"},
		RepoPaths:  []string{"/path1"},
		ModuleList: []ModuleStream{},
		Releasever: stringPtr("8"),
		Basearch:   stringPtr("x86_64"),
		LastChange: time.Now(),
	}

	// Store original function variables
	originalProcessRequest := processRequestFunc
	originalEvaluateRepositories := evaluateRepositoriesFunc

	// Mock processRequest to return a simple ProcessedRequest
	processRequestFunc = func(r *Request, c *Cache) (*ProcessedRequest, error) {
		return &ProcessedRequest{}, nil
	}

	// Mock evaluateRepositories to return our test data
	evaluateRepositoriesFunc = func(pr *ProcessedRequest, c *Cache, opts *options) *Updates {
		return mockUpdates
	}

	// Restore original functions after test
	defer func() {
		processRequestFunc = originalProcessRequest
		evaluateRepositoriesFunc = originalEvaluateRepositories
	}()

	// Create a real Request and call the actual updates function
	req := &Request{
		Packages: []string{"package1"},
	}

	// Actually call the updates function - this is the key part!
	result, err := req.updates(&Cache{}, &options{})

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify that manually fixable updates are filtered out
	assert.Len(t, result.UpdateList["package1"].AvailableUpdates, 1)
	assert.Equal(t, "package1-1.0.0", result.UpdateList["package1"].AvailableUpdates[0].Package)
	assert.False(t, result.UpdateList["package1"].AvailableUpdates[0].manuallyFixable)

	// Verify other fields are preserved
	assert.Equal(t, mockUpdates.RepoList, result.RepoList)
	assert.Equal(t, mockUpdates.RepoPaths, result.RepoPaths)
	assert.Equal(t, mockUpdates.Releasever, result.Releasever)
	assert.Equal(t, mockUpdates.Basearch, result.Basearch)
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
