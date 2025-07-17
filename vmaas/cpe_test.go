package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test helper functions to create test data

func createTestCpeID2Label() map[CpeID]CpeLabel {
	return map[CpeID]CpeLabel{
		1: "cpe:/o:redhat:enterprise_linux:8",
		2: "cpe:/o:redhat:enterprise_linux:8.1",
		3: "cpe:/o:redhat:enterprise_linux:9",
		4: "cpe:/o:redhat:enterprise_linux:9.1",
		5: "cpe:/o:centos:centos:8",
		6: "cpe:/o:invalid:invalid",
	}
}

func createTestCache() *Cache {
	c := &Cache{
		CpeID2Label: createTestCpeID2Label(),
		CpeLabel2ID: map[CpeLabel]CpeID{
			"cpe:/o:redhat:enterprise_linux:8":   1,
			"cpe:/o:redhat:enterprise_linux:8.1": 2,
			"cpe:/o:redhat:enterprise_linux:9":   3,
			"cpe:/o:redhat:enterprise_linux:9.1": 4,
			"cpe:/o:centos:centos:8":             5,
			"cpe:/o:invalid:invalid":             6,
		},
		RepoID2CpeIDs: map[RepoID][]CpeID{
			1: {1, 2},
			2: {3, 4},
			3: {5},
		},
		ContentSetID2CpeIDs: map[ContentSetID][]CpeID{
			1: {1, 2},
			2: {3, 4},
			3: {5},
		},
		ReleaseGraphs: []ReleaseGraph{
			{
				GetByCpe: map[CpeLabel][]*ReleaseNode{
					"cpe:/o:redhat:enterprise_linux:8": {
						{
							VariantSuffix: "8.0.0.GA",
							Type:          "major",
							CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8"},
						},
					},
					"cpe:/o:redhat:enterprise_linux:8.1": {
						{
							VariantSuffix: "8.1.0.GA",
							Type:          "minor",
							CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8.1"},
						},
					},
					"cpe:/o:redhat:enterprise_linux:9": {
						{
							VariantSuffix: "9.0.0.GA",
							Type:          "major",
							CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:9"},
						},
					},
				},
			},
		},
	}
	return c
}

func createTestReleaseNodes() []*ReleaseNode {
	return []*ReleaseNode{
		{
			VariantSuffix: "8.0.0.GA",
			Type:          "major",
			CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8"},
		},
		{
			VariantSuffix: "8.1.0.GA",
			Type:          "minor",
			CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8.1"},
		},
		{
			VariantSuffix: "9.0.0.GA",
			Type:          "major",
			CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:9"},
		},
	}
}

func TestGetMatchingCpes(t *testing.T) {
	cpeID2Label := createTestCpeID2Label()

	t.Run("with empty input", func(t *testing.T) {
		result := getMatchingCpes(cpeID2Label, []CpeLabel{})
		assert.Empty(t, result)
	})

	t.Run("with valid matching CPEs", func(t *testing.T) {
		inputCpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
			"cpe:/o:redhat:enterprise_linux:9",
		}
		result := getMatchingCpes(cpeID2Label, inputCpes)

		// Should match exactly
		assert.Contains(t, result, CpeLabel("cpe:/o:redhat:enterprise_linux:8"))
		assert.Contains(t, result, CpeLabel("cpe:/o:redhat:enterprise_linux:9"))
		// Should not contain duplicates
		assert.Equal(t, len(result), len(removeDuplicateCpeLabels(result)))
	})

	t.Run("with non-matching CPEs", func(t *testing.T) {
		inputCpes := []CpeLabel{
			"cpe:/o:ubuntu:ubuntu:20.04",
		}
		result := getMatchingCpes(cpeID2Label, inputCpes)
		assert.Empty(t, result)
	})

	t.Run("with invalid CPE format", func(t *testing.T) {
		inputCpes := []CpeLabel{
			"invalid-cpe-format",
		}
		result := getMatchingCpes(cpeID2Label, inputCpes)
		assert.Empty(t, result)
	})

	t.Run("with prefix matching CPEs", func(t *testing.T) {
		// Create a test map with a more specific CPE that can match partial input
		testCpeID2Label := map[CpeID]CpeLabel{
			1: "cpe:/o:redhat:enterprise_linux:8",
			2: "cpe:/o:redhat:enterprise_linux:8.1",
		}

		// Test with exact match - this should work
		inputCpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
		}
		result := getMatchingCpes(testCpeID2Label, inputCpes)

		// Should match the exact CPE
		assert.NotEmpty(t, result)
		assert.Contains(t, result, CpeLabel("cpe:/o:redhat:enterprise_linux:8"))

		// Test that results are sorted by version
		if len(result) > 1 {
			for i := 0; i < len(result)-1; i++ {
				curr, _ := result[i].Parse()
				next, _ := result[i+1].Parse()
				assert.LessOrEqual(t, curr.CmpByVersion(next), 0)
			}
		}
	})
}

func TestReleaseNodesFromCpes(t *testing.T) {
	cache := createTestCache()

	t.Run("with empty CPE list", func(t *testing.T) {
		result := releaseNodesFromCpes(cache, []CpeLabel{})
		assert.Empty(t, result)
	})

	t.Run("with valid CPEs", func(t *testing.T) {
		cpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
			"cpe:/o:redhat:enterprise_linux:9",
		}
		result := releaseNodesFromCpes(cache, cpes)
		assert.NotEmpty(t, result)
	})

	t.Run("with non-existing CPEs", func(t *testing.T) {
		cpes := []CpeLabel{
			"cpe:/o:ubuntu:ubuntu:20.04",
		}
		result := releaseNodesFromCpes(cache, cpes)
		assert.Empty(t, result)
	})
}

func TestReleaseNodes2VariantsCpes(t *testing.T) {
	cache := createTestCache()
	nodes := createTestReleaseNodes()

	t.Run("with empty nodes", func(t *testing.T) {
		variants, cpes := releaseNodes2VariantsCpes(cache, []*ReleaseNode{}, nil)
		assert.Empty(t, variants)
		assert.Empty(t, cpes)
	})

	t.Run("with valid nodes", func(t *testing.T) {
		variants, cpes := releaseNodes2VariantsCpes(cache, nodes, nil)
		assert.NotEmpty(t, variants)
		assert.NotEmpty(t, cpes)

		// Check for expected variants
		assert.Contains(t, variants, VariantSuffix("8.0.0.GA"))
		assert.Contains(t, variants, VariantSuffix("8.1.0.GA"))
		assert.Contains(t, variants, VariantSuffix("9.0.0.GA"))
	})

	t.Run("with except variants", func(t *testing.T) {
		exceptVariants := map[VariantSuffix]bool{
			"8.0.0.GA": true,
		}
		variants, cpes := releaseNodes2VariantsCpes(cache, nodes, exceptVariants)

		// Should not contain excluded variant
		assert.NotContains(t, variants, VariantSuffix("8.0.0.GA"))
		// Should contain others
		assert.Contains(t, variants, VariantSuffix("8.1.0.GA"))
		assert.Contains(t, variants, VariantSuffix("9.0.0.GA"))
		assert.NotEmpty(t, cpes)
	})

	t.Run("deduplication test", func(t *testing.T) {
		// Create nodes with duplicate CPEs
		duplicateNodes := []*ReleaseNode{
			{
				VariantSuffix: "8.0.0.GA",
				CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8"},
			},
			{
				VariantSuffix: "8.0.0.GA",
				CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8"},
			},
		}

		variants, cpes := releaseNodes2VariantsCpes(cache, duplicateNodes, nil)

		// Should have only one instance of each
		variantCount := make(map[VariantSuffix]int)
		for _, v := range variants {
			variantCount[v]++
		}
		assert.Equal(t, 1, variantCount[VariantSuffix("8.0.0.GA")])

		cpeCount := make(map[CpeID]int)
		for _, c := range cpes {
			cpeCount[c]++
		}
		assert.LessOrEqual(t, cpeCount[CpeID(1)], 1)
	})
}

func TestCpes2variantsCpes(t *testing.T) {
	cache := createTestCache()

	t.Run("with empty CPE list", func(t *testing.T) {
		variants, cpes := cpes2variantsCpes(cache, []CpeLabel{}, []VariantSuffix{})
		assert.Empty(t, variants)
		assert.Empty(t, cpes)
	})

	t.Run("with valid CPEs", func(t *testing.T) {
		cpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
		}
		variants, cpeIDs := cpes2variantsCpes(cache, cpes, []VariantSuffix{})

		assert.NotEmpty(t, variants)
		assert.NotEmpty(t, cpeIDs)

		// Results should be sorted
		for i := 0; i < len(variants)-1; i++ {
			assert.LessOrEqual(t, variants[i].Compare(&variants[i+1]), 0)
		}

		for i := 0; i < len(cpeIDs)-1; i++ {
			assert.LessOrEqual(t, cpeIDs[i], cpeIDs[i+1])
		}
	})

	t.Run("with except variants", func(t *testing.T) {
		cpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
		}
		exceptVariants := []VariantSuffix{"9.0.0.GA"}

		variants, cpeIDs := cpes2variantsCpes(cache, cpes, exceptVariants)

		// Direct variants from input CPEs should always be included
		assert.Contains(t, variants, VariantSuffix("8.0.0.GA"))
		// Except variants only apply to ancestors, so we can't easily test this
		// without a more complex setup with parent-child relationships
		assert.NotEmpty(t, cpeIDs)
	})
}

// Helper function to test CPE mapping functions with common logic
func testCpeMappingFunction(t *testing.T, emptyResult []CpeLabel, validResult []CpeLabel,
	nonExistingResult []CpeLabel, mixedResult []CpeLabel,
) {
	expectedCPEs := []CpeLabel{
		"cpe:/o:redhat:enterprise_linux:8",
		"cpe:/o:redhat:enterprise_linux:8.1",
		"cpe:/o:redhat:enterprise_linux:9",
		"cpe:/o:redhat:enterprise_linux:9.1",
	}

	t.Run("with empty list", func(t *testing.T) {
		assert.Empty(t, emptyResult)
	})

	t.Run("with valid IDs", func(t *testing.T) {
		assert.NotEmpty(t, validResult)
		for _, cpe := range expectedCPEs {
			assert.Contains(t, validResult, cpe)
		}
	})

	t.Run("with non-existing IDs", func(t *testing.T) {
		assert.Empty(t, nonExistingResult)
	})

	t.Run("with mixed existing and non-existing IDs", func(t *testing.T) {
		assert.NotEmpty(t, mixedResult)
		assert.Contains(t, mixedResult, CpeLabel("cpe:/o:redhat:enterprise_linux:8"))
		assert.Contains(t, mixedResult, CpeLabel("cpe:/o:redhat:enterprise_linux:8.1"))
	})
}

func TestRepos2cpes(t *testing.T) {
	cache := createTestCache()
	testCpeMappingFunction(t,
		repos2cpes(cache, []RepoID{}),
		repos2cpes(cache, []RepoID{1, 2}),
		repos2cpes(cache, []RepoID{999}),
		repos2cpes(cache, []RepoID{1, 999}),
	)
}

func TestContentSets2cpes(t *testing.T) {
	cache := createTestCache()
	testCpeMappingFunction(t,
		contentSets2cpes(cache, []ContentSetID{}),
		contentSets2cpes(cache, []ContentSetID{1, 2}),
		contentSets2cpes(cache, []ContentSetID{999}),
		contentSets2cpes(cache, []ContentSetID{1, 999}),
	)
}

// Helper function to remove duplicate CPE labels for testing
func removeDuplicateCpeLabels(cpes []CpeLabel) []CpeLabel {
	seen := make(map[CpeLabel]bool)
	result := make([]CpeLabel, 0)
	for _, cpe := range cpes {
		if !seen[cpe] {
			result = append(result, cpe)
			seen[cpe] = true
		}
	}
	return result
}

// Test edge cases and error conditions

func TestGetMatchingCpesErrorHandling(t *testing.T) {
	cpeID2Label := map[CpeID]CpeLabel{
		1: "invalid-cpe-format",
		2: "cpe:/o:redhat:enterprise_linux:8",
	}

	t.Run("with invalid CPE in map", func(t *testing.T) {
		inputCpes := []CpeLabel{
			"cpe:/o:redhat:enterprise_linux:8",
		}
		result := getMatchingCpes(cpeID2Label, inputCpes)

		// Should still work with valid CPEs
		assert.Contains(t, result, CpeLabel("cpe:/o:redhat:enterprise_linux:8"))
	})
}

func TestReleaseNodes2VariantsCpesWithUnknownCpe(t *testing.T) {
	cache := createTestCache()

	// Create node with CPE not in cache
	nodes := []*ReleaseNode{
		{
			VariantSuffix: "unknown.version",
			CPEs:          []CpeLabel{"cpe:/o:unknown:unknown:1.0"},
		},
	}

	variants, cpes := releaseNodes2VariantsCpes(cache, nodes, nil)

	// Should still include the variant even if CPE is unknown
	assert.Contains(t, variants, VariantSuffix("unknown.version"))
	// CPE ID should be 0 (unknown)
	assert.Contains(t, cpes, CpeID(0))
}

func TestCpes2variantsCpesWithAncestors(t *testing.T) {
	// Create a more complex cache with parent-child relationships
	cache := createTestCache()

	// Add a parent node
	parentNode := &ReleaseNode{
		VariantSuffix: "8.0.0.GA",
		Type:          "major",
		CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8"},
	}

	// Add a child node
	childNode := &ReleaseNode{
		VariantSuffix: "8.1.0.GA",
		Type:          "minor",
		CPEs:          []CpeLabel{"cpe:/o:redhat:enterprise_linux:8.1"},
		Parent:        parentNode,
	}

	parentNode.Children = []*ReleaseNode{childNode}

	// Update cache with parent-child relationship
	cache.ReleaseGraphs[0].GetByCpe["cpe:/o:redhat:enterprise_linux:8.1"] = []*ReleaseNode{childNode}

	cpes := []CpeLabel{"cpe:/o:redhat:enterprise_linux:8.1"}
	variants, cpeIDs := cpes2variantsCpes(cache, cpes, []VariantSuffix{})

	assert.NotEmpty(t, variants)
	assert.NotEmpty(t, cpeIDs)
}
