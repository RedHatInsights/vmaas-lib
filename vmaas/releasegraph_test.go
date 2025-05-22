package vmaas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testJSON = `{
  "nodes": {
    "RHEL-8.0.0": { "type": "main", "cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream"] },
    "RHEL-8.0.0.Z": { "type": "main", "cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream"] },
    "RHEL-8.0.1": { "type": "main", "cpes": ["cpe:/a:redhat:enterprise_linux:8::appstream"] }
  },
  "edges": {
    "RHEL-8.0.0": ["RHEL-8.0.0.Z"],
    "RHEL-8.0.0.Z": ["RHEL-8.0.1"]
  }
}`

func TestBuildGraphAndAncestors(t *testing.T) {
	c := &Cache{
		CpeID2Label: map[CpeID]CpeLabel{1: "cpe:/a:redhat:enterprise_linux:8::appstream"},
		CpeLabel2ID: map[CpeLabel]CpeID{"cpe:/a:redhat:enterprise_linux:8::appstream": 1},
	}

	var raw ReleaseGraphRaw
	err := json.Unmarshal([]byte(testJSON), &raw)
	require.NoError(t, err)

	graph := raw.BuildGraph(c.CpeID2Label, c.CpeLabel2ID)

	require.Len(t, graph.GetByVariant, 3)

	node := graph.GetByVariant["8.0.0.Z"]
	require.NotNil(t, node)

	assert.Equal(t, VariantSuffix("8.0.0"), node.Parent.VariantSuffix)
	assert.Len(t, node.Children, 1)
	assert.Equal(t, VariantSuffix("8.0.1"), node.Children[0].VariantSuffix)

	ancestors := graph.GetAncestors("8.0.1")
	require.Len(t, ancestors, 2)
	assert.Equal(t, VariantSuffix("8.0.0.Z"), ancestors[0].VariantSuffix)
	assert.Equal(t, VariantSuffix("8.0.0"), ancestors[1].VariantSuffix)
}
