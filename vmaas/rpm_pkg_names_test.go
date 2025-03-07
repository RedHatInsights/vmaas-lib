package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetContentSetLabels(t *testing.T) {
	c := Cache{
		PkgNameID2ContentSetLabels: map[NameID][]string{
			1: {"foo", "bar", "baz"},
		},
	}
	csMap := map[string]bool{
		"foo": true,
		"baz": true,
	}
	labels := c.getContentSetLabels(1, csMap)
	assert.Equal(t, 2, len(labels))

	labels = c.getContentSetLabels(1, nil)
	assert.Equal(t, 3, len(labels))

	labels = c.getContentSetLabels(0, nil)
	assert.NotNil(t, labels)
}

func TestGetContentData(t *testing.T) {
	req := RPMPkgNamesRequest{
		Names: []string{"a", "b", "b"},
	}
	c := Cache{
		Packagename2ID: map[string]NameID{"b": 2},
	}
	names2csLabels := c.getContentData(&req)
	assert.Equal(t, 1, len(names2csLabels))
}

func TestRPMPkgNames(t *testing.T) {
	req := &RPMPkgNamesRequest{}

	// empty rpm name list
	_, err := req.rpmPkgNames(nil)
	assert.Error(t, err)
}
