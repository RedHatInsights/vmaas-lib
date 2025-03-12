package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetContentData(t *testing.T) {
	names := []string{"a", "b", "b"}
	c := Cache{
		Packagename2ID: map[string]NameID{"b": 2},
	}
	names2csLabels := c.getContentData(names, nil)
	assert.Equal(t, 1, len(names2csLabels))
}

func TestRPMPkgNames(t *testing.T) {
	// missing rpm name list
	req := &RPMPkgNamesRequest{}
	_, err := req.rpmPkgNames(nil)
	assert.Error(t, err)

	// empty rpm name list
	req = &RPMPkgNamesRequest{RPMNames: []string{}}
	res, err := req.rpmPkgNames(nil)
	assert.NoError(t, err)
	assert.Empty(t, res)
}
