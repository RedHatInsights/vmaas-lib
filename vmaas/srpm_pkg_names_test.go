package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSrcPkgPkgNameIDs(t *testing.T) {
	c := mockCache()
	nameIDs := c.getSrcPkgPkgNameIDs(6)
	assert.Equal(t, 2, len(nameIDs))
	assert.True(t, nameIDs[1])
	assert.True(t, nameIDs[2])
}

func TestGetRPMData(t *testing.T) {
	c := mockCache()
	names := []string{"foo"}

	data := c.getRPMData(names, []string{})
	assert.Equal(t, 1, len(data))
	assert.Equal(t, 4, len(data["foo"]))

	contentSets := []string{"test_cs_02", "test_cs_03"}
	data = c.getRPMData(names, contentSets)
	assert.Equal(t, 1, len(data))
	assert.Equal(t, 2, len(data["foo"]))
}

func TestSRPMPkgNames(t *testing.T) {
	// missing srpm name list
	req := &SRPMPkgNamesRequest{}
	_, err := req.srpmPkgNames(nil)
	assert.Error(t, err)

	// empty srpm name list
	req = &SRPMPkgNamesRequest{SRPMNames: []string{}}
	res, err := req.srpmPkgNames(nil)
	assert.NoError(t, err)
	assert.Empty(t, res)
}
