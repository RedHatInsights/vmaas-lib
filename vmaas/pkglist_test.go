package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetFilteredPkgList(t *testing.T) {
	t1, _ := time.Parse(time.RFC3339, "2024-01-15T12:00:05+02:00")
	t2, _ := time.Parse(time.RFC3339, "2024-02-15T12:00:05+02:00")
	c := Cache{
		PackageDetails: map[PkgID]PackageDetail{
			1: {Modified: &t2},
			2: {Modified: nil},
			3: {Modified: &t1},
		},
		PackageDetailsModifiedIndex: []PkgID{2, 3, 1},
	}
	req := PkgListRequest{ModifiedSince: &t1}
	pkgList := req.getFilteredPkgList(&c)
	assert.Equal(t, 2, len(pkgList))
}

func TestLoadPkgListItems(t *testing.T) {
	c := mockCache()
	pkgList := c.loadPkgListItems([]PkgID{1, 2, 3}, true)
	assert.Equal(t, 3, len(pkgList))
	assert.NotNil(t, pkgList[0].Modified)
}
