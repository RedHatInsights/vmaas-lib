package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetSortedPackageNames(t *testing.T) {
	req := &PkgTreeRequest{
		PackageNames: []string{"bash", "vim-common", "389-ds-base"},
	}
	names, err := req.getSortedPackageNames(&Cache{})
	assert.NoError(t, err)
	assert.Equal(t, "389-ds-base", names[0])
	assert.Equal(t, "bash", names[1])
	assert.Equal(t, "vim-common", names[2])

	emptyReq := &PkgTreeRequest{}
	_, err = emptyReq.getSortedPackageNames(nil)
	assert.Error(t, err)
}

func TestLoadPackageRepos(t *testing.T) {
	c := mockCache()
	repos, thirdPartyOnly := c.loadPackageRepos(PkgID(4))
	assert.NotEmpty(t, repos)
	assert.False(t, thirdPartyOnly)

	// test thirdPartyOnly skip
	_, thirdPartyOnly = c.loadPackageRepos(PkgID(5))
	assert.True(t, thirdPartyOnly)
}

func TestLoadPackageErrata(t *testing.T) {
	c := mockCache()
	errata, firstPublished, modifiedSinceSkip := c.loadPackageErrata(&PkgTreeRequest{}, PkgID(4))
	assert.NotEmpty(t, errata)
	assert.NotEmpty(t, firstPublished)
	assert.False(t, modifiedSinceSkip)

	// test modifiedSinceSkip
	modSince, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59+02:00")
	req := &PkgTreeRequest{ModifiedSince: &modSince}
	_, _, modifiedSinceSkip = c.loadPackageErrata(req, PkgID(4))
	assert.True(t, modifiedSinceSkip)
}

func TestLoadPkgTreeItem(t *testing.T) {
	c := mockCache()
	item := c.loadPkgTreeItem(&PkgTreeRequest{}, PkgID(4))
	assert.NotNil(t, item)
	assert.NotEmpty(t, item.Repositories)
	assert.NotEmpty(t, item.Errata)
}

func TestPkgtree(t *testing.T) {
	req := &PkgTreeRequest{}
	// empty package name list
	_, err := req.pkgtree(nil)
	assert.Error(t, err)
}
