package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetPackageRepos(t *testing.T) {
	c := mockCache()
	repos, thirdPartyOnly := c.getPackageRepos(PkgID(4))
	assert.NotEmpty(t, repos)
	assert.False(t, thirdPartyOnly)

	// test thirdPartyOnly skip
	_, thirdPartyOnly = c.getPackageRepos(PkgID(5))
	assert.True(t, thirdPartyOnly)
}

func TestGetPackageErrata(t *testing.T) {
	c := mockCache()
	errata, firstPublished, modifiedSinceSkip := c.getPackageErrata(&PkgTreeRequest{}, PkgID(4))
	assert.NotEmpty(t, errata)
	assert.NotEmpty(t, firstPublished)
	assert.False(t, modifiedSinceSkip)

	// test modifiedSinceSkip
	modSince, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59+02:00")
	req := &PkgTreeRequest{ModifiedSince: &modSince}
	_, _, modifiedSinceSkip = c.getPackageErrata(req, PkgID(4))
	assert.True(t, modifiedSinceSkip)
}

func TestGetPkgTreeItem(t *testing.T) {
	c := mockCache()
	item := c.getPkgTreeItem(&PkgTreeRequest{}, PkgID(4))
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
