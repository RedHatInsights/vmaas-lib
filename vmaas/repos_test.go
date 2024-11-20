package vmaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterInputRepos(t *testing.T) {
	repos := []string{"rhel-6-server-rpms", "rhel-7-server-rpms", "rhel-8-server-rpms", "rhel-9-server-rpms"}
	c := mockCache()

	// usual case
	filtered := filterInputRepos(c, repos, &ReposRequest{})
	assert.Equal(t, 2, len(filtered))

	// ThirdParty
	req := &ReposRequest{ThirdParty: true}
	filtered = filterInputRepos(c, repos, req)
	assert.Equal(t, 3, len(filtered))

	// With LastChange before req.ModifiedSince
	testTime, _ := time.Parse(time.RFC3339, "2024-11-19T18:01:01+01:00")
	req = &ReposRequest{ModifiedSince: &testTime}
	filtered = filterInputRepos(c, repos, req)
	assert.Equal(t, 1, len(filtered))
	assert.Equal(t, "rhel-6-server-rpms", filtered[0])
}

func TestRepoID2CPEs(t *testing.T) {
	c := mockCache()
	cpes := c.repoID2CPEs(42, 0)
	assert.Equal(t, 2, len(cpes))

	cpes = c.repoID2CPEs(44, 111)
	assert.Equal(t, 3, len(cpes))
}

func TestGetRepoDetailSlice(t *testing.T) {
	c := mockCache()
	repoDetailSlice, _ := c.getRepoDetailSlice("rhel-6-server-rpms", map[RepoID][]ErratumID{}, true)
	assert.Equal(t, 2, len(repoDetailSlice))
}

func TestGetRepoDetails(t *testing.T) {
	c := mockCache()

	repos := []string{"rhel-6-server-rpms", "rhel-7-server-rpms", "rhel-8-server-rpms"}
	expectedChange, _ := time.Parse(time.RFC3339, "2024-11-18T17:58:00+01:00")
	_, latestRepoChange, actualPageSize := c.getRepoDetails(repos, map[RepoID][]ErratumID{}, true)
	assert.Equal(t, expectedChange, *latestRepoChange)
	assert.Equal(t, 4, actualPageSize)

	_, latestRepoChange, _ = c.getRepoDetails([]string{"rhel-7-server-rpms"}, map[RepoID][]ErratumID{}, true)
	assert.Nil(t, latestRepoChange)
}

func TestRepos(t *testing.T) {
	req := &ReposRequest{}
	c := mockCache()

	// empty repository list
	_, err := req.repos(c)
	assert.Error(t, err)
}
