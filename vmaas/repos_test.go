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
	assert.Equal(t, 3, len(filtered))

	// ThirdParty
	req := &ReposRequest{ThirdParty: true}
	filtered = filterInputRepos(c, repos, req)
	assert.Equal(t, 4, len(filtered))

	// With LastChange before req.ModifiedSince
	testTime, _ := time.Parse(time.RFC3339, "2024-11-19T18:01:01+01:00")
	req = &ReposRequest{ModifiedSince: &testTime}
	filtered = filterInputRepos(c, repos, req)
	assert.Equal(t, 2, len(filtered))
	assert.Contains(t, filtered, "rhel-6-server-rpms")
	assert.Contains(t, filtered, "rhel-9-server-rpms")
}

func TestFilterInputReposMultiRepoLastChange(t *testing.T) {
	// Test that a content set label with multiple repoIDs is included
	// when ANY repoID has a recent LastChange, even if the last repoID
	// in the slice has an old LastChange.
	c := mockCache()

	// modified_since between the two LastChange values
	modifiedSince, _ := time.Parse(time.RFC3339, "2024-06-01T00:00:00+00:00")
	req := &ReposRequest{ModifiedSince: &modifiedSince}
	filtered := filterInputRepos(c, []string{"rhel-9-server-rpms"}, req)
	// one repoID has LastChange after modified_since, so the label must be included
	assert.Equal(t, 1, len(filtered))
	assert.Equal(t, "rhel-9-server-rpms", filtered[0])

	// modified_since after both LastChange values
	modifiedSince2, _ := time.Parse(time.RFC3339, "2024-12-01T00:00:00+00:00")
	req = &ReposRequest{ModifiedSince: &modifiedSince2}
	filtered = filterInputRepos(c, []string{"rhel-9-server-rpms"}, req)
	// both repoIDs have LastChange before modified_since, label must be excluded
	assert.Equal(t, 0, len(filtered))
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
	req := ReposRequest{ShowPackages: true}
	repoDetailSlice, _ := c.getRepoDetailSlice(&req, "rhel-6-server-rpms", map[RepoID][]ErratumID{})
	assert.Equal(t, 2, len(repoDetailSlice))
}

func TestGetRepoDetails(t *testing.T) {
	c := mockCache()
	req := ReposRequest{ShowPackages: true}
	repos := []string{"rhel-6-server-rpms", "rhel-7-server-rpms", "rhel-8-server-rpms"}
	expectedChange, _ := time.Parse(time.RFC3339, "2024-11-18T17:58:00+01:00")
	_, latestRepoChange, actualPageSize := c.getRepoDetails(&req, repos, map[RepoID][]ErratumID{})
	assert.Equal(t, expectedChange, *latestRepoChange)
	assert.Equal(t, 4, actualPageSize)

	_, latestRepoChange, _ = c.getRepoDetails(&req, []string{"rhel-7-server-rpms"}, map[RepoID][]ErratumID{})
	assert.Nil(t, latestRepoChange)
}

func TestRepos(t *testing.T) {
	req := &ReposRequest{}
	// empty repository list
	_, err := req.repos(nil)
	assert.Error(t, err)
}
