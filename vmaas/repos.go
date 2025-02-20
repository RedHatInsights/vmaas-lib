package vmaas

import (
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type RepoDetails map[string][]RepoDetail

type Repos struct {
	Repos            RepoDetails `json:"repository_list"`
	LatestRepoChange *time.Time  `json:"latest_repo_change,omitempty"`
	LastChange       string      `json:"last_change"`
	utils.PaginationDetails
}

func filterInputRepos(c *Cache, repos []string, req *ReposRequest) []string {
	isDuplicate := make(map[string]bool, len(repos))
	filteredRepos := make([]string, 0, len(repos))
	for _, repo := range repos {
		if repo == "" || isDuplicate[repo] {
			continue
		}
		repoIDs, found := c.RepoLabel2IDs[repo]
		if !found || len(repoIDs) == 0 {
			continue
		}
		repoDetail, found := c.RepoDetails[repoIDs[len(repoIDs)-1]]
		if !found {
			continue
		}

		if req.ModifiedSince != nil {
			if req.ModifiedSince.After(time.Now()) {
				continue
			}
			if repoDetail.LastChange != nil && repoDetail.LastChange.Before(*req.ModifiedSince) {
				continue
			}
		}

		if !req.ThirdParty && repoDetail.ThirdParty {
			continue
		}

		filteredRepos = append(filteredRepos, repo)
		isDuplicate[repo] = true
	}
	return filteredRepos
}

func (c *Cache) repoID2CPEs(repoID RepoID, contentSetID ContentSetID) []string {
	cpeIDs, found := c.RepoID2CpeIDs[repoID]
	if !found {
		cpeIDs = c.ContentSetID2CpeIDs[contentSetID]
	}
	return c.cpeIDs2Labels(cpeIDs)
}

func (c *Cache) getRepoDetailSlice(repo string, repoID2ErratumIDs map[RepoID][]ErratumID, showPackages bool) (
	[]RepoDetail, *time.Time,
) {
	repoIDs := c.RepoLabel2IDs[repo]
	contentSetID := c.Label2ContentSetID[repo]
	repoDetailSlice := make([]RepoDetail, 0, len(repoIDs))
	var latestChange *time.Time
	for _, repoID := range repoIDs {
		repoDetail := c.RepoDetails[repoID]
		repoDetail.Label = repo
		repoDetail.CPEs = c.repoID2CPEs(repoID, contentSetID)
		if showPackages {
			erratumIDs := repoID2ErratumIDs[repoID]
			pkgNames := c.erratumIDs2PackageNames(erratumIDs)
			repoDetail.UpdatedPackageNames = &pkgNames
		}
		repoDetailSlice = append(repoDetailSlice, repoDetail)

		lastChange := repoDetail.LastChange
		if latestChange == nil || (lastChange != nil && lastChange.After(*latestChange)) {
			latestChange = lastChange
		}
	}
	return repoDetailSlice, latestChange
}

func (c *Cache) getRepoDetails(repos []string, repoID2ErratumIDs map[RepoID][]ErratumID, showPackages bool) (
	RepoDetails, *time.Time, int,
) {
	repoDetails := make(RepoDetails, len(repos))
	var latestRepoChange *time.Time
	actualPageSize := 0
	for _, repo := range repos {
		repoDetailSlice, latestChange := c.getRepoDetailSlice(repo, repoID2ErratumIDs, showPackages)
		if latestRepoChange == nil || (latestChange != nil && latestChange.After(*latestRepoChange)) {
			latestRepoChange = latestChange
		}
		repoDetails[repo] = repoDetailSlice
		actualPageSize += len(repoDetailSlice)
	}
	return repoDetails, latestRepoChange, actualPageSize
}

func (req *ReposRequest) repos(c *Cache) (*Repos, error) { // TODO: implement opts
	if len(req.Repos) == 0 {
		return &Repos{}, errors.Wrap(ErrProcessingInput, "'repository_list' is a required property")
	}
	repos, err := utils.TryExpandRegexPattern(req.Repos, c.RepoLabel2IDs)
	if err != nil {
		return &Repos{}, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}
	repos = filterInputRepos(c, repos, req)
	repos, paginationDetails := utils.Paginate(repos, req.PageNumber, req.PageSize)

	repoID2ErratumIDs := c.buildRepoID2ErratumIDs(req.ModifiedSince)
	repoDetails, latestRepoChange, actualPageSize := c.getRepoDetails(repos, repoID2ErratumIDs, req.ShowPackages)
	paginationDetails.PageSize = actualPageSize
	res := Repos{
		Repos:             repoDetails,
		LatestRepoChange:  latestRepoChange,
		LastChange:        c.DBChange.LastChange,
		PaginationDetails: paginationDetails,
	}
	return &res, nil
}
