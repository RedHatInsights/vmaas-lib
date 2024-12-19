package vmaas

import (
	"os"
	"strings"
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

var RepoPrefixes = strings.Split(os.Getenv("REPO_NAME_PREFIXES"), ",")

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

func (c *Cache) loadRepoDetailSlice(repo string, repoID2ErratumIDs map[RepoID][]ErratumID) ([]RepoDetail, *time.Time) {
	repoIDs := c.RepoLabel2IDs[repo]
	contentSetID := c.Label2ContentSetID[repo]
	repoDetailSlice := make([]RepoDetail, 0, len(repoIDs))
	var latestChange *time.Time
	for _, repoID := range repoIDs {
		repoDerail := c.RepoDetails[repoID]
		repoDerail.Label = repo
		repoDerail.CPEs = c.repoID2CPEs(repoID, contentSetID)
		erratumIDs := repoID2ErratumIDs[repoID]
		repoDerail.UpdatedPackageNames = c.erratumIDs2PackageNames(erratumIDs)
		lastChange := repoDerail.LastChange
		if latestChange == nil || (lastChange != nil && lastChange.After(*latestChange)) {
			latestChange = lastChange
		}
		repoDetailSlice = append(repoDetailSlice, repoDerail)
	}
	return repoDetailSlice, latestChange
}

func (c *Cache) loadRepoDetails(repos []string, repoID2ErratumIDs map[RepoID][]ErratumID) (
	RepoDetails, *time.Time, int,
) {
	repodDetails := make(RepoDetails, len(repos))
	var latestRepoChange *time.Time
	actualPageSize := 0
	for _, repo := range repos {
		repoDetailSlice, latestChange := c.loadRepoDetailSlice(repo, repoID2ErratumIDs)
		if latestRepoChange == nil || (latestChange != nil && latestChange.After(*latestRepoChange)) {
			latestRepoChange = latestChange
		}
		repodDetails[repo] = repoDetailSlice
		actualPageSize += len(repoDetailSlice)
	}
	return repodDetails, latestRepoChange, actualPageSize
}

func (req *ReposRequest) repos(c *Cache) (*Repos, error) { // TODO: implement opts
	if len(req.Repos) == 0 {
		return nil, errors.Wrap(ErrProcessingInput, "'repository_list' is a required property")
	}
	repos := utils.StripPrefixes(req.Repos, RepoPrefixes)
	repos, err := utils.TryExpandRegexPattern(repos, c.RepoLabel2IDs)
	if err != nil {
		return nil, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}
	repos = filterInputRepos(c, repos, req)
	repos, paginationDetails := utils.Paginate(repos, req.PageNumber, req.PageSize)

	repoID2ErratumIDs := c.buildRepoID2ErratumIDs(req.ModifiedSince, req.ShowPackages)
	repoDetails, latestRepoChange, actualPageSize := c.loadRepoDetails(repos, repoID2ErratumIDs)
	paginationDetails.PageSize = actualPageSize
	res := Repos{
		Repos:             repoDetails,
		LatestRepoChange:  latestRepoChange,
		LastChange:        c.DBChange.LastChange,
		PaginationDetails: paginationDetails,
	}
	return &res, nil
}
