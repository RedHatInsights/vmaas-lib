package vmaas

import (
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PkgTreeErratumDetail struct {
	Name    string     `json:"name"`
	Issued  *time.Time `json:"issued"`
	Updated *time.Time `json:"updated"`
	CVEs    []string   `json:"cve_list"`
}

type PkgTreeRepoDetail struct {
	RepoDetailCommon
	Revision string `json:"revision"`
	// ModuleStream
}

type PkgTreeItem struct {
	Nevra          string                  `json:"nevra"`
	Summary        string                  `json:"summary,omitempty"`
	Description    string                  `json:"description,omitempty"`
	FirstPublished *time.Time              `json:"first_published,omitempty"`
	Repositories   *[]PkgTreeRepoDetail    `json:"repositories,omitempty"`
	Errata         *[]PkgTreeErratumDetail `json:"errata,omitempty"`
}

type PkgTreeItems map[string][]PkgTreeItem

type PkgTree struct {
	PackageNames PkgTreeItems `json:"package_name_list"`
	LastChange   time.Time    `json:"last_change"`
	utils.Pagination
}

func (c *Cache) getPackageRepos(pkgID PkgID) ([]PkgTreeRepoDetail, bool) {
	repoIDs, ok := c.PkgID2RepoIDs[pkgID]
	if !ok {
		return []PkgTreeRepoDetail{}, false
	}

	thirdPartyOnly := true
	repos := make([]PkgTreeRepoDetail, 0, len(repoIDs))
	for _, repoID := range repoIDs {
		repoDetail, found := c.RepoDetails[repoID]
		if !found {
			continue
		}
		if !repoDetail.ThirdParty {
			thirdPartyOnly = false
		}
		repos = append(repos, PkgTreeRepoDetail{
			RepoDetailCommon: RepoDetailCommon{
				Label:      repoDetail.Label,
				Name:       repoDetail.Name,
				Basearch:   repoDetail.Basearch,
				Releasever: repoDetail.Releasever,
			},
			Revision: repoDetail.Revision,
		}) // TODO: add support for ModuleStream
	}
	slices.SortFunc(repos, func(a, b PkgTreeRepoDetail) int {
		return strings.Compare(a.Label, b.Label)
	})
	return repos, len(repos) > 0 && thirdPartyOnly
}

func (c *Cache) getPackageErrata(req *PkgTreeRequest, pkgID PkgID) ([]PkgTreeErratumDetail, *time.Time, bool) {
	erratumIDs, ok := c.PkgID2ErratumIDs[pkgID]
	if !ok {
		return []PkgTreeErratumDetail{}, nil, false
	}

	var modifiedFound bool
	var firstPublished *time.Time
	errata := make([]PkgTreeErratumDetail, 0, len(erratumIDs))
	for _, erratumID := range erratumIDs {
		erratum, found := c.ErratumID2Name[erratumID]
		if !found {
			continue
		}
		erratumDetail, found := c.ErratumDetails[erratum]
		if !found {
			continue
		}
		if !req.ThirdParty && erratumDetail.ThirdParty {
			continue
		}
		if req.ModifiedSince != nil {
			if erratumDetail.Updated == nil || req.ModifiedSince.After(*erratumDetail.Updated) {
				continue
			}
			modifiedFound = true
		}
		cves := erratumDetail.CVEs
		if cves == nil {
			cves = []string{}
		}
		slices.Sort(cves)
		errata = append(errata, PkgTreeErratumDetail{
			Name:    erratum,
			Issued:  erratumDetail.Issued,
			Updated: erratumDetail.Updated,
			CVEs:    cves,
		})

		if erratumDetail.Issued != nil {
			if firstPublished == nil || firstPublished.After(*erratumDetail.Issued) {
				firstPublished = erratumDetail.Issued
			}
		}
	}
	slices.SortFunc(errata, func(a, b PkgTreeErratumDetail) int {
		return strings.Compare(a.Name, b.Name)
	})
	return errata, firstPublished, !modifiedFound && req.ModifiedSince != nil
}

func (c *Cache) getPkgTreeItem(req *PkgTreeRequest, pkgID PkgID) *PkgTreeItem {
	pkgDetail, found := c.PackageDetails[pkgID]
	if !found {
		return nil
	}

	item := PkgTreeItem{Nevra: c.pkgDetail2Nevra(pkgDetail)}
	if req.ReturnRepositories == nil || *req.ReturnRepositories {
		repos, thirdPartyOnly := c.getPackageRepos(pkgID)
		if !req.ThirdParty && thirdPartyOnly {
			return nil
		}
		item.Repositories = &repos
	}

	errata, firstPublished, modifiedSinceSkip := c.getPackageErrata(req, pkgID)
	if modifiedSinceSkip {
		return nil
	}
	if req.ReturnErrata == nil || *req.ReturnErrata {
		item.Errata = &errata
		item.FirstPublished = firstPublished
	}

	if req.ReturnSummary {
		item.Summary = c.String[pkgDetail.SummaryID]
	}

	if req.ReturnDescription {
		item.Description = c.String[pkgDetail.DescriptionID]
	}
	return &item
}

func (c *Cache) getPkgTreeItems(req *PkgTreeRequest, names []string) PkgTreeItems {
	pkgTree := make(PkgTreeItems, len(names))
	for _, name := range names {
		nameID, found := c.Packagename2ID[name]
		if !found {
			pkgTree[name] = []PkgTreeItem{}
			continue
		}

		items := make([]PkgTreeItem, 0)
		pkgIDs := c.Updates[nameID]
		for _, id := range pkgIDs {
			item := c.getPkgTreeItem(req, id)
			if item != nil {
				items = append(items, *item)
			}
		}

		slices.SortFunc(items, func(a, b PkgTreeItem) int {
			an, aErr := utils.ParseNevra(a.Nevra, false)
			bn, bErr := utils.ParseNevra(b.Nevra, false)
			if aErr != nil || bErr != nil {
				return strings.Compare(a.Nevra, b.Nevra)
			}
			return an.Cmp(&bn)
		})
		pkgTree[name] = items
	}
	return pkgTree
}

func (req *PkgTreeRequest) pkgtree(c *Cache) (*PkgTree, error) { // TODO: implement opts
	names := req.PackageNames
	if len(names) == 0 {
		return &PkgTree{}, errors.Wrap(ErrProcessingInput, "'package_name_list' is a required property")
	}

	names, err := utils.TryExpandRegexPattern(names, c.Packagename2ID)
	if err != nil {
		return &PkgTree{}, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}

	slices.Sort(names)
	names, pagination := utils.Paginate(names, req.PaginationRequest)

	res := PkgTree{
		PackageNames: c.getPkgTreeItems(req, names),
		LastChange:   c.DBChange.LastChange,
		Pagination:   pagination,
	}
	return &res, nil
}
