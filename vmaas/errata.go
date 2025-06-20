package vmaas

import (
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type ErratumDetails map[string]ErratumDetail

type Errata struct {
	Errata     ErratumDetails `json:"errata_list"`
	Type       TypeT          `json:"type,omitempty" example:"security"`
	Severity   SeverityT      `json:"severity,omitempty" enums:"Low,Moderate,Important,Critical,null"`
	LastChange time.Time      `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
	utils.Pagination
}

func filterInputErrata(c *Cache, errata []string, req *ErrataRequest) []string {
	isDuplicate := make(map[string]bool, len(errata))
	filteredErrata := make([]string, 0, len(errata))
	for _, erratum := range errata {
		if erratum == "" || isDuplicate[erratum] {
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
			if erratumDetail.Issued != nil && erratumDetail.Issued.Before(*req.ModifiedSince) {
				continue
			}
			if erratumDetail.Updated != nil && erratumDetail.Updated.Before(*req.ModifiedSince) {
				continue
			}
		}

		if req.Type != nil && !slices.Contains(req.Type, erratumDetail.Type) {
			continue
		}

		if req.Severity != nil && !req.Severity.contains(erratumDetail.Severity) {
			continue
		}

		filteredErrata = append(filteredErrata, erratum)
		isDuplicate[erratum] = true
	}
	return filteredErrata
}

func (c *Cache) erratumID2Releasevers(erratumID ErratumID) []string {
	erratumRepos := c.ErratumID2RepoIDs[erratumID]
	releaseVers := make([]string, 0, len(erratumRepos))
	isDuplicate := make(map[string]bool, len(erratumRepos))
	for repoID := range erratumRepos {
		repoDetail := c.RepoDetails[repoID]
		releaseVer := repoDetail.Releasever
		if releaseVer != "" && !isDuplicate[releaseVer] {
			releaseVers = append(releaseVers, releaseVer)
			isDuplicate[releaseVer] = true
		}
	}
	return releaseVers
}

func (c *Cache) getErratumDetails(errata []string) ErratumDetails {
	erratumDetails := make(ErratumDetails, len(errata))
	for _, erratum := range errata {
		erratumDetail := c.ErratumDetails[erratum]
		binPackages, sourcePackages := c.packageIDs2Nevras(erratumDetail.PkgIDs)
		erratumDetail.PackageList = binPackages
		erratumDetail.SourcePackageList = sourcePackages
		erratumDetail.ReleaseVersions = c.erratumID2Releasevers(erratumDetail.ID)
		if erratumDetail.CVEs == nil {
			erratumDetail.CVEs = []string{}
		}
		if erratumDetail.Bugzillas == nil {
			erratumDetail.Bugzillas = []string{}
		}
		if erratumDetail.Refs == nil {
			erratumDetail.Refs = []string{}
		}
		if erratumDetail.Modules == nil {
			erratumDetail.Modules = []Module{}
		}
		erratumDetails[erratum] = erratumDetail
	}
	return erratumDetails
}

func (req *ErrataRequest) errata(c *Cache) (*Errata, error) { // TODO: implement opts
	errata := req.Errata
	if len(errata) == 0 {
		return &Errata{}, errors.Wrap(ErrProcessingInput, "'errata_list' is a required property")
	}

	errata, err := utils.TryExpandRegexPattern(errata, c.ErratumDetails)
	if err != nil {
		return &Errata{}, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}

	errata = filterInputErrata(c, errata, req)
	slices.Sort(errata)
	errata, pagination := utils.Paginate(errata, req.PaginationRequest)

	res := Errata{
		Errata:     c.getErratumDetails(errata),
		Type:       req.Type,
		Severity:   req.Severity,
		LastChange: c.DBChange.LastChange,
		Pagination: pagination,
	}
	return &res, nil
}
