package vmaas

import (
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type CveDetails map[string]CveDetail

type Cves struct {
	Cves       CveDetails `json:"cve_list"`
	LastChange time.Time  `json:"last_change"`
	utils.Pagination
}

func filterInputCves(c *Cache, cves []string, req *CvesRequest) []string {
	filteredIDs := make([]string, 0, len(cves))
	for _, cve := range cves {
		if cve == "" {
			continue
		}
		cveDetail, found := c.CveDetail[cve]
		if !found {
			continue
		}
		if req.RHOnly && cveDetail.Source != "Red Hat" {
			continue
		}
		if req.AreErrataAssociated && len(cveDetail.ErrataIDs) == 0 {
			// FIXME: also check CSAF
			continue
		}

		if req.ModifiedSince != nil {
			if cveDetail.ModifiedDate == nil || cveDetail.ModifiedDate.Before(*req.ModifiedSince) {
				continue
			}
		}
		if req.PublishedSince != nil {
			if cveDetail.PublishedDate == nil || cveDetail.PublishedDate.Before(*req.PublishedSince) {
				continue
			}
		}

		filteredIDs = append(filteredIDs, cve)
	}
	return filteredIDs
}

func (c *Cache) loadCveDetails(cves []string) CveDetails {
	cveDetails := make(CveDetails, len(cves))
	for _, cve := range cves {
		cveDetail := c.CveDetail[cve]
		cveDetail.Name = cve
		cveDetail.Errata = c.errataIDs2Names(cveDetail.ErrataIDs)
		binPackages, sourcePackages := c.packageIDs2Nevras(cveDetail.PkgIDs)
		cveDetail.Packages = binPackages
		cveDetail.SourcePackages = sourcePackages
		if cveDetail.CWEs == nil {
			cveDetail.CWEs = []string{}
		}
		cveDetails[cve] = cveDetail
	}
	return cveDetails
}

func (req *CvesRequest) cves(c *Cache) (*Cves, error) { // TODO: implement opts
	cves := req.Cves
	if len(cves) == 0 {
		return &Cves{}, errors.Wrap(ErrProcessingInput, "'cve_list' is a required property")
	}

	cves, err := utils.TryExpandRegexPattern(cves, c.CveDetail)
	if err != nil {
		return &Cves{}, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}

	cves = filterInputCves(c, cves, req)
	slices.Sort(cves)
	cves, pagination := utils.Paginate(cves, req.PaginationRequest)

	res := Cves{
		Cves:       c.loadCveDetails(cves),
		LastChange: c.DBChange.LastChange,
		Pagination: pagination,
	}
	return &res, nil
}
