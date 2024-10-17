package vmaas

import (
	"slices"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type CveDetails map[string]CveDetail

type Cves struct {
	Cves       CveDetails `json:"cve_list"`
	LastChange string     `json:"last_change"`
	utils.PaginationDetails
}

func (c *Cache) pkgDetail2Nevra(pkgDetail PackageDetail) string {
	evr := c.ID2Evr[pkgDetail.EvrID]
	nevra := utils.Nevra{
		Name:    c.ID2Packagename[pkgDetail.NameID],
		Epoch:   evr.Epoch,
		Version: evr.Version,
		Release: evr.Release,
		Arch:    c.ID2Arch[pkgDetail.ArchID],
	}
	return nevra.String()
}

func (c *Cache) errataIDs2Names(eids []int) []string {
	names := make([]string, 0, len(eids))
	for _, eid := range eids {
		names = append(names, c.ErratumID2Name[ErratumID(eid)])
	}
	return names
}

func (c *Cache) packageIDs2Nevras(pkgIDs []int) ([]string, []string) {
	binPackages := make([]string, 0, len(pkgIDs))
	sourcePackages := make([]string, 0, len(pkgIDs))
	sourceArchID := c.Arch2ID["src"]
	for _, pkgID := range pkgIDs {
		pkgDetail := c.PackageDetails[PkgID(pkgID)]
		nevra := c.pkgDetail2Nevra(pkgDetail)
		if nevra == "" {
			continue
		}
		if pkgDetail.ArchID == sourceArchID {
			sourcePackages = append(sourcePackages, nevra)
		} else {
			binPackages = append(binPackages, nevra)
		}
	}
	return binPackages, sourcePackages
}

func (req *CvesRequest) getSortedCves(c *Cache) ([]string, error) {
	cves := req.Cves
	if len(cves) == 0 {
		return nil, errors.New("cve_list must contain at least one item")
	}
	cves = utils.TryExpandRegexPattern(cves, c.CveDetail)
	slices.Sort(cves)
	return cves, nil
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

		if req.ModifiedSince != nil && cveDetail.ModifiedDate != nil {
			if cveDetail.ModifiedDate.Before(*req.ModifiedSince) {
				continue
			}
		}
		if req.PublishedSince != nil && cveDetail.PublishedDate != nil {
			if cveDetail.PublishedDate.Before(*req.PublishedSince) {
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
		cveDetails[cve] = cveDetail
	}
	return cveDetails
}

func (req *CvesRequest) cves(c *Cache) (*Cves, error) { // TODO: implement opts
	cves, err := req.getSortedCves(c)
	if err != nil {
		return nil, err
	}

	cves = filterInputCves(c, cves, req)
	cves, paginationDetails := utils.Paginate(cves, req.PageNumber, req.PageSize)

	res := Cves{
		Cves:              c.loadCveDetails(cves),
		LastChange:        c.DBChange.LastChange,
		PaginationDetails: paginationDetails,
	}
	return &res, nil
}
