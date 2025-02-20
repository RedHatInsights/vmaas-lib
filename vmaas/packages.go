package vmaas

import (
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PackageDetails map[string]interface{}

type Packages struct {
	Packages   PackageDetails `json:"package_list"`
	LastChange time.Time      `json:"last_change"`
}

func filterInputPkgs(c *Cache, pkgs []string, req *PackagesRequest) ([]string, map[string]PkgID) {
	isDuplicate := make(map[string]bool, len(pkgs))
	filteredOut := make([]string, 0, len(pkgs))
	filtered := make(map[string]PkgID, len(pkgs))
	for _, pkg := range pkgs {
		if isDuplicate[pkg] {
			continue
		}
		isDuplicate[pkg] = true

		nevra, err := utils.ParseNevra(pkg, false)
		if err != nil {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		pkgID := c.nevra2PkgID(nevra)
		if pkgID == 0 {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		if !req.ThirdParty && c.isPkgThirdParty(pkgID) {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		filtered[pkg] = pkgID
	}
	return filteredOut, filtered
}

func (c *Cache) getPackageDetails(filteredOut []string, pkgs2pkgIDs map[string]PkgID) PackageDetails {
	pkgDetails := make(PackageDetails, len(pkgs2pkgIDs))
	for pkg, pkgID := range pkgs2pkgIDs {
		pd, ok := c.PackageDetails[pkgID]
		if !ok {
			filteredOut = append(filteredOut, pkg)
			continue
		}

		pkgDetail := PackageDetailResponse{
			Summary:       c.String[pd.SummaryID],
			Description:   c.String[pd.DescriptionID],
			SourcePackage: c.srcPkgID2Pkg(pd.SrcPkgID),
			Repositories:  c.pkgID2Repos(pkgID),
			Packages:      c.pkgID2BuiltBinaryPkgs(pkgID),
		}

		pkgDetails[pkg] = pkgDetail
	}

	for _, pkg := range filteredOut {
		pkgDetails[pkg] = struct{}{}
	}

	return pkgDetails
}

func (req *PackagesRequest) packages(c *Cache) (*Packages, error) { // TODO: implement opts
	pkgs := req.Packages
	if len(pkgs) == 0 {
		return &Packages{}, errors.Wrap(ErrProcessingInput, "'package_list' is a required property")
	}

	filteredOut, pkgs2pkgIDs := filterInputPkgs(c, pkgs, req)

	res := Packages{
		Packages:   c.getPackageDetails(filteredOut, pkgs2pkgIDs),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
