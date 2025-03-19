package vmaas

import (
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type RPMData map[string]map[string][]string

type SRPMPkgNames struct {
	Names      RPMData   `json:"srpm_name_list"` // TODO: use `omitzero` from go1.24
	LastChange time.Time `json:"last_change"`
}

// GetSrcPkgPkgNameIDs returns package names of the packages under the source package with srcNameID.
func (c *Cache) getSrcPkgPkgNameIDs(srcNameID NameID) map[NameID]bool {
	pkgNameIDs := map[NameID]bool{}
	for nevra, pkgID := range c.Nevra2PkgID {
		pkgIDs, found := c.SrcPkgID2PkgID[pkgID]
		if nevra.NameID != srcNameID || !found {
			continue
		}
		for _, pid := range pkgIDs {
			nameID := c.PackageDetails[pid].NameID
			pkgNameIDs[nameID] = true
		}
	}
	return pkgNameIDs
}

func (c *Cache) getRPMData(srpmNames []string, contentSets []string) RPMData {
	csMap := c.labels2ContentSetIDs(contentSets)
	isDuplicate := make(map[string]bool, len(srpmNames))
	rpmData := make(RPMData, len(srpmNames))
	for _, srpm := range srpmNames {
		srcNameID, found := c.Packagename2ID[srpm]
		if !found || isDuplicate[srpm] {
			continue
		}

		csIDs := c.nameID2ContentSetIDs(srcNameID)
		csIDs = append(csIDs, c.SrcPkgNameID2ContentSetIDs[srcNameID]...)
		if len(contentSets) != 0 {
			csIDs = utils.Intersection(csIDs, csMap)
		}

		pkgNameIDs := c.getSrcPkgPkgNameIDs(srcNameID)
		if len(pkgNameIDs) == 0 {
			continue
		}

		filteredNames := make(map[string][]string, len(csIDs))
		for _, id := range csIDs {
			label := c.ContentSetID2Label[id]
			nameIDs := utils.Intersection(c.ContentSetID2PkgNameIDs[id], pkgNameIDs)
			names := c.nameIDs2PackageNames(nameIDs)
			slices.Sort(names)
			filteredNames[label] = names
		}

		rpmData[srpm] = filteredNames
		isDuplicate[srpm] = true
	}
	return rpmData
}

func (req *SRPMPkgNamesRequest) srpmPkgNames(c *Cache) (*SRPMPkgNames, error) { // TODO: implement opts
	if req.SRPMNames == nil {
		return &SRPMPkgNames{}, errors.Wrap(ErrProcessingInput, "'srpm_name_list' is a required property")
	}

	if len(req.SRPMNames) == 0 {
		return &SRPMPkgNames{}, nil
	}

	res := SRPMPkgNames{
		Names:      c.getRPMData(req.SRPMNames, req.ContentSets),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
