package vmaas

import (
	"slices"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PkgList struct {
	PkgList    []PkgListItem `json:"package_list"`
	Total      int           `json:"total"`
	LastChange time.Time     `json:"last_change"`
	utils.Pagination
}

func (req *PkgListRequest) getFilteredPkgList(c *Cache) []PkgID {
	if req.ModifiedSince == nil {
		return c.PackageDetailsModifiedIndex
	}

	i, _ := slices.BinarySearchFunc(c.PackageDetailsModifiedIndex, req.ModifiedSince, func(aID PkgID, b *time.Time) int {
		a := c.PackageDetails[aID].Modified
		if a == nil || b == nil {
			return utils.Bool2Int(b == nil) - utils.Bool2Int(a == nil)
		}
		return a.Compare(*b)
	})
	if i >= len(c.PackageDetailsModifiedIndex) {
		return []PkgID{}
	}
	return c.PackageDetailsModifiedIndex[i:]
}

func (c *Cache) loadPkgListItems(pkgListItemIDs []PkgID, returnModified bool) []PkgListItem {
	pkgList := make([]PkgListItem, 0, len(pkgListItemIDs))
	for _, pkgID := range pkgListItemIDs {
		pkgDetail := c.PackageDetails[pkgID]
		item := PkgListItem{
			Nevra:       c.pkgDetail2Nevra(pkgDetail),
			Summary:     c.String[pkgDetail.SummaryID],
			Description: c.String[pkgDetail.DescriptionID],
		}
		if returnModified {
			item.Modified = pkgDetail.Modified
		}
		pkgList = append(pkgList, item)
	}
	return pkgList
}

func (req *PkgListRequest) pkglist(c *Cache) (*PkgList, error) { // TODO: implement opts
	pkgIDs := req.getFilteredPkgList(c)
	pkgListItemIDs, pagination := utils.Paginate(pkgIDs, req.PaginationRequest)

	res := PkgList{
		PkgList:    c.loadPkgListItems(pkgListItemIDs, req.ReturnModified),
		Total:      len(pkgIDs),
		LastChange: c.DBChange.LastChange,
		Pagination: pagination,
	}
	return &res, nil
}
