package vmaas

import (
	"slices"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PkgList struct {
	PkgList []PkgListItem `json:"package_list"`
	// Total number of packages to return.
	Total      int       `json:"total" example:"100"`
	LastChange time.Time `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
	utils.Pagination
}

func (c *Cache) getFilteredPkgList(req *PkgListRequest) []PkgID {
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

func (c *Cache) getPkgListItems(pkgListItemIDs []PkgID, returnModified bool) []PkgListItem {
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

func (req *PkgListRequest) pkglist(c *Cache) *PkgList { // TODO: implement opts
	pkgIDs := c.getFilteredPkgList(req)
	pkgListItemIDs, pagination := utils.Paginate(pkgIDs, req.PaginationRequest)

	res := PkgList{
		PkgList:    c.getPkgListItems(pkgListItemIDs, req.ReturnModified),
		Total:      len(pkgIDs),
		LastChange: c.DBChange.LastChange,
		Pagination: pagination,
	}
	return &res
}
