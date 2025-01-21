package vmaas

import (
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type PkgList struct {
	PkgList    []PkgListItem `json:"package_list"`
	Total      int           `json:"total"`
	LastChange string        `json:"last_change"`
	utils.PaginationDetails
}

func (req *PkgListRequest) getFilteredPkgList(c *Cache) []PkgID {
	return nil // TODO: implement func
}

func (c *Cache) loadPkgListItems(pkgListItemIDs []PkgID, returnModified bool) []PkgListItem {
	return nil // TODO: implement func
}

func (req *PkgListRequest) pkglist(c *Cache) (*PkgList, error) { // TODO: implement opts
	pkgIDs := req.getFilteredPkgList(c)
	pkgListItemIDs, paginationDetails := utils.Paginate(pkgIDs, req.PageNumber, req.PageSize)
	res := PkgList{
		PkgList:           c.loadPkgListItems(pkgListItemIDs, req.ReturnModified),
		Total:             len(pkgIDs),
		LastChange:        c.DBChange.LastChange,
		PaginationDetails: paginationDetails,
	}
	return &res, nil
}
