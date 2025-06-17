package vmaas

import (
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type ContentData map[string][]string

type RPMPkgNames struct {
	Names      ContentData `json:"rpm_name_list"` // TODO: use `omitzero` from go1.24
	LastChange time.Time   `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
}

func (c *Cache) getContentData(rpmNames []string, contentSets []string) ContentData {
	csMap := make(map[string]bool, len(contentSets))
	for _, cs := range contentSets {
		csMap[cs] = true
	}

	isDuplicate := make(map[string]bool, len(rpmNames))
	contentData := make(ContentData, len(rpmNames))
	for _, name := range rpmNames {
		nameID, found := c.Packagename2ID[name]
		if !found || isDuplicate[name] {
			continue
		}

		csIDs := c.nameID2ContentSetIDs(nameID)
		labels := c.contentSetIDs2Labels(csIDs)
		if len(contentSets) != 0 {
			labels = utils.Intersection(labels, csMap)
		}
		slices.Sort(labels)
		contentData[name] = labels
		isDuplicate[name] = true
	}
	return contentData
}

func (req *RPMPkgNamesRequest) rpmPkgNames(c *Cache) (*RPMPkgNames, error) { // TODO: implement opts
	if req.RPMNames == nil {
		return &RPMPkgNames{}, errors.Wrap(ErrProcessingInput, "'rpm_name_list' is a required property")
	}

	if len(req.RPMNames) == 0 {
		return &RPMPkgNames{}, nil
	}

	res := RPMPkgNames{
		Names:      c.getContentData(req.RPMNames, req.ContentSets),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
