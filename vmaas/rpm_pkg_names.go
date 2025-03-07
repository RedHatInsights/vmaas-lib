package vmaas

import (
	"slices"

	"github.com/pkg/errors"
)

type ContentData map[string][]string

type RPMPkgNames struct {
	Names      ContentData `json:"rpm_name_list"`
	LastChange string      `json:"last_change"`
}

func (c *Cache) getContentSetLabels(nameID NameID, contentSets map[string]bool) []string {
	labels, found := c.PkgNameID2ContentSetLabels[nameID]
	if !found {
		return []string{}
	}
	if len(contentSets) == 0 {
		return labels
	}

	filtered := make([]string, 0, len(labels))
	for _, label := range labels {
		if contentSets[label] {
			filtered = append(filtered, label)
		}
	}
	return filtered
}

func (c *Cache) getContentData(req *RPMPkgNamesRequest) ContentData {
	namesLen := len(req.Names)
	isDuplicate := make(map[string]bool, namesLen)
	contentData := make(ContentData, namesLen)

	csMap := make(map[string]bool, len(req.ContentSets))
	for _, cs := range req.ContentSets {
		csMap[cs] = true
	}

	for _, name := range req.Names {
		nameID, found := c.Packagename2ID[name]
		if !found || isDuplicate[name] {
			continue
		}

		labels := c.getContentSetLabels(nameID, csMap)
		slices.Sort(labels)
		contentData[name] = labels
		isDuplicate[name] = true
	}
	return contentData
}

func (req *RPMPkgNamesRequest) rpmPkgNames(c *Cache) (*RPMPkgNames, error) { // TODO: implement opts
	if len(req.Names) == 0 {
		return &RPMPkgNames{}, errors.Wrap(ErrProcessingInput, "'rpm_name_list' is a required property")
	}

	res := RPMPkgNames{
		Names:      c.getContentData(req),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
