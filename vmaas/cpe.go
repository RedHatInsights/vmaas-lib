package vmaas

import (
	"slices"

	"github.com/hashicorp/go-version"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

func getMatchingCpes(cpeID2Label map[CpeID]CpeLabel, inputCpes []CpeLabel) []CpeLabel {
	type Cpe struct {
		Label  CpeLabel
		Parsed ParsedCpe
	}
	cpes := make([]Cpe, 0)
	if len(inputCpes) > 0 {
		for _, cpeLabel := range cpeID2Label {
			cpeLabelParsed, err := cpeLabel.Parse()
			if err != nil {
				utils.LogWarn("cpe", cpeLabel, "Cannot parse")
				continue
			}
			for _, inputCpe := range inputCpes {
				repoCpeParsed, err := inputCpe.Parse()
				if err != nil {
					utils.LogWarn("cpe", inputCpe, "Cannot parse")
					continue
				}
				if cpeLabelParsed.Match(repoCpeParsed) {
					cpes = append(cpes, Cpe{cpeLabel, *cpeLabelParsed})
					break
				}
			}
		}
	}
	slices.SortFunc(cpes, func(x, y Cpe) int {
		return x.Parsed.CmpByVersion(&y.Parsed)
	})

	res := make([]CpeLabel, 0, len(cpes))
	seen := make(map[CpeLabel]bool, len(cpes))
	for _, cpe := range cpes {
		if !seen[cpe.Label] {
			res = append(res, cpe.Label)
			seen[cpe.Label] = true
		}
	}
	return res
}

func releaseNodesFromCpes(c *Cache, cpes []CpeLabel) []*ReleaseNode {
	res := make([]*ReleaseNode, 0)
	for _, cpe := range cpes {
		for _, graph := range c.ReleaseGraphs {
			nodes, ok := graph.GetByCpe[cpe]
			if !ok {
				continue
			}
			res = append(res, nodes...)
		}
	}
	return res
}

func releaseNodes2VariantCpes(c *Cache, nodes []*ReleaseNode, except map[variantCPE]bool) []variantCPE {
	variantCpes := make([]variantCPE, 0)
	seen := make(map[variantCPE]bool)
	for _, node := range nodes {
		for _, nodeCpe := range node.CPEs {
			cpeID, ok := c.CpeLabel2ID[nodeCpe]
			if !ok {
				utils.LogInfo("cpe", nodeCpe, "Unknown CPE")
			}
			varCpe := variantCPE{
				VariantSuffix: node.VariantSuffix,
				CpeID:         cpeID,
			}
			if !except[varCpe] && !seen[varCpe] {
				variantCpes = append(variantCpes, varCpe)
				seen[varCpe] = true
			}
		}
	}
	return variantCpes
}

func cpes2variantCpes(c *Cache, cpes []CpeLabel, except []variantCPE) []variantCPE {
	ancestorNodes := make([]*ReleaseNode, 0)
	nodes := releaseNodesFromCpes(c, cpes)
	variantCpes := releaseNodes2VariantCpes(c, nodes, nil)

	for _, node := range nodes {
		ancestors := node.GetAncestors()
		ancestorNodes = append(ancestorNodes, ancestors...)
	}

	exceptMap := make(map[variantCPE]bool, len(except))
	for _, x := range except {
		exceptMap[x] = true
	}

	ancestorVariantCpes := releaseNodes2VariantCpes(c, ancestorNodes, exceptMap)
	variantCpes = append(variantCpes, ancestorVariantCpes...)

	slices.SortStableFunc(variantCpes, func(x, y variantCPE) int {
		verX, errx := version.NewVersion(string(x.VariantSuffix))
		verY, erry := version.NewVersion(string(y.VariantSuffix))
		switch {
		case errx != nil && erry != nil:
			return 0
		case errx != nil:
			return -1
		case erry != nil:
			return 1
		}
		return verX.Compare(verY)
	})
	return variantCpes
}

func repos2cpes(c *Cache, repoIDs []RepoID) []CpeLabel {
	repoCpes := make([]CpeID, 0)
	for _, repoID := range repoIDs {
		if cpes, has := c.RepoID2CpeIDs[repoID]; has {
			repoCpes = append(repoCpes, cpes...)
		}
	}
	return c.cpeIDs2Labels(repoCpes)
}

func contentSets2cpes(c *Cache, csIDs []ContentSetID) []CpeLabel {
	csCpes := make([]CpeID, 0)
	for _, csID := range csIDs {
		if cpes, has := c.ContentSetID2CpeIDs[csID]; has {
			csCpes = append(csCpes, cpes...)
		}
	}

	return c.cpeIDs2Labels(csCpes)
}
