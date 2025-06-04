package vmaas

import (
	"slices"

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

func releaseNodes2VariantsCpes(
	c *Cache, nodes []*ReleaseNode, exceptVariants map[VariantSuffix]bool,
) ([]VariantSuffix, []CpeID) {
	variants := make([]VariantSuffix, 0)
	cpes := make([]CpeID, 0)
	seenVariants := make(map[VariantSuffix]bool)
	seenCpes := make(map[CpeID]bool)
	for _, node := range nodes {
		for _, nodeCpe := range node.CPEs {
			cpeID, ok := c.CpeLabel2ID[nodeCpe]
			if !ok {
				utils.LogInfo("cpe", nodeCpe, "Unknown CPE")
			}
			if !seenCpes[cpeID] {
				cpes = append(cpes, cpeID)
				seenCpes[cpeID] = true
			}
			if !exceptVariants[node.VariantSuffix] && !seenVariants[node.VariantSuffix] {
				variants = append(variants, node.VariantSuffix)
				seenVariants[node.VariantSuffix] = true
			}
		}
	}
	return variants, cpes
}

func cpes2variantsCpes(c *Cache, cpes []CpeLabel, exceptVariants []VariantSuffix) ([]VariantSuffix, []CpeID) {
	ancestorNodes := make([]*ReleaseNode, 0)
	nodes := releaseNodesFromCpes(c, cpes)
	variants, cpeIDs := releaseNodes2VariantsCpes(c, nodes, nil)

	for _, node := range nodes {
		ancestors := node.GetAncestors()
		ancestorNodes = append(ancestorNodes, ancestors...)
	}

	exceptVariantsMap := make(map[VariantSuffix]bool, len(exceptVariants))
	for _, x := range exceptVariants {
		exceptVariantsMap[x] = true
	}
	for _, x := range variants {
		exceptVariantsMap[x] = true
	}

	ancestorVariants, ancestorCpes := releaseNodes2VariantsCpes(c, ancestorNodes, exceptVariantsMap)
	variants = append(variants, ancestorVariants...)
	cpeIDs = append(cpeIDs, ancestorCpes...)

	slices.SortStableFunc(variants, func(x, y VariantSuffix) int {
		return x.Compare(&y)
	})
	slices.Sort(cpeIDs)
	return variants, cpeIDs
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
