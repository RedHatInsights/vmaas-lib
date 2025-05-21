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
