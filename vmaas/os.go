package vmaas

import (
	"encoding/json"
)

type VulnerabilityReport struct {
	OSReleases []OSReleaseDetail `json:"os_releases"`
	LastChange string            `json:"last_change"`
}

func evaluateCveCounts(c *Cache, opts *options, release *OSReleaseDetail) error {
	request := Request{}
	err := json.Unmarshal([]byte(release.SystemProfile), &request)
	if err != nil {
		return err
	}
	cves, err := evaluate(c, opts, &request)
	if err != nil {
		return err
	}

	for cve := range cves.Cves {
		cveDetail := c.CveDetail[cve]
		switch impact := cveDetail.Impact; impact {
		case CriticalCveImpact:
			release.CvesCritical++
		case ImportantCveImpact:
			release.CvesImportant++
		case ModerateCveImpact:
			release.CvesModerate++
		case LowCveImpact:
			release.CvesLow++
		}
	}

	for cve := range cves.UnpatchedCves {
		cveDetail := c.CveDetail[cve]
		switch impact := cveDetail.Impact; impact {
		case CriticalCveImpact:
			release.CvesUnpatchedCritical++
		case ImportantCveImpact:
			release.CvesUnpatchedImportant++
		case ModerateCveImpact:
			release.CvesUnpatchedModerate++
		case LowCveImpact:
			release.CvesUnpatchedLow++
		}
	}
	return nil
}

func prepareVulnerabilityReport(c *Cache, opts *options) ([]OSReleaseDetail, error) {
	OSReleases := []OSReleaseDetail{}
	for _, release := range c.OSReleaseDetails {
		err := evaluateCveCounts(c, opts, &release)
		if err != nil {
			return OSReleases, err
		}
		OSReleases = append(OSReleases, release)
	}
	return OSReleases, nil
}

func vulnerabilityReport(c *Cache, opts *options) (*VulnerabilityReport, error) {
	vulnReport, err := prepareVulnerabilityReport(c, opts)
	if err != nil {
		return nil, err
	}
	res := VulnerabilityReport{
		OSReleases: vulnReport,
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
