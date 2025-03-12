package vmaas

import (
	"io"
	"net/http"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type Cache struct {
	DumpSchemaVersion int

	Packagename2ID map[string]NameID
	ID2Packagename map[NameID]string

	// name -> []pkg ordered by e-v-r ordering
	Updates map[NameID][]PkgID
	// name -> evr -> idx into updates[name]
	UpdatesIndex                map[NameID]map[EvrID][]int
	PackageDetailsModifiedIndex []PkgID

	Evr2ID map[utils.Evr]EvrID
	ID2Evr map[EvrID]utils.Evr

	ID2Arch map[ArchID]string
	Arch2ID map[string]ArchID

	ArchCompat map[ArchID]map[ArchID]bool

	PackageDetails map[PkgID]PackageDetail
	Nevra2PkgID    map[Nevra]PkgID

	RepoIDs            []RepoID
	RepoDetails        map[RepoID]RepoDetail
	RepoLabel2IDs      map[string][]RepoID
	RepoPath2IDs       map[string][]RepoID
	Label2ContentSetID map[string]ContentSetID
	ContentSetID2Label map[ContentSetID]string

	ContentSetID2PkgNameIDs map[ContentSetID][]NameID

	ProductID2RepoIDs map[int][]RepoID
	PkgID2RepoIDs     map[PkgID][]RepoID

	ErratumID2Name    map[ErratumID]string
	PkgID2ErrataIDs   map[PkgID][]ErratumID
	ErratumID2RepoIDs map[ErratumID]map[RepoID]bool

	CveDetail map[string]CveDetail
	CveNames  map[int]string

	PkgErratum2Module map[PkgErratum][]int
	Module2IDs        map[ModuleStream][]int
	ModuleRequires    map[int][]int
	DBChange          DBChange
	ErratumDetails    map[string]ErratumDetail
	SrcPkgID2PkgID    map[PkgID][]PkgID
	String            map[int]string

	ContentSetID2CpeIDs map[ContentSetID][]CpeID
	RepoID2CpeIDs       map[RepoID][]CpeID
	CpeID2Label         map[CpeID]CpeLabel

	// CSAF
	CSAFProductStatus     map[int]string
	CSAFCVEs              map[CpeIDNameID]map[CSAFProduct]CSAFCVEs
	CSAFCVEProduct2Errata map[CSAFCVEProduct]string
	CSAFProduct2ID        map[CSAFProduct]CSAFProductID

	OSReleaseDetails map[int]OSReleaseDetail
}

func ShouldReload(c *Cache, latestDumpEndpoint string) bool {
	if c == nil {
		return true
	}

	resp, err := http.Get(latestDumpEndpoint) //nolint:gosec // url is user's input
	if err != nil {
		utils.LogWarn("err", err.Error(), "Request to latestdump failed")
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.LogWarn("err", err.Error(), "Couldn't read response body")
		return false
	}

	if len(body) == 0 {
		utils.LogWarn("No latestdump info, cache is not exported")
		return false
	}

	latest, err := time.Parse(time.RFC3339, string(body))
	if err != nil {
		utils.LogWarn("err", err.Error(), "Couldn't parse latest timestamp")
		return false
	}

	exported, err := time.Parse(time.RFC3339, c.DBChange.Exported)
	if err != nil {
		utils.LogWarn("err", err.Error(), "Couldn't parse exported timestamp in cache")
		return true
	}

	if latest.After(exported) {
		utils.LogDebug("latest", latest, "exported", exported, "Cache reload needed")
		return true
	}
	utils.LogDebug("latest", latest, "exported", exported, "Cache reload not needed")
	return false
}

func (c *Cache) errataIDs2Names(eids []ErratumID) []string {
	return utils.ApplyMap(eids, c.ErratumID2Name)
}

func (c *Cache) pkgDetail2Nevra(pkgDetail PackageDetail) string {
	evr := c.ID2Evr[pkgDetail.EvrID]
	nevra := utils.Nevra{
		Name:    c.ID2Packagename[pkgDetail.NameID],
		Epoch:   evr.Epoch,
		Version: evr.Version,
		Release: evr.Release,
		Arch:    c.ID2Arch[pkgDetail.ArchID],
	}
	return nevra.String()
}

func (c *Cache) packageIDs2Nevras(pkgIDs []int) ([]string, []string) {
	binPackages := make([]string, 0, len(pkgIDs))
	sourcePackages := make([]string, 0, len(pkgIDs))
	sourceArchID := c.Arch2ID["src"]
	for _, pkgID := range pkgIDs {
		pkgDetail := c.PackageDetails[PkgID(pkgID)]
		nevra := c.pkgDetail2Nevra(pkgDetail)
		if nevra == "" {
			continue
		}
		if pkgDetail.ArchID == sourceArchID {
			sourcePackages = append(sourcePackages, nevra)
		} else {
			binPackages = append(binPackages, nevra)
		}
	}
	return binPackages, sourcePackages
}

func (c *Cache) buildRepoID2ErratumIDs(modifiedSince *time.Time) map[RepoID][]ErratumID {
	if modifiedSince == nil {
		return nil
	}
	repoID2ErrataIDsMap := make(map[RepoID][]ErratumID, len(c.RepoIDs))
	for _, erratumDetail := range c.ErratumDetails {
		if erratumDetail.Updated != nil && !erratumDetail.Updated.After(*modifiedSince) {
			continue
		}
		for repoID := range c.ErratumID2RepoIDs[erratumDetail.ID] {
			repoID2ErrataIDsMap[repoID] = append(repoID2ErrataIDsMap[repoID], erratumDetail.ID)
		}
	}
	return repoID2ErrataIDsMap
}

func (c *Cache) cpeIDs2Labels(cpeIDs []CpeID) []CpeLabel {
	return utils.ApplyMap(cpeIDs, c.CpeID2Label)
}

func (c *Cache) erratumIDs2PackageNames(erratumIDs []ErratumID) []string {
	isDuplicate := make(map[ErratumID]bool, len(erratumIDs))
	pkgNames := make([]string, 0, len(erratumIDs))
	for _, erratumID := range erratumIDs {
		if isDuplicate[erratumID] {
			continue
		}
		isDuplicate[erratumID] = true
		erratum := c.ErratumID2Name[erratumID]
		erratumDetail := c.ErratumDetails[erratum]
		for _, pkgID := range erratumDetail.PkgIDs {
			pkgDetail := c.PackageDetails[PkgID(pkgID)]
			pkgName := c.ID2Packagename[pkgDetail.NameID]
			pkgNames = append(pkgNames, pkgName)
		}
	}
	return pkgNames
}

func (c *Cache) nevra2PkgID(nevra utils.Nevra) PkgID {
	nameID, ok := c.Packagename2ID[nevra.Name]
	if !ok {
		return 0
	}
	evrID, ok := c.Evr2ID[nevra.GetEvr()]
	if !ok {
		return 0
	}
	archID, ok := c.Arch2ID[nevra.Arch]
	if !ok {
		return 0
	}

	key := Nevra{
		NameID: nameID,
		EvrID:  evrID,
		ArchID: archID,
	}
	return c.Nevra2PkgID[key]
}

func (c *Cache) isPkgThirdParty(pkgID PkgID) bool {
	repoIDs := c.PkgID2RepoIDs[pkgID]
	for _, repoID := range repoIDs {
		repoDetail := c.RepoDetails[repoID]
		if repoDetail.ThirdParty {
			return true
		}
	}
	return false
}

func (c *Cache) srcPkgID2Pkg(srcPkgID *PkgID) string {
	if srcPkgID == nil {
		return ""
	}

	srcPackageDetail, ok := c.PackageDetails[*srcPkgID]
	if !ok {
		return ""
	}

	return c.pkgDetail2Nevra(srcPackageDetail)
}

func (c *Cache) pkgID2Repos(pkgID PkgID) []RepoDetailCommon {
	repoIDs, ok := c.PkgID2RepoIDs[pkgID]
	if !ok {
		return []RepoDetailCommon{}
	}

	repoDetails := make([]RepoDetailCommon, 0, len(repoIDs))
	for _, repoID := range repoIDs {
		if repoDetail, ok := c.RepoDetails[repoID]; ok {
			repoDetails = append(repoDetails, repoDetail.RepoDetailCommon)
		}
	}
	return repoDetails
}

func (c *Cache) pkgID2BuiltBinaryPkgs(pkgID PkgID) []string {
	pkgIDs, ok := c.SrcPkgID2PkgID[pkgID]
	if !ok {
		return []string{}
	}

	pkgs := make([]string, 0, len(pkgIDs))
	for _, pkgID := range pkgIDs {
		if packageDetail, ok := c.PackageDetails[pkgID]; ok {
			pkgs = append(pkgs, c.pkgDetail2Nevra(packageDetail))
		}
	}
	return pkgs
}
