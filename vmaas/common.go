package vmaas

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const SecurityErrataType = "security"

type ProcessedRequest struct {
	Updates         *Updates
	Packages        map[string]utils.Nevra
	OriginalRequest *Request
}

func (r *ProcessedRequest) evaluateRepositories(c *Cache) *Updates {
	if len(r.Packages) == 0 {
		return r.Updates
	}

	// Get list of valid repository IDs based on input parameters
	repoIDs := getRepoIDs(c, r.Updates)

	moduleIDs := getModules(c, r.Updates.ModuleList)

	updateList := processUpdates(c, r.Updates.UpdateList, r.Packages, repoIDs, moduleIDs, r.OriginalRequest)
	r.Updates.UpdateList = updateList

	return r.Updates
}

// This method is looking for updates of a package, including name of package to update to,
// associated erratum and repository this erratum is from.
func (r *Request) processRequest(c *Cache) (*ProcessedRequest, error) {
	lastChanged, err := time.Parse(time.RFC3339, c.DBChange.LastChange)
	if err != nil {
		return nil, errors.Wrap(err, "parsing lastChanged")
	}

	pkgsToProcess, updateList := processInputPackages(c, r)
	updates := Updates{
		UpdateList: updateList,
		LastChange: lastChanged,
		Basearch:   r.Basearch,
		Releasever: r.Releasever,
		RepoList:   r.Repos,
		RepoPaths:  r.RepoPaths,
		ModuleList: r.Modules,
	}
	processed := ProcessedRequest{Updates: &updates, Packages: pkgsToProcess, OriginalRequest: r}
	return &processed, nil
}

// Parse input NEVRAs and filter out unknown (or without updates) package names
func processInputPackages(c *Cache, request *Request) (map[string]utils.Nevra, UpdateList) {
	if request == nil {
		return map[string]utils.Nevra{}, UpdateList{}
	}
	pkgsToProcess := filterPkgList(request.Packages, request.LatestOnly)
	filteredPkgsToProcess := make(map[string]utils.Nevra)
	updateList := make(UpdateList)
	for _, pkg := range pkgsToProcess {
		updateList[pkg] = UpdateDetail{}
		nevra, err := utils.ParseNevra(pkg)
		if err != nil {
			utils.Log("nevra", pkg).Warn("Cannot parse")
			continue
		}
		if pkgID, ok := c.Packagename2ID[nevra.Name]; ok {
			if _, ok := c.UpdatesIndex[pkgID]; ok {
				filteredPkgsToProcess[pkg] = nevra
			}
		}
	}
	return filteredPkgsToProcess, updateList
}

func processUpdates(c *Cache, updateList UpdateList, packages map[string]utils.Nevra,
	repoIDs map[RepoID]bool, moduleIDs map[int]bool, r *Request,
) UpdateList {
	for pkg, nevra := range packages {
		updateList[pkg] = processPackagesUpdates(c, nevra, repoIDs, moduleIDs, r)
	}
	return updateList
}

func processPackagesUpdates(c *Cache, nevra utils.Nevra, repoIDs map[RepoID]bool, moduleIDs map[int]bool, r *Request,
) UpdateDetail {
	updateDetail := UpdateDetail{}
	nevraIDs := extractNevraIDs(c, &nevra)

	var updatePkgIDs []PkgID
	var validReleasevers map[string]bool
	switch {
	case len(nevraIDs.EvrIDs) > 0:
		// nevraUpdates
		updatePkgIDs, validReleasevers = nevraUpdates(c, &nevraIDs)
	case r.Optimistic:
		updatePkgIDs = optimisticUpdates(c, &nevraIDs, &nevra)
		validReleasevers = nil
	default:
		return UpdateDetail{}
	}

	for _, u := range updatePkgIDs {
		updateDetail.updatePkgUpdates(c, u, nevraIDs.ArchID, r.SecurityOnly, moduleIDs,
			repoIDs, validReleasevers, r.ThirdParty)
	}
	return updateDetail
}

func (u *UpdateDetail) updatePkgUpdates(c *Cache, pkgID PkgID, archID ArchID, securityOnly bool, modules map[int]bool,
	repoIDs map[RepoID]bool, releasevers map[string]bool, thirdparty bool,
) {
	if archID == 0 {
		return
	}

	// Filter out packages without errata
	if _, ok := c.PkgID2ErrataIDs[pkgID]; !ok {
		return
	}

	// Filter arch compatibility
	updatedNevraArchID := c.PackageDetails[pkgID].ArchID
	if updatedNevraArchID != archID {
		compatArchs := c.ArchCompat[archID]
		if !compatArchs[updatedNevraArchID] {
			return
		}
	}

	errataIDs := c.PkgID2ErrataIDs[pkgID]
	nevra := buildNevra(c, pkgID)
	for _, eid := range errataIDs {
		updates := pkgErrataUpdates(c, pkgID, eid, modules, repoIDs,
			releasevers, nevra, securityOnly, thirdparty)
		u.AvailableUpdates = append(u.AvailableUpdates, updates...)
	}
}

func pkgErrataUpdates(c *Cache, pkgID PkgID, erratumID ErrataID, modules map[int]bool,
	repoIDs map[RepoID]bool, releasevers map[string]bool, nevra utils.Nevra, securityOnly, thirdparty bool,
) []Update {
	erratumName := c.ErrataID2Name[erratumID]
	erratumDetail := c.ErrataDetail[erratumName]

	// Filter out non-security updates
	if filterNonSecurity(erratumDetail, securityOnly) {
		return nil
	}

	// If we don't want third party content, and current advisory is third party, skip it
	if !thirdparty && erratumDetail.ThirdParty {
		return nil
	}

	pkgErrata := PkgErrata{
		PkgID:    int(pkgID),
		ErrataID: int(erratumID),
	}
	errataModules := c.PkgErrata2Module[pkgErrata]
	// return nil if errataModules and modules intersection is empty
	intersects := false
	for _, em := range errataModules {
		if _, ok := modules[em]; ok {
			// at least 1 item in intersection
			intersects = true
			break
		}
	}
	if len(errataModules) > 0 && !intersects {
		return nil
	}

	repos := filterRepositories(c, pkgID, erratumID, repoIDs, releasevers)
	updates := make([]Update, 0, len(repos))
	for _, r := range repos {
		details := c.RepoDetails[r]
		updates = append(updates, Update{
			Package:    nevra.String(),
			Erratum:    erratumName,
			Repository: details.Label,
			Basearch:   details.Basearch,
			Releasever: details.Releasever,
		})
	}
	return updates
}

// Decide whether the errata should be filtered base on 'security only' rule
func filterNonSecurity(errataDetail ErrataDetail, securityOnly bool) bool {
	if !securityOnly {
		return false
	}
	isSecurity := errataDetail.Type == SecurityErrataType || len(errataDetail.CVEs) > 0
	return !isSecurity
}

func filterRepositories(c *Cache, pkgID PkgID, erratumID ErrataID, repoIDs map[RepoID]bool,
	releasevers map[string]bool,
) []RepoID {
	pkgRepos := c.PkgID2RepoIDs[pkgID]
	errataRepos := c.ErrataID2RepoIDs[erratumID]
	result := []RepoID{}
	for _, rid := range pkgRepos {
		if errataRepos[rid] && repoIDs[rid] && isRepoValid(c, rid, releasevers) {
			result = append(result, rid)
		}
	}

	return result
}

func isRepoValid(c *Cache, repoID RepoID, releasevers map[string]bool) bool {
	if len(releasevers) == 0 {
		_, ok := c.RepoDetails[repoID]
		return ok
	}
	repoDetail := c.RepoDetails[repoID]
	return releasevers[repoDetail.Releasever]
}

func buildNevra(c *Cache, pkgID PkgID) utils.Nevra {
	pkgDetail := c.PackageDetails[pkgID]
	name := c.ID2Packagename[pkgDetail.NameID]
	evr := c.ID2Evr[pkgDetail.EvrID]
	arch := c.ID2Arch[pkgDetail.ArchID]
	nevra := utils.Nevra{
		Name:    name,
		Epoch:   evr.Epoch,
		Version: evr.Version,
		Release: evr.Release,
		Arch:    arch,
	}
	return nevra
}

func optimisticUpdates(c *Cache, nevraIDs *NevraIDs, nevra *utils.Nevra) []PkgID {
	updatePkgIDs := c.Updates[nevraIDs.NameID]
	updateIDx := 0
	for i := len(updatePkgIDs) - 1; i > 0; i-- {
		// go from the end of list because we expect most system is up2date
		// therefore we will test just a few pkgs at the end
		updatePkg := c.PackageDetails[updatePkgIDs[i]]
		updateEvr := c.ID2Evr[updatePkg.EvrID]
		// create NEVRA type to compare rpm version
		updateNevra := utils.Nevra{
			Name:    nevra.Name,
			Epoch:   updateEvr.Epoch,
			Version: updateEvr.Version,
			Release: updateEvr.Release,
			Arch:    nevra.Arch,
		}
		if updateNevra.EVRACmp(nevra) <= 0 {
			updateIDx = i
			break
		}
	}
	filteredUpdates := updatePkgIDs[updateIDx+1:]
	return filteredUpdates
}

func nevraUpdates(c *Cache, n *NevraIDs) ([]PkgID, map[string]bool) {
	currentNevraPkgID := nevraPkgID(c, n)
	// Package with given NEVRA not found in cache/DB
	if currentNevraPkgID == 0 {
		return nil, nil
	}

	// No updates found for given NEVRA
	lastVersionPkgID := c.Updates[n.NameID][len(c.Updates[n.NameID])-1]
	if lastVersionPkgID == currentNevraPkgID {
		return nil, nil
	}

	// Get candidate package IDs
	updatePkgIDs := c.Updates[n.NameID][n.EvrIDs[len(n.EvrIDs)-1]+1:]

	// Get associated product IDs
	validReleasevers := pkgReleasevers(c, currentNevraPkgID)
	return updatePkgIDs, validReleasevers
}

func pkgReleasevers(c *Cache, pkgID PkgID) map[string]bool {
	repoIDs := c.PkgID2RepoIDs[pkgID]
	releasevers := make(map[string]bool)
	for _, rid := range repoIDs {
		relVer := c.RepoDetails[rid].Releasever
		releasevers[relVer] = true
	}
	return releasevers
}

func nevraPkgID(c *Cache, n *NevraIDs) PkgID {
	var nPkgID PkgID
	if n == nil {
		return nPkgID
	}
	for _, eid := range n.EvrIDs {
		pkgID := c.Updates[n.NameID][eid]
		nevraArchID := c.PackageDetails[pkgID].ArchID
		if nevraArchID == n.ArchID {
			nPkgID = pkgID
			break
		}
	}
	return nPkgID
}

func extractNevraIDs(c *Cache, nevra *utils.Nevra) NevraIDs {
	if nevra == nil {
		return NevraIDs{}
	}
	nameID := c.Packagename2ID[nevra.Name]
	evr := utils.Evr{
		Epoch:   nevra.Epoch,
		Version: nevra.Version,
		Release: nevra.Release,
	}
	evrID := c.Evr2ID[evr]
	archID := c.Arch2ID[nevra.Arch]
	currentEvrIndexes := c.UpdatesIndex[nameID][evrID]
	return NevraIDs{
		NameID: nameID,
		EvrIDs: currentEvrIndexes,
		ArchID: archID,
	}
}

// Filter packages with latest NEVRA
func filterPkgList(pkgs []string, latestOnly bool) []string {
	if !latestOnly {
		return pkgs
	}

	latestPkgs := make(map[NameArch]NevraString, len(pkgs))
	filtered := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		nevra, err := utils.ParseNevra(pkg)
		if err != nil {
			utils.Log("nevra", pkg).Warn("Cannot parse")
			continue
		}
		nameArch := NameArch{Name: nevra.Name, Arch: nevra.Arch}
		if latestPkg, ok := latestPkgs[nameArch]; ok {
			if nevra.EVRCmp(&latestPkg.Nevra) < 1 {
				// nevra <= latestPkg
				continue
			}
		}
		latestPkgs[nameArch] = NevraString{nevra, pkg}
	}
	for _, v := range latestPkgs {
		filtered = append(filtered, v.Pkg)
	}
	return filtered
}

func getRepoIDs(c *Cache, u *Updates) map[RepoID]bool {
	res := make(map[RepoID]bool, len(u.RepoList))
	if len(u.RepoList) == 0 && len(u.RepoPaths) == 0 {
		for _, r := range c.RepoIDs {
			if passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				res[r] = true
			}
		}
	}
	for _, label := range u.RepoList {
		repoIDsCache := c.RepoLabel2IDs[label]
		for _, r := range repoIDsCache {
			if !res[r] && passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				res[r] = true
			}
		}
	}
	for _, path := range u.RepoPaths {
		path = strings.TrimSuffix(path, "/")
		repoIDsCache := c.RepoPath2IDs[path]
		for _, r := range repoIDsCache {
			if !res[r] && passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				res[r] = true
			}
		}
	}
	return res
}

func passReleasever(c *Cache, releasever *string, repoID RepoID) bool {
	detail, ok := c.RepoDetails[repoID]
	if !ok {
		return false
	}
	if releasever == nil {
		return true
	}
	return (detail.Releasever == "" && strings.Contains(detail.URL, *releasever)) || detail.Releasever == *releasever
}

func passBasearch(c *Cache, basearch *string, repoID RepoID) bool {
	detail, ok := c.RepoDetails[repoID]
	if !ok {
		return false
	}
	if basearch == nil {
		return true
	}
	return (detail.Basearch == "" && strings.Contains(detail.URL, *basearch)) || detail.Basearch == *basearch
}

func getModules(c *Cache, modules []ModuleStream) map[int]bool {
	moduleIDs := make(map[int]bool, len(modules))
	for _, m := range modules {
		if mIDs, ok := c.Module2IDs[m]; ok {
			for _, id := range mIDs {
				moduleIDs[id] = true
			}
		}
	}
	// filter out streams without satisfied requires
	filteredIDs := make(map[int]bool, len(moduleIDs))
	for m := range moduleIDs {
		requires := c.ModuleRequires[m]
		issubset := true
		for _, r := range requires {
			if !moduleIDs[r] {
				issubset = false
			}
		}
		if issubset {
			filteredIDs[m] = true
		}
	}
	return filteredIDs
}

func cveMapKeys(cves map[string]VulnerabilityDetail) []Vulnerability {
	keys := make([]Vulnerability, 0, len(cves))
	for k := range cves {
		keys = append(keys, Vulnerability(k))
	}
	return keys
}

func cveMapValues(cves map[string]VulnerabilityDetail) []VulnerabilityDetail {
	vals := make([]VulnerabilityDetail, 0, len(cves))
	for _, v := range cves {
		vals = append(vals, v)
	}
	return vals
}
