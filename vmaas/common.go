package vmaas

import (
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const SecurityErrataType = "security"

var ErrProcessingInput = errors.New("processing input")

type ProcessedRequest struct {
	Updates         *Updates
	Packages        map[string]utils.Nevra
	OriginalRequest *Request
}

func (r *ProcessedRequest) evaluateRepositories(c *Cache, cfg *Config) *Updates {
	if len(r.Packages) == 0 {
		return r.Updates
	}

	// Get list of valid repository IDs based on input parameters
	repoIDs := getRepoIDs(c, r.Updates)

	moduleIDs := getModules(c, r.Updates.ModuleList)

	updateList := processUpdates(c, cfg, r.Updates.UpdateList, r.Packages, repoIDs, moduleIDs, r.OriginalRequest)
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

	pkgsToProcess, updateList, err := processInputPackages(c, r)
	if err != nil {
		return nil, errors.Wrap(err, "processing input packages")
	}
	modules, err := processModules(r.Modules)
	if err != nil {
		return nil, errors.Wrap(err, "processing modules from request")
	}
	updates := Updates{
		UpdateList: updateList,
		LastChange: lastChanged,
		Basearch:   r.Basearch,
		Releasever: r.Releasever,
		RepoList:   r.Repos,
		RepoPaths:  r.RepoPaths,
		ModuleList: modules,
	}
	processed := ProcessedRequest{Updates: &updates, Packages: pkgsToProcess, OriginalRequest: r}
	return &processed, nil
}

// Convert input []ModuleStreamPtrs to []ModuleStream
func processModules(modules []ModuleStreamPtrs) ([]ModuleStream, error) {
	res := make([]ModuleStream, 0, len(modules))
	for _, m := range modules {
		if m.Module == nil || m.Stream == nil {
			return nil, errors.Wrap(ErrProcessingInput, "`module_name` and `module_stream` can't be `nil`")
		}
		res = append(res, ModuleStream{*m.Module, *m.Stream})
	}
	return res, nil
}

// Parse input NEVRAs and filter out unknown (or without updates) package names
func processInputPackages(c *Cache, request *Request) (map[string]utils.Nevra, UpdateList, error) {
	if request == nil {
		return map[string]utils.Nevra{}, UpdateList{}, nil
	}
	pkgsToProcess := filterPkgList(request.Packages, request.LatestOnly)
	filteredPkgsToProcess := make(map[string]utils.Nevra)
	updateList := make(UpdateList)
	for _, pkg := range pkgsToProcess {
		updateList[pkg] = UpdateDetail{}
		nevra, err := utils.ParseNevra(pkg, request.EpochRequired)
		if err != nil {
			utils.LogWarn("nevra", pkg, "Cannot parse")
			continue
		}
		if nevra.Epoch == -1 {
			return nil, nil, errors.Wrapf(ErrProcessingInput, "missing required epoch in %s", pkg)
		}
		if pkgID, ok := c.Packagename2ID[nevra.Name]; ok {
			if _, ok := c.UpdatesIndex[pkgID]; ok {
				filteredPkgsToProcess[pkg] = nevra
			}
		}
	}
	return filteredPkgsToProcess, updateList, nil
}

func processUpdates(c *Cache, cfg *Config, updateList UpdateList, packages map[string]utils.Nevra,
	repoIDs map[RepoID]bool, moduleIDs map[int]bool, r *Request,
) UpdateList {
	for pkg, nevra := range packages {
		updateList[pkg] = processPackagesUpdates(c, cfg, nevra, repoIDs, moduleIDs, r)
	}
	return updateList
}

func processPackagesUpdates(c *Cache, cfg *Config, nevra utils.Nevra, repoIDs map[RepoID]bool,
	moduleIDs map[int]bool, r *Request,
) UpdateDetail {
	updateDetail := UpdateDetail{}
	nevraIDs := extractNevraIDs(c, &nevra)

	var updatePkgIDs []PkgID
	var filteredRepos []RepoID
	pkgFromModule := false
	if len(nevraIDs.EvrIDs) > 0 {
		// nevraUpdates
		updatePkgIDs, pkgFromModule = nevraUpdates(c, &nevraIDs, moduleIDs, repoIDs)
	}
	if len(updatePkgIDs) == 0 {
		// no nevra updates, try optimistic updates
		updatePkgIDs = optimisticUpdates(c, &nevraIDs, &nevra)
	}
	if len(updatePkgIDs) == 0 {
		// still no updates, return empty UpdateDetail
		return updateDetail
	}

	// get repositories for update packages
	filteredRepos = repositoriesByPkgs(c, cfg, updatePkgIDs, repoIDs)

	// get pkgUpdates concurrently
	updates := make(chan Update)
	wg := sync.WaitGroup{}
	maxGoroutines := make(chan struct{}, cfg.MaxGoroutines)
	for _, u := range updatePkgIDs {
		wg.Add(1)
		go func(u PkgID) {
			defer wg.Done()
			maxGoroutines <- struct{}{}
			pkgUpdates(c, u, nevraIDs.ArchID, r.SecurityOnly, moduleIDs,
				filteredRepos, r.ThirdParty, pkgFromModule, updates)
			<-maxGoroutines
		}(u)
	}
	go func() {
		wg.Wait()
		close(updates)
	}()
	for u := range updates {
		updateDetail.AvailableUpdates = append(updateDetail.AvailableUpdates, u)
	}
	return updateDetail
}

func pkgUpdates(c *Cache, pkgID PkgID, archID ArchID, securityOnly bool, modules map[int]bool,
	repoIDs []RepoID, thirdparty bool, currentPkgFromModule bool, updates chan Update,
) {
	if archID == 0 {
		return
	}

	// Filter out packages without errata
	errataIDs, ok := c.PkgID2ErrataIDs[pkgID]
	if !ok {
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

	nevra := buildNevra(c, pkgID)
	for _, eid := range errataIDs {
		pkgErrataUpdates(c, pkgID, eid, modules, repoIDs,
			nevra, securityOnly, thirdparty, currentPkgFromModule, updates)
	}
}

func pkgErrataUpdates(c *Cache, pkgID PkgID, erratumID ErratumID, modules map[int]bool,
	repoIDs []RepoID, nevra utils.Nevra, securityOnly, thirdparty bool, currentPkgFromModule bool,
	updates chan Update,
) {
	erratumName := c.ErratumID2Name[erratumID]
	erratumDetail := c.ErratumDetails[erratumName]

	// Filter out non-security updates
	if filterNonSecurity(erratumDetail, securityOnly) {
		return
	}

	// If we don't want third party content, and current advisory is third party, skip it
	if !thirdparty && erratumDetail.ThirdParty {
		return
	}

	pkgErrata := PkgErratum{pkgID, erratumID}
	errataModules := c.PkgErratum2Module[pkgErrata]
	// return nil if errataModules and modules intersection is empty
	intersects := false
	for _, em := range errataModules {
		if _, ok := modules[em]; ok {
			// at least 1 item in intersection
			intersects = true
			break
		}
	}
	if (len(errataModules) > 0 || currentPkgFromModule) && !intersects {
		return
	}

	repos := filterErrataRepos(c, erratumID, repoIDs)
	for _, r := range repos {
		details := c.RepoDetails[r]
		updates <- Update{
			Package:     nevra.String(),
			PackageName: nevra.Name,
			EVRA:        nevra.EVRAStringE(true),
			Erratum:     erratumName,
			Repository:  details.Label,
			Basearch:    details.Basearch,
			Releasever:  details.Releasever,
		}
	}
}

// Decide whether the errata should be filtered base on 'security only' rule
func filterNonSecurity(errataDetail ErratumDetail, securityOnly bool) bool {
	if !securityOnly {
		return false
	}
	isSecurity := errataDetail.Type == SecurityErrataType || len(errataDetail.CVEs) > 0
	return !isSecurity
}

func repositoriesByPkgs(c *Cache, cfg *Config, pkgIDs []PkgID, repoIDs map[RepoID]bool) []RepoID {
	res := []RepoID{}
	seen := map[RepoID]bool{}
	repos := make(chan RepoID)
	wg := sync.WaitGroup{}
	maxGoroutines := make(chan struct{}, cfg.MaxGoroutines)
	for _, p := range pkgIDs {
		wg.Add(1)
		go func(p PkgID) {
			defer wg.Done()
			maxGoroutines <- struct{}{}
			filterPkgRepos(c, p, repoIDs, repos)
			<-maxGoroutines
		}(p)
	}
	go func() {
		wg.Wait()
		close(repos)
	}()
	for r := range repos {
		if !seen[r] {
			seen[r] = true
			res = append(res, r)
		}
	}
	return res
}

func filterPkgRepos(c *Cache, pkgID PkgID, repoIDs map[RepoID]bool, res chan RepoID) {
	pkgRepos := c.PkgID2RepoIDs[pkgID]
	for _, r := range pkgRepos {
		if repoIDs[r] {
			res <- r
		}
	}
}

func filterErrataRepos(c *Cache, erratumID ErratumID, pkgRepos []RepoID) []RepoID {
	erratumRepos := c.ErratumID2RepoIDs[erratumID]
	result := []RepoID{}
	for _, rid := range pkgRepos {
		if erratumRepos[rid] {
			result = append(result, rid)
		}
	}

	return result
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

func nevraUpdates(c *Cache, n *NevraIDs, modules map[int]bool, repoIDs map[RepoID]bool) ([]PkgID, bool) {
	currentNevraPkgID := nevraPkgID(c, n)
	// Package with given NEVRA not found in cache/DB
	if currentNevraPkgID == 0 {
		return nil, false
	}

	currentFromModule := isPkgFromEnabledModule(c, currentNevraPkgID, modules, repoIDs)
	lastVersionPkgID := c.Updates[n.NameID][len(c.Updates[n.NameID])-1]
	// No updates found for given NEVRA
	if lastVersionPkgID == currentNevraPkgID {
		return nil, currentFromModule
	}

	// Get candidate package IDs
	updatePkgIDs := c.Updates[n.NameID][n.EvrIDs[len(n.EvrIDs)-1]+1:]
	return updatePkgIDs, currentFromModule
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

func isPkgFromEnabledModule(c *Cache, pkgID PkgID, modules map[int]bool, repoIDs map[RepoID]bool) bool {
	errata := c.PkgID2ErrataIDs[pkgID]
	for _, eid := range errata {
		erratumRepos := c.ErratumID2RepoIDs[eid]
		validRepo := false
		for r := range repoIDs {
			if erratumRepos[r] {
				validRepo = true
				break
			}
		}
		if !validRepo {
			continue
		}
		pkgErrata := PkgErratum{pkgID, eid}
		errataModules := c.PkgErratum2Module[pkgErrata]
		for _, em := range errataModules {
			if modules[em] {
				return true
			}
		}
	}
	return false
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
		nevra, err := utils.ParseNevra(pkg, false)
		if err != nil {
			utils.LogWarn("nevra", pkg, "Cannot parse")
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
	res := map[RepoID]bool{}
	if u.RepoList == nil && len(u.RepoPaths) == 0 {
		for _, r := range c.RepoIDs {
			if passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				res[r] = true
			}
		}
	}
	if u.RepoList != nil {
		res = make(map[RepoID]bool, len(*u.RepoList))
		for _, label := range *u.RepoList {
			repoIDsCache := c.RepoLabel2IDs[label]
			for _, r := range repoIDsCache {
				if !res[r] && passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
					res[r] = true
				}
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
