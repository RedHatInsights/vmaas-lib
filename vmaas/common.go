package vmaas

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const (
	SecurityErrataType = "security"
	CriticalCveImpact  = "Critical"
	ImportantCveImpact = "Important"
	ModerateCveImpact  = "Moderate"
	LowCveImpact       = "Low"
)

var (
	ErrProcessingInput = errors.New("processing input")
	ReleaseverRegex    = regexp.MustCompile(`^\d+\.\d+$`)
)

type repoIDMaps struct {
	currentReleasever map[RepoID]bool
	newerReleasever   map[RepoID]bool
}

type repoIDSlices struct {
	currentReleasever []RepoID
	newerReleasever   []RepoID
}

type repoIDReleasevers struct {
	currentReleasever RepoID
	newerReleasever   RepoID
}

type ProcessedRequest struct {
	Updates             *Updates
	Packages            []NevraString
	Cpes                []CpeID
	NewerReleaseverCpes []CpeID
	ContentSetsCpes     []CpeID
	ContentSets         []ContentSetID
	OriginalRequest     *Request
}

func (r *ProcessedRequest) evaluateRepositories(c *Cache, opts *options) *Updates {
	if len(r.Packages) == 0 {
		return r.Updates
	}

	// Get list of valid repository IDs based on input parameters
	repoIDs := getRepoIDs(c, r.Updates, opts)

	moduleIDs := getModules(c, r.Updates.ModuleList)

	updateList := processUpdates(c, opts, r.Updates.UpdateList, r.Packages, repoIDs, moduleIDs, r.OriginalRequest)
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
func processInputPackages(c *Cache, request *Request) ([]NevraString, UpdateList, error) {
	if request == nil {
		return make([]NevraString, 0), UpdateList{}, nil
	}
	pkgsToProcess := filterPkgList(request.Packages, request.LatestOnly)
	sort.Strings(pkgsToProcess)
	filteredPkgsToProcess := make([]NevraString, 0, len(pkgsToProcess))
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
				filteredPkgsToProcess = append(filteredPkgsToProcess, NevraString{nevra, pkg})
			}
		}
	}
	return filteredPkgsToProcess, updateList, nil
}

func processUpdates(c *Cache, opts *options, updateList UpdateList, packages []NevraString,
	repoIDs repoIDMaps, moduleIDs map[int]bool, r *Request,
) UpdateList {
	type pkgUpdates struct {
		UpdateDetail
		pkg string
	}

	wg := sync.WaitGroup{}
	maxGoroutines := make(chan struct{}, opts.maxGoroutines)
	updates := make(chan pkgUpdates)
	for _, nevra := range packages {
		wg.Add(1)
		go func(nevra NevraString) {
			defer func() {
				<-maxGoroutines
				wg.Done()
			}()
			maxGoroutines <- struct{}{}
			detail := processPackagesUpdates(c, opts, nevra.Nevra, repoIDs, moduleIDs, r)
			updates <- pkgUpdates{UpdateDetail: detail, pkg: nevra.Pkg}
		}(nevra)
	}
	go func() {
		wg.Wait()
		close(updates)
	}()
	for u := range updates {
		updateList[u.pkg] = u.UpdateDetail
	}
	return updateList
}

func processPackagesUpdates(c *Cache, opts *options, nevra utils.Nevra, repoIDs repoIDMaps,
	moduleIDs map[int]bool, r *Request,
) UpdateDetail {
	updateDetail := UpdateDetail{}
	nevraIDs := extractNevraIDs(c, &nevra)

	var updatePkgIDs []PkgID
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
	filteredRepos := repositoriesByPkgs(c, opts, updatePkgIDs, repoIDs)

	for _, u := range updatePkgIDs {
		pkgUpdates(c, u, nevraIDs.ArchID, r.SecurityOnly, moduleIDs,
			filteredRepos, r.ThirdParty, pkgFromModule, &updateDetail)
	}

	sort.Slice(updateDetail.AvailableUpdates, func(i, j int) bool {
		updateI := updateDetail.AvailableUpdates[i]
		updateJ := updateDetail.AvailableUpdates[j]
		cmp := updateI.nevra.EVRACmp(&updateJ.nevra)
		if cmp == 0 {
			cmp = strings.Compare(updateI.Erratum, updateJ.Erratum)
		}
		if cmp == 0 {
			cmp = strings.Compare(updateI.Repository, updateJ.Repository)
		}
		if cmp == 0 {
			cmp = strings.Compare(updateI.Basearch, updateJ.Basearch)
		}
		if cmp == 0 {
			cmp = strings.Compare(updateI.Releasever, updateJ.Releasever)
		}
		return cmp < 0
	})
	return updateDetail
}

func pkgUpdates(c *Cache, pkgID PkgID, archID ArchID, securityOnly bool, modules map[int]bool,
	repoIDs repoIDSlices, thirdparty bool, currentPkgFromModule bool, updateDetail *UpdateDetail,
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
			nevra, securityOnly, thirdparty, currentPkgFromModule, updateDetail)
	}
}

func pkgErrataUpdates(c *Cache, pkgID PkgID, erratumID ErratumID, modules map[int]bool,
	repoIDs repoIDSlices, nevra utils.Nevra, securityOnly, thirdparty bool, currentPkgFromModule bool,
	updateDetail *UpdateDetail,
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
	for _, r := range repos.currentReleasever {
		buildUpdateDetail(c, r, pkgID, nevra, erratumName, false, updateDetail)
	}
	for _, r := range repos.newerReleasever {
		buildUpdateDetail(c, r, pkgID, nevra, erratumName, true, updateDetail)
	}
}

func buildUpdateDetail(c *Cache, repoID RepoID, pkgID PkgID, nevra utils.Nevra,
	erratumName string, manuallyFixable bool, updateDetail *UpdateDetail,
) {
	// filter out update package if it does not exist in the enabled repo
	pkgInRepo := false
	pkgRepos := c.PkgID2RepoIDs[pkgID]
	for _, pkgRepo := range pkgRepos {
		if repoID == pkgRepo {
			pkgInRepo = true
			break
		}
	}
	if !pkgInRepo {
		return
	}
	details := c.RepoDetails[repoID]
	updateDetail.AvailableUpdates = append(updateDetail.AvailableUpdates, Update{
		Package:         nevra.String(),
		PackageName:     nevra.Name,
		EVRA:            nevra.EVRAStringE(true),
		Erratum:         erratumName,
		Repository:      details.Label,
		Basearch:        details.Basearch,
		Releasever:      details.Releasever,
		nevra:           nevra,
		manuallyFixable: manuallyFixable,
	})
}

// Decide whether the errata should be filtered base on 'security only' rule
func filterNonSecurity(errataDetail ErratumDetail, securityOnly bool) bool {
	if !securityOnly {
		return false
	}
	isSecurity := errataDetail.Type == SecurityErrataType || len(errataDetail.CVEs) > 0
	return !isSecurity
}

func repositoriesByPkgs(c *Cache, opts *options, pkgIDs []PkgID, repoIDs repoIDMaps) repoIDSlices {
	res := repoIDSlices{make([]RepoID, 0), make([]RepoID, 0)}
	seenCurrent := map[RepoID]bool{}
	seenNewer := map[RepoID]bool{}
	repos := make(chan repoIDReleasevers)
	wg := sync.WaitGroup{}
	maxGoroutines := make(chan struct{}, opts.maxGoroutines)
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
		if r.currentReleasever != 0 && !seenCurrent[r.currentReleasever] {
			seenCurrent[r.currentReleasever] = true
			res.currentReleasever = append(res.currentReleasever, r.currentReleasever)
		}
		if r.newerReleasever != 0 && !seenNewer[r.newerReleasever] {
			seenNewer[r.newerReleasever] = true
			res.newerReleasever = append(res.newerReleasever, r.newerReleasever)
		}
	}
	return res
}

func filterPkgRepos(c *Cache, pkgID PkgID, repoIDs repoIDMaps, repos chan repoIDReleasevers) {
	pkgRepos := c.PkgID2RepoIDs[pkgID]
	for _, r := range pkgRepos {
		repo := repoIDReleasevers{}
		if repoIDs.currentReleasever[r] {
			repo.currentReleasever = r
		}
		if repoIDs.newerReleasever[r] {
			repo.newerReleasever = r
		}
		if repo.currentReleasever != 0 || repo.newerReleasever != 0 {
			repos <- repo
		}
	}
}

func filterErrataRepos(c *Cache, erratumID ErratumID, pkgRepos repoIDSlices) repoIDSlices {
	erratumRepos := c.ErratumID2RepoIDs[erratumID]
	result := repoIDSlices{make([]RepoID, 0), make([]RepoID, 0)}
	for _, rid := range pkgRepos.currentReleasever {
		if erratumRepos[rid] {
			result.currentReleasever = append(result.currentReleasever, rid)
		}
	}
	for _, rid := range pkgRepos.newerReleasever {
		if erratumRepos[rid] {
			result.newerReleasever = append(result.newerReleasever, rid)
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

func nevraUpdates(c *Cache, n *NevraIDs, modules map[int]bool, repoIDs repoIDMaps) ([]PkgID, bool) {
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

func isPkgFromEnabledModule(c *Cache, pkgID PkgID, modules map[int]bool, repoIDs repoIDMaps) bool {
	errata := c.PkgID2ErrataIDs[pkgID]
	for _, eid := range errata {
		erratumRepos := c.ErratumID2RepoIDs[eid]
		validRepo := false
		for r := range repoIDs.currentReleasever {
			if erratumRepos[r] {
				validRepo = true
				break
			}
		}
		if !validRepo {
			for r := range repoIDs.newerReleasever {
				if erratumRepos[r] {
					validRepo = true
					break
				}
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

func getRepoIDs(c *Cache, u *Updates, opts *options) repoIDMaps { //nolint: gocognit
	current := map[RepoID]bool{}
	newer := map[RepoID]bool{}
	if u.RepoList == nil && len(u.RepoPaths) == 0 {
		for _, r := range c.RepoIDs {
			if passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				current[r] = true
			} else if passBasearch(c, u.Basearch, r) && isNewerReleasever(c, u.Releasever, r, opts) {
				newer[r] = true
			}
		}
	}
	if u.RepoList != nil {
		current = make(map[RepoID]bool, len(*u.RepoList))
		for _, label := range *u.RepoList {
			repoIDsCache := c.RepoLabel2IDs[label]
			for _, r := range repoIDsCache {
				if !current[r] && passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
					current[r] = true
				} else if !newer[r] && passBasearch(c, u.Basearch, r) && isNewerReleasever(c, u.Releasever, r, opts) {
					newer[r] = true
				}
			}
		}
	}
	for _, path := range u.RepoPaths {
		path = strings.TrimSuffix(path, "/")
		repoIDsCache := c.RepoPath2IDs[path]
		for _, r := range repoIDsCache {
			if !current[r] && passReleasever(c, u.Releasever, r) && passBasearch(c, u.Basearch, r) {
				current[r] = true
			} else if !newer[r] && passBasearch(c, u.Basearch, r) && isNewerReleasever(c, u.Releasever, r, opts) {
				newer[r] = true
			}
		}
	}
	return repoIDMaps{current, newer}
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

func isNewerReleasever(c *Cache, requestReleasever *string, repoID RepoID, opts *options) bool {
	if !opts.newerReleaseverRepos {
		return false // option is disabled
	}
	if requestReleasever == nil {
		return false
	}
	if !ReleaseverRegex.MatchString(*requestReleasever) {
		return false
	}

	detail, ok := c.RepoDetails[repoID]
	if !ok {
		return false
	}
	candidateReleasever := detail.Releasever
	if !ReleaseverRegex.MatchString(candidateReleasever) {
		return false
	}

	if candidateReleasever != *requestReleasever {
		parsedRequestReleasever, err := version.NewVersion(*requestReleasever)
		if err != nil {
			return false
		}
		parsedCandidateReleasever, err := version.NewVersion(candidateReleasever)
		if err != nil {
			return false
		}
		// repository with higher releasever
		if parsedCandidateReleasever.GreaterThan(parsedRequestReleasever) {
			return true
		}
	}
	return false
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

// `update` is applicable to `input`
func isApplicable(c *Cache, update, input *utils.Nevra, opts *options) bool {
	if anyReleaseExcluded(opts, update.Release, input.Release) {
		return false
	}
	return compatNameArch(c, update, input) && update.EVRCmp(input) > 0
}

// `x` is applicable to `y` or they are equal
func isApplicableOrEqual(c *Cache, x, y *utils.Nevra, opts *options) bool {
	if anyReleaseExcluded(opts, x.Release, y.Release) {
		return false
	}
	return compatNameArch(c, x, y) && x.EVRCmp(y) >= 0
}

func compatNameArch(c *Cache, update, input *utils.Nevra) bool {
	if update.Name != input.Name {
		return false
	}
	if update.Arch != input.Arch {
		// check if the u arch is compatible
		uArchID := c.Arch2ID[update.Arch]
		iArchID := c.Arch2ID[input.Arch]
		compatArchs := c.ArchCompat[iArchID]
		if !compatArchs[uArchID] {
			return false
		}
	}
	return true
}

// returns true if at least one of `releases` is excluded
func anyReleaseExcluded(opts *options, releases ...string) bool {
	for _, r := range releases {
		splittedRelease := strings.Split(r, ".")
		if opts.excludedReleases[splittedRelease[len(splittedRelease)-1]] {
			return true
		}
	}
	return false
}

func pkgID2Nevra(c *Cache, pkgID PkgID) utils.Nevra {
	pkg := c.PackageDetails[pkgID]
	name := c.ID2Packagename[pkg.NameID]
	evr := c.ID2Evr[pkg.EvrID]
	arch := c.ID2Arch[pkg.ArchID]
	nevra := utils.Nevra{
		Name:    name,
		Epoch:   evr.Epoch,
		Version: evr.Version,
		Release: evr.Release,
		Arch:    arch,
	}
	return nevra
}
