package vmaas

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const (
	OvalOperationEvrEquals   = 1
	OvalOperationEvrLessThan = 2

	OvalCheckExistenceAtLeastOne = 1
	OvalCheckExistenceNone       = 2

	OvalDefinitionTypePatch         = 1
	OvalDefinitionTypeVulnerability = 2

	OvalCriteriaOperatorAnd = 1
	OvalCriteriaOperatorOr  = 2
)

type VulnerabilitiesCvesDetails struct {
	Cves          map[string]VulnerabilityDetail
	ManualCves    map[string]VulnerabilityDetail
	UnpatchedCves map[string]VulnerabilityDetail
	LastChange    *time.Time
}

type ProcessedDefinitions struct {
	Patch         []*ProcessedDefinition
	Vulnerability []*ProcessedDefinition
}

type ProcessedDefinition struct {
	DefinitionID     DefinitionID
	DefinitionTypeID int
	CriteriaID       CriteriaID
	Packages         []Package
	Cpe              CpeLabel
}

type ProductsPackage struct {
	ProductsFixed   []CSAFProduct
	ProductsUnfixed []CSAFProduct
	Package         Package
}

type Package struct {
	utils.Nevra
	String string
	NameID NameID
}

type packageErratum struct {
	pkg     string
	erratum string
}

func (r *Request) vulnerabilities(c *Cache, opts *options) (*Vulnerabilities, error) {
	cves, err := evaluate(c, opts, r)
	if err != nil {
		return nil, err
	}
	vuln := Vulnerabilities{
		CVEs:                cveMapKeys(cves.Cves),
		ManuallyFixableCVEs: cveMapKeys(cves.ManualCves),
		UnpatchedCVEs:       cveMapKeys(cves.UnpatchedCves),
		LastChange:          *cves.LastChange,
	}
	return &vuln, nil
}

func (r *Request) vulnerabilitiesExtended(c *Cache, opts *options) (*VulnerabilitiesExtended, error) {
	cves, err := evaluate(c, opts, r)
	if err != nil {
		return nil, err
	}
	vuln := VulnerabilitiesExtended{
		CVEs:                cveMapValues(cves.Cves),
		ManuallyFixableCVEs: cveMapValues(cves.ManualCves),
		UnpatchedCVEs:       cveMapValues(cves.UnpatchedCves),
		LastChange:          *cves.LastChange,
	}
	return &vuln, nil
}

//nolint:funlen,gocognit
func evaluate(c *Cache, opts *options, request *Request) (*VulnerabilitiesCvesDetails, error) {
	cves := VulnerabilitiesCvesDetails{
		Cves:          make(map[string]VulnerabilityDetail),
		ManualCves:    make(map[string]VulnerabilityDetail),
		UnpatchedCves: make(map[string]VulnerabilityDetail),
	}

	// process request
	processed, err := request.processRequest(c)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't process request")
	}
	cves.LastChange = &processed.Updates.LastChange

	// get CPEs and ContentSets from repos
	processed.processRepos(c)
	definitions, err := processed.processDefinitions(c, opts)
	if err != nil {
		return &cves, errors.Wrap(err, "couldn't evaluate OVAL")
	}
	products := processed.processProducts(c, opts)

	modules := make(map[string]string)
	for _, m := range processed.Updates.ModuleList {
		modules[m.Module] = m.Stream
	}

	// 1. evaluate Unpatched CVEs
	if definitions != nil {
		for _, definition := range definitions.Vulnerability {
			cvesOval := c.OvaldefinitionID2Cves[definition.DefinitionID]
			definition.evaluate(c, modules, cvesOval, &cves, cves.UnpatchedCves)
		}
	}
	evaluateUnpatchedCves(c, products, &cves)

	// 2. evaluate CVEs from Repositories
	// if CVE is already in Unpatched list -> skip it
	updates := processed.evaluateRepositories(c, opts)
	seenPkgErratum := map[packageErratum]bool{}
	for pkg, upDetail := range updates.UpdateList {
		for _, update := range upDetail.AvailableUpdates {
			pe := packageErratum{pkg, update.Erratum}
			if seenPkgErratum[pe] {
				continue
			}
			seenPkgErratum[pe] = true
			for _, cve := range c.ErratumDetails[update.Erratum].CVEs {
				if _, inUnpatchedCves := cves.UnpatchedCves[cve]; inUnpatchedCves {
					continue
				}
				updateCves(cves.Cves, cve, Package{String: pkg}, []string{update.Erratum}, "", nil)
			}
		}
	}

	// 3. evaluate Manually Fixable CVEs
	// if CVE is already in Unpatched or CVE list -> skip it
	if definitions != nil {
		for _, definition := range definitions.Patch {
			cvesOval := c.OvaldefinitionID2Cves[definition.DefinitionID]
			// Skip if all CVEs from definition were already found somewhere
			allCvesFound := true
			for _, cve := range cvesOval {
				_, inCves := cves.Cves[cve]
				_, inManualCves := cves.ManualCves[cve]
				_, inUnpatchedCves := cves.UnpatchedCves[cve]
				if !(inCves || inManualCves || inUnpatchedCves) {
					allCvesFound = false
				}
			}
			if allCvesFound {
				continue
			}
			definition.evaluate(c, modules, cvesOval, &cves, cves.ManualCves)
		}
	}
	evaluateManualCves(c, products, &cves)
	return &cves, nil
}

func evaluateUnpatchedCves(c *Cache, products []ProductsPackage, cves *VulnerabilitiesCvesDetails) {
	for _, pp := range products {
		for _, product := range pp.ProductsUnfixed {
			module := product.ModuleStream
			cn := CpeIDNameID{CpeID: product.CpeID, NameID: product.PackageNameID}
			csafCves := c.CSAFCVEs[cn][product]
			for _, cveID := range csafCves.Unfixed {
				cve := c.CveNames[int(cveID)]
				cpe := c.CpeID2Label[product.CpeID]
				if module.Module != "" {
					updateCves(cves.UnpatchedCves, cve, pp.Package, nil, cpe, &module)
				} else {
					updateCves(cves.UnpatchedCves, cve, pp.Package, nil, cpe, nil)
				}
			}
		}
	}
}

func evaluateManualCves(c *Cache, products []ProductsPackage, cves *VulnerabilitiesCvesDetails) {
	for _, pp := range products {
		pp := pp // make copy because &pp is used
		for _, product := range pp.ProductsFixed {
			updateNevra := pkgID2Nevra(c, product.PackageID)
			if !isApplicable(c, &updateNevra, &pp.Package.Nevra) {
				continue
			}

			module := product.ModuleStream
			cn := CpeIDNameID{CpeID: product.CpeID, NameID: pp.Package.NameID}
			csafCves := c.CSAFCVEs[cn][product]
			for _, cveID := range csafCves.Fixed {
				cve := c.CveNames[int(cveID)]
				_, inCves := cves.Cves[cve]
				_, inUnpatchedCves := cves.UnpatchedCves[cve]
				if !(inCves || inUnpatchedCves) {
					// show only CVE hit which is not in Cves and UnpatchedCves
					cpe := c.CpeID2Label[product.CpeID]
					erratum := c.CSAFCVEProduct2Errata[CSAFCVEProduct{
						CVEID:         cveID,
						CSAFProductID: c.CSAFProduct2ID[product],
					}]
					if module.Module != "" {
						updateCves(cves.ManualCves, cve, pp.Package, []string{erratum}, cpe, &module)
					} else {
						updateCves(cves.ManualCves, cve, pp.Package, []string{erratum}, cpe, nil)
					}
				}
			}
		}
	}
}

func (d *ProcessedDefinition) evaluate(
	c *Cache, modules map[string]string, cvesOval []string, cves *VulnerabilitiesCvesDetails,
	dst map[string]VulnerabilityDetail,
) {
	for _, p := range d.Packages {
		resultContext := map[string]interface{}{}
		if evaluateCriteria(c, d.CriteriaID, p.NameID, p.Nevra, modules, resultContext) {
			for _, cve := range cvesOval {
				_, inCves := cves.Cves[cve]
				_, inUnpatchedCves := cves.UnpatchedCves[cve]
				// Fixable and Unpatched CVEs take precedence over Manually fixable
				if d.DefinitionTypeID == OvalDefinitionTypePatch && (inCves || inUnpatchedCves) {
					continue
				}
				errataNames := make([]string, 0)
				for _, erratumID := range c.OvalDefinitionID2ErrataIDs[d.DefinitionID] {
					errataNames = append(errataNames, c.ErratumID2Name[erratumID])
				}
				if data, has := resultContext["module"]; has {
					module := data.(ModuleStream)
					updateCves(dst, cve, p, errataNames, d.Cpe, &module)
				} else {
					updateCves(dst, cve, p, errataNames, d.Cpe, nil)
				}
			}
		}
	}
}

// process repos into CPEs and ContentSets needed for vulnerability evaluation
func (r *ProcessedRequest) processRepos(c *Cache) {
	repoIDs, newerReleaseverRepoIDs, contentSetIDs := repos2IDs(c, r.OriginalRequest)
	cpes := repos2cpes(c, repoIDs)
	newerReleaseverCpes := repos2cpes(c, newerReleaseverRepoIDs)
	r.Cpes = cpes
	r.NewerReleaseverCpes = newerReleaseverCpes
	r.ContentSets = contentSetIDs
}

func (r *ProcessedRequest) processProducts(c *Cache, opts *options) []ProductsPackage {
	productsPackages := make([]ProductsPackage, 0)
	if r.OriginalRequest.UseCsaf {
		csCpes := make([]CpeID, 0)
		for _, csID := range r.ContentSets {
			if cpes, has := c.ContentSetID2CpeIDs[csID]; has {
				for cpeID, cpeLabel := range c.CpeID2Label {
					for _, cpe := range cpes {
						csCpe := c.CpeID2Label[cpe]
						if cpeMatch(cpeLabel, csCpe) {
							csCpes = append(csCpes, cpeID)
						}
					}
				}
			}
		}

		for _, pkg := range r.Packages {
			nameID := c.Packagename2ID[pkg.Nevra.Name]
			products := cpes2products(c, r.Cpes, nameID, r.Updates.ModuleList, pkg, opts)

			if (len(products.ProductsFixed) + len(products.ProductsUnfixed)) == 0 {
				// use CPEs from Content Sets if we haven't found any products
				products = cpes2products(c, csCpes, nameID, r.Updates.ModuleList, pkg, opts)
			}
			productsPackages = append(productsPackages, products)
		}
	}
	return productsPackages
}

//nolint:funlen
func (r *ProcessedRequest) processDefinitions(c *Cache, opts *options) (*ProcessedDefinitions, error) {
	if r.OriginalRequest.UseCsaf {
		return nil, nil
	}
	candidateDefinitions := repos2definitions(c, r)
	patchDefinitions := make(map[DefinitionID]*ProcessedDefinition)
	vulnerabilityDefinitions := make(map[DefinitionID]*ProcessedDefinition)
	definitions := ProcessedDefinitions{
		make([]*ProcessedDefinition, 0),
		make([]*ProcessedDefinition, 0),
	}

	for _, parsedNevra := range r.Packages {
		pkgNameID := c.Packagename2ID[parsedNevra.Nevra.Name]
		allDefinitionsIDs := c.PackagenameID2definitionIDs[pkgNameID]
		for _, defID := range allDefinitionsIDs {
			if cpe, ok := candidateDefinitions[defID]; ok {
				definition := c.OvaldefinitionDetail[defID]
				switch definition.DefinitionTypeID {
				case OvalDefinitionTypePatch:
					processedDefinition, ok := patchDefinitions[defID]
					if !ok {
						processedDefinition = &ProcessedDefinition{
							DefinitionID:     definition.ID,
							DefinitionTypeID: definition.DefinitionTypeID,
							CriteriaID:       definition.CriteriaID,
							// store CPE only for Vulnerability type, field omitted intentionally
						}
						patchDefinitions[defID] = processedDefinition
						definitions.Patch = append(definitions.Patch, processedDefinition)
					}
					processedDefinition.Packages = append(processedDefinition.Packages, Package{
						Nevra:  parsedNevra.Nevra,
						NameID: pkgNameID,
						String: parsedNevra.Pkg,
					})
				case OvalDefinitionTypeVulnerability:
					// Skip if unfixed CVE feature flag is disabled
					if !opts.evalUnfixed {
						continue
					}
					processedDefinition, ok := vulnerabilityDefinitions[defID]
					if !ok {
						processedDefinition = &ProcessedDefinition{
							DefinitionID:     definition.ID,
							DefinitionTypeID: definition.DefinitionTypeID,
							CriteriaID:       definition.CriteriaID,
							Cpe:              c.CpeID2Label[cpe],
						}
						vulnerabilityDefinitions[defID] = processedDefinition
						definitions.Vulnerability = append(definitions.Vulnerability, processedDefinition)
					}
					processedDefinition.Packages = append(processedDefinition.Packages, Package{
						Nevra:  parsedNevra.Nevra,
						NameID: pkgNameID,
						String: parsedNevra.Pkg,
					})
				default:
					return nil, fmt.Errorf("unsupported definition type: %d", definition.DefinitionTypeID)
				}
			}
		}
	}
	return &definitions, nil
}

//nolint:gocognit
func repos2IDs(c *Cache, r *Request) ([]RepoID, []RepoID, []ContentSetID) {
	if r.Repos == nil {
		return nil, nil, nil
	}
	sort.Strings(*r.Repos)

	repoIDs := make([]RepoID, 0)
	newerReleaseverRepoIDs := make([]RepoID, 0)
	contentSetIDs := make([]ContentSetID, 0)
	// Try to identify repos (CS+basearch+releasever) or at least CS
	for _, label := range *r.Repos {
		if r.Basearch != nil || r.Releasever != nil {
			for _, repoID := range c.RepoLabel2IDs[label] {
				if r.Basearch != nil && c.RepoDetails[repoID].Basearch != *r.Basearch {
					continue
				}
				candidateReleasever := c.RepoDetails[repoID].Releasever
				if r.Releasever != nil && candidateReleasever != *r.Releasever {
					parsedRequestReleasever, err := version.NewVersion(*r.Releasever)
					if err != nil {
						continue
					}
					parsedCandidateReleasever, err := version.NewVersion(candidateReleasever)
					if err != nil {
						continue
					}
					// Save repositories with higher releasever
					if parsedCandidateReleasever.GreaterThan(parsedRequestReleasever) {
						newerReleaseverRepoIDs = append(newerReleaseverRepoIDs, repoID)
					}
					continue
				}
				repoIDs = append(repoIDs, repoID)
			}
		}
		if csID, has := c.Label2ContentSetID[label]; has {
			contentSetIDs = append(contentSetIDs, csID)
		}
	}
	return repoIDs, newerReleaseverRepoIDs, contentSetIDs
}

func cpeMatch(l, r CpeLabel) bool {
	lParsed, err := l.Parse()
	if err != nil {
		utils.LogWarn("cpe", l, "Cannot parse")
		return false
	}
	rParsed, err := r.Parse()
	if err != nil {
		utils.LogWarn("cpe", r, "Cannot parse")
		return false
	}
	return lParsed.match(rParsed)
}

func repos2cpes(c *Cache, repoIDs []RepoID) []CpeID {
	res := make([]CpeID, 0)
	repoCpes := make([]CpeID, 0)
	uniqCpes := make(map[CpeID]bool)
	for _, repoID := range repoIDs {
		if cpes, has := c.RepoID2CpeIDs[repoID]; has {
			repoCpes = append(repoCpes, cpes...)
		}
	}

	if len(repoCpes) > 0 {
		for cpeID, cpeLabel := range c.CpeID2Label {
			for _, repoCpeID := range repoCpes {
				repoCpe := c.CpeID2Label[repoCpeID]
				if cpeMatch(cpeLabel, repoCpe) {
					if !uniqCpes[cpeID] {
						res = append(res, cpeID)
						uniqCpes[cpeID] = true
					}
				}
			}
		}
	}
	return res
}

func productsWithUnfixedCVEs(c *Cache, cpe CpeID, nameID NameID, modules []ModuleStream) []CSAFProduct {
	products := make([]CSAFProduct, 0, len(modules)+1)
	cn := CpeIDNameID{CpeID: cpe, NameID: nameID}
	for _, ms := range modules {
		product := CSAFProduct{CpeID: cpe, PackageNameID: nameID, ModuleStream: ms}
		if _, ok := c.CSAFCVEs[cn][product]; ok {
			products = append(products, product)
		}
	}
	return products
}

func productWithFixedCVEs(c *Cache, cpe CpeID, nameID NameID, modules []ModuleStream) ([]CSAFProduct, bool) {
	cn := CpeIDNameID{CpeID: cpe, NameID: nameID}
	productCves, ok := c.CSAFCVEs[cn]
	products := make([]CSAFProduct, 0, len(productCves))
	for p := range productCves {
		if p.PackageID == 0 {
			// fixed product always has PackageID
			continue
		}
		for _, module := range modules {
			if p.ModuleStream == module {
				products = append(products, p)
			}
		}
	}
	return products, ok
}

func cpes2products(c *Cache, cpes []CpeID, nameID NameID, modules []ModuleStream, pkg NevraString,
	opts *options,
) ProductsPackage {
	productsUnfixed := make([]CSAFProduct, 0, len(cpes)*(len(modules)+1))
	productsFixed := make([]CSAFProduct, 0, len(cpes))
	// add empty module to module list to find affected products without modules
	modules = append(modules, ModuleStream{})
	for _, cpe := range cpes {
		// create unfixed products for every CPE, unfixed product has PackageID=0
		for srcNameID := range c.NameID2SrcNameIDs[nameID] {
			srcName := c.ID2Packagename[srcNameID]
			if opts.excludedPackages[srcName] {
				continue
			}
			productsUnfixed = append(productsUnfixed, productsWithUnfixedCVEs(c, cpe, srcNameID, modules)...)
		}
		// create fixed products for every CPE
		if products, ok := productWithFixedCVEs(c, cpe, nameID, modules); ok {
			productsFixed = append(productsFixed, products...)
		}
	}
	pp := ProductsPackage{
		ProductsFixed:   productsFixed,
		ProductsUnfixed: productsUnfixed,
		Package:         Package{Nevra: pkg.Nevra, NameID: nameID, String: pkg.Pkg},
	}
	return pp
}

//nolint:gocognit,nolintlint,funlen
func repos2definitions(c *Cache, r *ProcessedRequest) map[DefinitionID]CpeID {
	candidateDefinitions := make(map[DefinitionID]CpeID)
	// Check CPE-Repo mapping first
	// Existing CPE-Repo mapping means the repository is eus/aus/e4s
	// Check exactly matched repositories (current enabled eus/aus/e4s version)
	// Use all definitions from these, and save vulnerabilities addressed by these definitions
	cvesFixedCurrentReleasever := make(map[string]bool)
	for _, cpe := range r.Cpes {
		if defs, has := c.CpeID2OvalDefinitionIDs[cpe]; has {
			for _, def := range defs {
				if cves, has := c.OvaldefinitionID2Cves[def]; has {
					for _, cve := range cves {
						cvesFixedCurrentReleasever[cve] = true
					}
				}
				if _, has := candidateDefinitions[def]; !has {
					candidateDefinitions[def] = cpe
				}
			}
		}
	}
	// Check repositories with newer releasever
	// Consider only definitions addressing CVEs which were not backported to the current stream
	for _, cpe := range r.NewerReleaseverCpes {
		if defs, has := c.CpeID2OvalDefinitionIDs[cpe]; has {
			for _, def := range defs {
				includeDefinition := true
				if cves, has := c.OvaldefinitionID2Cves[def]; has {
					for _, cve := range cves {
						// Don't add definition to evaluated definitions if the same CVE was
						// addressed by definition for the current stream
						if _, has := cvesFixedCurrentReleasever[cve]; has {
							includeDefinition = false
							break
						}
					}
				}
				if includeDefinition {
					if _, has := candidateDefinitions[def]; !has {
						candidateDefinitions[def] = cpe
					}
				}
			}
		}
	}

	// Not an eus/aus/e4s repo? Use only CPE-CS mapping
	if len(candidateDefinitions) == 0 {
		for _, csID := range r.ContentSets {
			if cpes, has := c.ContentSetID2CpeIDs[csID]; has {
				for _, cpe := range cpes {
					if defs, has := c.CpeID2OvalDefinitionIDs[cpe]; has {
						for _, def := range defs {
							if _, has := candidateDefinitions[def]; !has {
								candidateDefinitions[def] = cpe
							}
						}
					}
				}
			}
		}
	}

	return candidateDefinitions
}

func evaluateCriteria(c *Cache, criteriaID CriteriaID, pkgNameID NameID, nevra utils.Nevra,
	modules map[string]string, resultContext map[string]interface{},
) bool {
	moduleTestDeps := c.OvalCriteriaID2DepModuleTestIDs[criteriaID]
	testDeps := c.OvalCriteriaID2DepTestIDs[criteriaID]
	criteriaDeps := c.OvalCriteriaID2DepCriteriaIDs[criteriaID]

	criteriaType := c.OvalCriteriaID2Type[criteriaID]
	mustMatch := false
	requiredMatches := 0
	switch criteriaType {
	case OvalCriteriaOperatorAnd:
		requiredMatches = len(moduleTestDeps) + len(testDeps) + len(criteriaDeps)
		mustMatch = true
	case OvalCriteriaOperatorOr:
		requiredMatches = int(math.Min(1, float64((len(moduleTestDeps) + len(testDeps) + len(criteriaDeps)))))
		mustMatch = false
	default:
		utils.LogError("operator", criteriaType, "Unsupported operator")
		return false
	}
	matches := 0

	for _, m := range moduleTestDeps {
		if matches >= requiredMatches {
			break
		}
		if evaluateModuleTest(c, m, modules) {
			matches++
			resultContext["module"] = c.OvalModuleTestDetail[m].ModuleStream
		} else if mustMatch { // AND
			break
		}
	}

	for _, t := range testDeps {
		if matches >= requiredMatches {
			break
		}
		if evaluateTest(c, t, pkgNameID, nevra) {
			matches++
		} else if mustMatch { // AND
			break
		}
	}

	for _, cr := range criteriaDeps {
		if matches >= requiredMatches {
			break
		}
		if evaluateCriteria(c, cr, pkgNameID, nevra, modules, resultContext) {
			matches++
		} else if mustMatch { // AND
			break
		}
	}

	return matches >= requiredMatches
}

func evaluateState(c *Cache, state OvalState, nevra utils.Nevra) (matched bool) {
	candidateEvr := c.ID2Evr[state.EvrID]
	switch state.OperationEvr {
	case OvalOperationEvrEquals:
		matched = (nevra.Epoch == candidateEvr.Epoch &&
			nevra.Version == candidateEvr.Version &&
			nevra.Release == candidateEvr.Release)
	case OvalOperationEvrLessThan:
		matched = nevra.NevraCmpEvr(candidateEvr) < 0
	default:
		utils.LogError("OvalOperationEvr", state.OperationEvr, "Unsupported OvalOperationEvr")
		return false
	}

	candidateArches := c.OvalStateID2Arches[state.ID]
	if len(candidateArches) > 0 {
		archID, ok := c.Arch2ID[nevra.Arch]
		if !ok {
			utils.LogError("arch", nevra.Arch, "Invalid arch name")
			return false
		}
		if matched {
			for _, a := range candidateArches {
				if a == archID {
					return true
				}
			}
			return false
		}
	}
	return matched
}

func evaluateModuleTest(c *Cache, moduleTestID ModuleTestID, modules map[string]string) bool {
	testDetail := c.OvalModuleTestDetail[moduleTestID]
	return modules[testDetail.ModuleStream.Module] == testDetail.ModuleStream.Stream
}

func evaluateTest(c *Cache, testID TestID, pkgNameID NameID, nevra utils.Nevra) (matched bool) {
	candidate := c.OvalTestDetail[testID]
	pkgNameMatched := pkgNameID == candidate.PkgNameID
	switch candidate.CheckExistence {
	case OvalCheckExistenceAtLeastOne:
		states := c.OvalTestID2States[testID]
		if pkgNameMatched && len(states) > 0 {
			for _, s := range states {
				if evaluateState(c, s, nevra) {
					matched = true
					break // at least one
				}
			}
		} else {
			matched = pkgNameMatched
		}
	case OvalCheckExistenceNone:
		matched = !pkgNameMatched
	default:
		utils.LogError("check_existence", candidate.CheckExistence, "Unsupported check_existence")
		return false
	}
	return matched
}

func updateCves(cves map[string]VulnerabilityDetail, cve string, pkg Package, errata []string, cpe CpeLabel,
	module *ModuleStream,
) {
	if _, has := cves[cve]; !has {
		cveDetail := VulnerabilityDetail{
			CVE:      cve,
			Packages: map[string]bool{pkg.String: true},
			Errata:   map[string]bool{},
		}
		for _, erratum := range errata {
			cveDetail.Errata[erratum] = true
		}
		if len(cpe) > 0 {
			cveDetail.Affected = []AffectedPackage{{
				Name: pkg.Name,
				EVRA: pkg.EVRAStringE(true),
				Cpe:  cpe,
			}}
			if module != nil {
				cveDetail.Affected[0].ModuleStreamPtrs.Module = &module.Module
				cveDetail.Affected[0].ModuleStreamPtrs.Stream = &module.Stream
			}
		}
		cves[cve] = cveDetail
		return
	}
	// update list of packages and errata
	vulnDetail := cves[cve]
	vulnDetail.Packages[pkg.String] = true
	for _, erratum := range errata {
		vulnDetail.Errata[erratum] = true
	}
	if len(cpe) > 0 {
		affectedPackage := AffectedPackage{
			Name: pkg.Name,
			EVRA: pkg.EVRAStringE(true),
			Cpe:  cpe,
		}
		if module != nil {
			affectedPackage.ModuleStreamPtrs.Module = &module.Module
			affectedPackage.ModuleStreamPtrs.Stream = &module.Stream
		}
		vulnDetail.Affected = append(vulnDetail.Affected, affectedPackage)
	}
	cves[cve] = vulnDetail
}
