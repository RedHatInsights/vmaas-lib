package vmaas

import (
	"fmt"
	"math"
	"time"

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
	Patch         map[DefinitionID]ProcessedDefinition
	Vulnerability map[DefinitionID]ProcessedDefinition
}

type ProcessedDefinition struct {
	DefinitionID DefinitionID
	CriteriaID   CriteriaID
	Packages     []Package
	Cpe          string
}

type Package struct {
	utils.Nevra
	String string
	NameID NameID
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

//nolint:funlen
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

	definitions, err := processed.processDefinitions(c, opts)
	if err != nil {
		return &cves, errors.Wrap(err, "couldn't evaluate OVAL")
	}

	modules := make(map[string]string)
	for _, m := range processed.Updates.ModuleList {
		modules[m.Module] = m.Stream
	}

	// 1. evaluate Unpatched CVEs
	for defID, definition := range definitions.Vulnerability {
		cvesOval := c.OvaldefinitionID2Cves[defID]
		definition.evaluate(c, modules, cvesOval, &cves, cves.UnpatchedCves)
	}

	// 2. evaluate CVEs from Repositories
	// if CVE is already in Unpatched list -> skip it
	updates := processed.evaluateRepositories(c, opts)
	seenErrata := map[string]bool{}
	for pkg, upDetail := range updates.UpdateList {
		for _, update := range upDetail.AvailableUpdates {
			if seenErrata[update.Erratum] {
				continue
			}
			seenErrata[update.Erratum] = true
			for _, cve := range c.ErratumDetails[update.Erratum].CVEs {
				if _, inUnpatchedCves := cves.UnpatchedCves[cve]; inUnpatchedCves {
					continue
				}
				updateCves(cves.Cves, cve, Package{String: pkg}, []string{update.Erratum}, "")
			}
		}
	}

	// 3. evaluate Manually Fixable CVEs
	// if CVE is already in Unpatched or CVE list -> skip it
	for defID, definition := range definitions.Patch {
		cvesOval := c.OvaldefinitionID2Cves[defID]
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

	return &cves, nil
}

func (d *ProcessedDefinition) evaluate(
	c *Cache, modules map[string]string, cvesOval []string, cves *VulnerabilitiesCvesDetails,
	dst map[string]VulnerabilityDetail,
) {
	for _, p := range d.Packages {
		if evaluateCriteria(c, d.CriteriaID, p.NameID, p.Nevra, modules) {
			for _, cve := range cvesOval {
				_, inCves := cves.Cves[cve]
				_, inUnpatchedCves := cves.UnpatchedCves[cve]
				// Fixable and Unpatched CVEs take precedence over Manually fixable
				if inCves || inUnpatchedCves {
					continue
				}
				errataNames := make([]string, 0)
				for _, erratumID := range c.OvalDefinitionID2ErrataIDs[d.DefinitionID] {
					errataNames = append(errataNames, c.ErratumID2Name[erratumID])
				}
				updateCves(dst, cve, p, errataNames, d.Cpe)
			}
		}
	}
}

func (r *ProcessedRequest) processDefinitions(c *Cache, opts *options) (*ProcessedDefinitions, error) {
	// Get CPEs for affected repos/content sets
	// TODO: currently OVAL doesn't evaluate when there is not correct input repo list mapped to CPEs
	//       there needs to be better fallback at least to guess correctly RHEL version,
	//       use old VMaaS repo guessing?
	candidateDefinitions := repos2definitions(c, r.OriginalRequest)
	definitions := ProcessedDefinitions{
		make(map[DefinitionID]ProcessedDefinition),
		make(map[DefinitionID]ProcessedDefinition),
	}

	for pkg, parsedNevra := range r.Packages {
		pkgNameID := c.Packagename2ID[parsedNevra.Name]
		allDefinitionsIDs := c.PackagenameID2definitionIDs[pkgNameID]
		for _, defID := range allDefinitionsIDs {
			if cpe, ok := candidateDefinitions[defID]; ok {
				definition := c.OvaldefinitionDetail[defID]
				switch definition.DefinitionTypeID {
				case OvalDefinitionTypePatch:
					if _, ok := definitions.Patch[defID]; !ok {
						definitions.Patch[defID] = ProcessedDefinition{}
					}
					definitions.Patch[defID] = ProcessedDefinition{
						DefinitionID: definition.ID,
						CriteriaID:   definition.CriteriaID,
						// store CPE only for Vulnerability type, field omitted intentionally
						Packages: append(definitions.Patch[defID].Packages, Package{
							Nevra:  parsedNevra,
							NameID: pkgNameID,
							String: pkg,
						}),
					}
				case OvalDefinitionTypeVulnerability:
					// Skip if unfixed CVE feature flag is disabled
					if !opts.evalUnfixed {
						continue
					}
					if _, ok := definitions.Vulnerability[defID]; !ok {
						definitions.Vulnerability[defID] = ProcessedDefinition{}
					}
					definitions.Vulnerability[defID] = ProcessedDefinition{
						DefinitionID: definition.ID,
						CriteriaID:   definition.CriteriaID,
						Cpe:          c.CpeID2Label[cpe],
						Packages: append(definitions.Vulnerability[defID].Packages, Package{
							Nevra:  parsedNevra,
							NameID: pkgNameID,
							String: pkg,
						}),
					}
				default:
					return nil, fmt.Errorf("unsupported definition type: %d", definition.DefinitionTypeID)
				}
			}
		}
	}
	return &definitions, nil
}

//nolint:gocognit,nolintlint
func repos2definitions(c *Cache, r *Request) map[DefinitionID]CpeID {
	// TODO: some CPEs are not matching because they are substrings/subtrees
	if r.Repos == nil {
		return nil
	}

	repoIDs := make(map[RepoID]bool)
	contentSetIDs := make(map[ContentSetID]bool)
	// Try to identify repos (CS+basearch+releasever) or at least CS
	for _, label := range *r.Repos {
		if r.Basearch != nil || r.Releasever != nil {
			for _, repoID := range c.RepoLabel2IDs[label] {
				if r.Basearch != nil && c.RepoDetails[repoID].Basearch != *r.Basearch {
					continue
				}
				if r.Releasever != nil && c.RepoDetails[repoID].Releasever != *r.Releasever {
					continue
				}
				repoIDs[repoID] = true
			}
		}
		if csID, has := c.Label2ContentSetID[label]; has {
			contentSetIDs[csID] = true
		}
	}

	cpeIDs := make(map[CpeID]bool)
	if len(repoIDs) > 0 { // Check CPE-Repo mapping first
		for repoID := range repoIDs {
			if cpes, has := c.RepoID2CpeIDs[repoID]; has {
				for _, cpe := range cpes {
					cpeIDs[cpe] = true
				}
			}
		}
	}
	if len(cpeIDs) == 0 { // No CPE-Repo mapping? Use CPE-CS mapping
		for csID := range contentSetIDs {
			if cpes, has := c.ContentSetID2CpeIDs[csID]; has {
				for _, cpe := range cpes {
					cpeIDs[cpe] = true
				}
			}
		}
	}

	candidateDefinitions := make(map[DefinitionID]CpeID)
	for cpe := range cpeIDs {
		if defs, has := c.CpeID2OvalDefinitionIDs[cpe]; has {
			for _, def := range defs {
				candidateDefinitions[def] = cpe
			}
		}
	}
	return candidateDefinitions
}

func evaluateCriteria(c *Cache, criteriaID CriteriaID, pkgNameID NameID, nevra utils.Nevra,
	modules map[string]string,
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
		if evaluateCriteria(c, cr, pkgNameID, nevra, modules) {
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

func updateCves(cves map[string]VulnerabilityDetail, cve string, pkg Package, errata []string, cpe string) {
	if _, has := cves[cve]; !has {
		cveDetail := VulnerabilityDetail{
			CVE:      cve,
			Packages: []string{pkg.String},
			Errata:   errata,
		}
		if len(cpe) > 0 {
			cveDetail.Affected = []AffectedPackage{{
				Name: pkg.Name,
				EVRA: pkg.EVRAStringE(true),
				Cpe:  cpe,
			}}
		}
		cves[cve] = cveDetail
		return
	}
	// update list of packages and errata
	vulnDetail := cves[cve]
	vulnDetail.Packages = append(vulnDetail.Packages, pkg.String)
	vulnDetail.Errata = append(vulnDetail.Errata, errata...)
	if len(cpe) > 0 {
		vulnDetail.Affected = append(vulnDetail.Affected, AffectedPackage{
			Name: pkg.Name,
			EVRA: pkg.EVRAStringE(true),
			Cpe:  cpe,
		})
	}
}
