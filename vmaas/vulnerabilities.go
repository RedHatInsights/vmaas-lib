package vmaas

import (
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/conf"
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

func (r *Request) Vulnerabilities(c *Cache) (*Vulnerabilities, error) {
	cves, err := evaluate(c, r)
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

func (r *Request) VulnerabilitiesExtended(c *Cache) (*VulnerabilitiesExtended, error) {
	cves, err := evaluate(c, r)
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

func evaluate(c *Cache, request *Request) (*VulnerabilitiesCvesDetails, error) {
	cves := VulnerabilitiesCvesDetails{
		Cves:          make(map[string]VulnerabilityDetail),
		ManualCves:    make(map[string]VulnerabilityDetail),
		UnpatchedCves: make(map[string]VulnerabilityDetail),
	}

	// always use optimistic updates
	request.Optimistic = true

	// process request
	processed, err := request.processRequest(c)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't process request")
	}
	cves.LastChange = &processed.Updates.LastChange

	// Repositories
	updates := processed.evaluateRepositories(c)
	seenErrata := map[string]bool{}
	for pkg, upDetail := range updates.UpdateList {
		for _, update := range upDetail.AvailableUpdates {
			if seenErrata[update.Erratum] {
				continue
			}
			seenErrata[update.Erratum] = true
			for _, cve := range c.ErrataDetail[update.Erratum].CVEs {
				updateCves(cves.Cves, cve, pkg, []string{update.Erratum})
			}
		}
	}

	// OVAL
	err = processed.evaluateOval(c, &cves)
	if err != nil {
		return &cves, errors.Wrap(err, "couldn't evaluate OVAL")
	}

	return &cves, nil
}

//nolint:funlen,gocognit,nolintlint
func (r *ProcessedRequest) evaluateOval(c *Cache, cves *VulnerabilitiesCvesDetails) error {
	modules := make(map[*string]*string)
	for _, m := range r.OriginalRequest.Modules {
		modules[m.Module] = m.Stream
	}

	// Get CPEs for affected repos/content sets
	// TODO: currently OVAL doesn't evaluate when there is not correct input repo list mapped to CPEs
	//       there needs to be better fallback at least to guess correctly RHEL version,
	//       use old VMaaS repo guessing?
	candidateDefinitions := repos2definitions(c, r.OriginalRequest)
	if candidateDefinitions == nil {
		return nil
	}
	for pkg, parsedNevra := range r.Packages {
		pkgNameID := c.Packagename2ID[parsedNevra.Name]
		definitionsIDs := map[DefinitionID]bool{}
		allDefinitionsIDs := c.PackagenameID2definitionIDs[pkgNameID]
		for _, defID := range allDefinitionsIDs {
			if candidateDefinitions[defID] {
				definitionsIDs[defID] = true
			}
		}

		for defID := range definitionsIDs {
			definition := c.OvaldefinitionDetail[defID]
			// Skip if unfixed CVE feature flag is disabled
			if definition.DefinitionTypeID == OvalDefinitionTypeVulnerability && !conf.Env.OvalUnfixedEvalEnabled {
				continue
			}
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

			if evaluateCriteria(c, definition.CriteriaID, pkgNameID, parsedNevra, modules) {
				// Vulnerable
				switch definition.DefinitionTypeID {
				case OvalDefinitionTypePatch:
					for _, cve := range cvesOval {
						if _, has := cves.Cves[cve]; has {
							continue
						}
						errataNames := make([]string, 0)
						for _, errataID := range c.OvalDefinitionID2ErrataID[defID] {
							errataNames = append(errataNames, c.ErrataID2Name[errataID])
						}
						updateCves(cves.ManualCves, cve, pkg, errataNames)
					}
				case OvalDefinitionTypeVulnerability:
					for _, cve := range cvesOval {
						_, inCves := cves.Cves[cve]
						_, inManualCves := cves.ManualCves[cve]
						// Skip fixable CVEs (should never happen, just in case)
						if inCves || inManualCves {
							continue
						}
						// no erratum for unpatched CVEs
						updateCves(cves.UnpatchedCves, cve, pkg, []string{})
					}
				default:
					return fmt.Errorf("unsupported definition type: %d", definition.DefinitionTypeID)
				}
			}
		}
	}

	return nil
}

//nolint:gocognit,nolintlint
func repos2definitions(c *Cache, r *Request) map[DefinitionID]bool {
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

	candidateDefinitions := make(map[DefinitionID]bool)
	for cpe := range cpeIDs {
		if defs, has := c.CpeID2OvalDefinitionIDs[cpe]; has {
			for _, def := range defs {
				candidateDefinitions[def] = true
			}
		}
	}
	return candidateDefinitions
}

func evaluateCriteria(c *Cache, criteriaID CriteriaID, pkgNameID NameID, nevra utils.Nevra,
	modules map[*string]*string,
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

func evaluateModuleTest(c *Cache, moduleTestID ModuleTestID, modules map[*string]*string) bool {
	testDetail := c.OvalModuleTestDetail[moduleTestID]
	_, ok := modules[testDetail.ModuleStream.Module]
	return ok
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

func updateCves(cves map[string]VulnerabilityDetail, cve, pkg string, erratum []string) {
	if _, has := cves[cve]; !has {
		cveDetail := VulnerabilityDetail{
			CVE:      cve,
			Packages: []string{pkg},
			Errata:   erratum,
		}
		cves[cve] = cveDetail
		return
	}
	// update list of packages and errata
	vulnDetail := cves[cve]
	vulnDetail.Packages = append(vulnDetail.Packages, pkg)
	vulnDetail.Errata = append(vulnDetail.Errata, erratum...)
}
