package vmaas

import (
	"sort"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type VulnerabilitiesCvesDetails struct {
	Cves          map[string]VulnerabilityDetail
	ManualCves    map[string]VulnerabilityDetail
	UnpatchedCves map[string]VulnerabilityDetail
	LastChange    *time.Time
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
	manual  bool
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

func evaluate(c *Cache, opts *options, request *Request) (*VulnerabilitiesCvesDetails, error) { //nolint: funlen
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
	products := processed.processProducts(c, opts)

	modules := make(map[string]string)
	for _, m := range processed.Updates.ModuleList {
		modules[m.Module] = m.Stream
	}

	// 1. evaluate Unpatched CVEs
	if opts.evalUnfixed {
		evaluateUnpatchedCves(c, products, &cves)
	}

	// 2. evaluate CVEs from Repositories
	// if CVE is already in Unpatched list -> skip it
	updates := processed.evaluateRepositories(c, opts)
	seenPkgErratum := map[packageErratum]bool{}
	tmpManualCves := map[string]VulnerabilityDetail{}
	for pkg, upDetail := range updates.UpdateList {
		for _, update := range upDetail.AvailableUpdates {
			pe := packageErratum{pkg, update.Erratum, update.manuallyFixable}
			if seenPkgErratum[pe] {
				continue
			}
			seenPkgErratum[pe] = true
			for _, cve := range c.ErratumDetails[update.Erratum].CVEs {
				if _, inUnpatchedCves := cves.UnpatchedCves[cve]; inUnpatchedCves {
					continue
				}
				if update.manuallyFixable {
					updateCves(tmpManualCves, cve, Package{String: pkg}, []string{update.Erratum}, "", nil)
				} else {
					updateCves(cves.Cves, cve, Package{String: pkg}, []string{update.Erratum}, "", nil)
				}
			}
		}
	}
	// store to cves.ManualCves only CVEs not found in cves.Cves
	for cve, detail := range tmpManualCves {
		if _, ok := cves.Cves[cve]; !ok {
			cves.ManualCves[cve] = detail
		}
	}

	// 3. evaluate Manually Fixable CVEs
	// if CVE is already in Unpatched or CVE list -> skip it
	evaluateManualCves(c, products, &cves)
	return &cves, nil
}

func evaluateUnpatchedCves(c *Cache, products []ProductsPackage, cves *VulnerabilitiesCvesDetails) {
	for _, pp := range products {
		seenProducts := make(map[CSAFProduct]bool, len(pp.ProductsUnfixed))
		for _, product := range pp.ProductsUnfixed {
			if seenProducts[product] {
				// duplicate product in pp.ProductsUnfixed
				// skip processing of already processed product
				continue
			}
			seenProducts[product] = true
			module := product.ModuleStream
			cn := CpeIDNameID{CpeID: product.CpeID, NameID: product.PackageNameID}
			csafCves := c.CSAFCVEs[cn][product]
			for _, cveID := range csafCves.Unfixed {
				cve, ok := c.CveNames[int(cveID)]
				if !ok {
					utils.LogWarn("cve_id", cveID, "Missing cve_id to name mapping, CVE might be removed by ProdSec")
					continue
				}
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
		seenProducts := make(map[CSAFProduct]bool, len(pp.ProductsFixed))
		for _, product := range pp.ProductsFixed {
			if seenProducts[product] {
				// duplicate product in pp.ProductsFixed
				// skip processing of already processed product
				continue
			}
			seenProducts[product] = true
			updateNevra := pkgID2Nevra(c, product.PackageID)
			if !isApplicable(c, &updateNevra, &pp.Package.Nevra) {
				continue
			}

			module := product.ModuleStream
			cn := CpeIDNameID{CpeID: product.CpeID, NameID: pp.Package.NameID}
			csafCves := c.CSAFCVEs[cn][product]
			for _, cveID := range csafCves.Fixed {
				cve, ok := c.CveNames[int(cveID)]
				if !ok {
					utils.LogWarn("cve_id", cveID, "Missing cve_id to name mapping, CVE might be removed by ProdSec")
					continue
				}
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

// process repos into CPEs and ContentSets needed for vulnerability evaluation
func (r *ProcessedRequest) processRepos(c *Cache) {
	repoIDs, newerReleaseverRepoIDs, contentSetIDs := repos2IDs(c, r.OriginalRequest)
	cpes := repos2cpes(c, repoIDs)
	newerReleaseverCpes := repos2cpes(c, newerReleaseverRepoIDs)
	csCpes := []CpeID{}
	if r.OriginalRequest.UseCsaf {
		// cpes of content sets are needed only for CSAF
		csCpes = contentSets2cpes(c, contentSetIDs)
	}
	r.Cpes = cpes
	r.NewerReleaseverCpes = newerReleaseverCpes
	r.ContentSets = contentSetIDs
	r.ContentSetsCpes = csCpes
}

func (r *ProcessedRequest) processProducts(c *Cache, opts *options) []ProductsPackage {
	productsPackages := make([]ProductsPackage, 0)
	if r.OriginalRequest.UseCsaf {
		for _, pkg := range r.Packages {
			nameID := c.Packagename2ID[pkg.Nevra.Name]
			products := cpes2products(c, r.Cpes, nameID, r.Updates.ModuleList, pkg, opts)
			if opts.newerReleaseverCsaf && len(r.Cpes) > 0 {
				// look at newer releasever cpes only when there is a CPE hit for EUS repo
				newerReleaseverProducts := cpes2products(c, r.NewerReleaseverCpes, nameID, r.Updates.ModuleList, pkg, opts)
				products.ProductsFixed = append(products.ProductsFixed, newerReleaseverProducts.ProductsFixed...)
				products.ProductsUnfixed = append(products.ProductsUnfixed, newerReleaseverProducts.ProductsUnfixed...)
			}

			if len(r.Cpes) == 0 {
				// use CPEs from Content Sets if we haven't found any Cpes from repos
				products = cpes2products(c, r.ContentSetsCpes, nameID, r.Updates.ModuleList, pkg, opts)
			}
			productsPackages = append(productsPackages, products)
		}
	}
	return productsPackages
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

func allMatchingCpes(c *Cache, repoCpes []CpeID) []CpeID {
	res := make([]CpeID, 0)
	if len(repoCpes) > 0 {
		for cpeID, cpeLabel := range c.CpeID2Label {
			for _, repoCpeID := range repoCpes {
				repoCpe := c.CpeID2Label[repoCpeID]
				if cpeMatch(cpeLabel, repoCpe) {
					res = append(res, cpeID)
					break
				}
			}
		}
	}
	return res
}

func repos2cpes(c *Cache, repoIDs []RepoID) []CpeID {
	repoCpes := make([]CpeID, 0)
	for _, repoID := range repoIDs {
		if cpes, has := c.RepoID2CpeIDs[repoID]; has {
			repoCpes = append(repoCpes, cpes...)
		}
	}

	return allMatchingCpes(c, repoCpes)
}

func contentSets2cpes(c *Cache, csIDs []ContentSetID) []CpeID {
	csCpes := make([]CpeID, 0)
	for _, csID := range csIDs {
		if cpes, has := c.ContentSetID2CpeIDs[csID]; has {
			csCpes = append(csCpes, cpes...)
		}
	}

	return allMatchingCpes(c, csCpes)
}

func productsWithUnfixedCVEs(c *Cache, cpe CpeID, nameID NameID, modules []ModuleStream) []CSAFProduct {
	products := make([]CSAFProduct, 0, len(modules))
	cn := CpeIDNameID{CpeID: cpe, NameID: nameID}
	product := CSAFProduct{CpeID: cpe, PackageNameID: nameID}
	for _, ms := range modules {
		product.ModuleStream = ms
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
