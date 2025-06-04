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
	ProductsFixed             []CSAFProduct
	ProductsUnfixed           []CSAFProduct
	ProductsFixedNewerRelease []CSAFProduct
	Package                   Package
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

	// 3. evaluate Manually Fixable CVEs
	// if CVE is already in Unpatched or CVE list -> skip it
	evaluateManualCves(c, products, &cves, tmpManualCves, opts)
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
			vs := product.VariantSuffix
			cn := CpeIDNameID{CpeID: product.CpeID, NameID: product.PackageNameID}
			csafCves := c.CSAFCVEs[vs][cn][product]
			for _, cve := range getCveStrings(c, csafCves.Unfixed) {
				cpe := c.CpeID2Label[product.CpeID]
				if module.Module != "" {
					updateCves(cves.UnpatchedCves, cve.String, pp.Package, nil, cpe, &module)
				} else {
					updateCves(cves.UnpatchedCves, cve.String, pp.Package, nil, cpe, nil)
				}
			}
		}
	}
}

func updateManualCvesFromProducts(c *Cache, pkg Package, product CSAFProduct, seenProducts map[CSAFProduct]bool,
	alreadyFixed map[string]map[string]bool, cves *VulnerabilitiesCvesDetails, opts *options,
) {
	if seenProducts[product] {
		// duplicate product in pp.ProductsFixed
		// skip processing of already processed product
		return
	}
	seenProducts[product] = true
	updateNevra := pkgID2Nevra(c, product.PackageID)
	cn := CpeIDNameID{CpeID: product.CpeID, NameID: pkg.NameID}

	if isApplicableOrEqual(c, &pkg.Nevra, &updateNevra, opts) {
		// The installed package version is newer or equal to update version.
		// This means that the fix for this package is already applied in the current product release,
		// so updates from later releases should not be shown.
		if _, ok := alreadyFixed[pkg.String]; !ok {
			alreadyFixed[pkg.String] = make(map[string]bool)
		}
		vs := product.VariantSuffix
		csafCves := c.CSAFCVEs[vs][cn][product]
		for _, cve := range getCveStrings(c, csafCves.Fixed) {
			alreadyFixed[pkg.String][cve.String] = true
		}
		return // current package is newer than the update
	}

	if isApplicable(c, &updateNevra, &pkg.Nevra, opts) {
		// update is applicable to the currently installed package
		module := product.ModuleStream
		vs := product.VariantSuffix
		csafCves := c.CSAFCVEs[vs][cn][product]
		for _, cve := range getCveStrings(c, csafCves.Fixed) {
			if alreadyFixed[pkg.String][cve.String] {
				// This CVE has already been fixed for the current package.
				// Example:
				//   - Enabled repository: 	rhel-8-for-x86_64-appstream-eus-rpms, releasever=8.6
				//   - Installed package: 	python3-unbound-1.7.3-17.el8_6.5.x86_64
				//   - Fix in RHEL 8.6 EUS: python3-unbound-1.7.3-17.el8_6.4.x86_64, CVE-2024-1488, RHSA-2024:1804
				//   - Fix in RHEL 8.8 EUS: python3-unbound-1.16.2-5.el8_8.4.x86_64, CVE-2024-1488, RHSA-2024:1802
				// The CVE is considered already resolved, so it should not be marked as manually fixable.
				//
				// There is a potential issue:
				//   - installed package:			 pkg-1.1.0
				//   - package fixing CVE-123:		 pkg-1.0.0
				//   - package fixing CVE-123 again: pkg-1.2.0 (previous fix is not complete)
				// in this case we might not show CVE-123
				return
			}
			_, inCves := cves.Cves[cve.String]
			_, inUnpatchedCves := cves.UnpatchedCves[cve.String]
			if !(inCves || inUnpatchedCves) {
				// show only CVE hit which is not in Cves and UnpatchedCves
				cpe := c.CpeID2Label[product.CpeID]
				erratum := c.CSAFCVEProduct2Erratum[CSAFCVEProduct{
					CVEID:         cve.ID,
					CSAFProductID: c.CSAFProduct2ID[product],
				}]
				if module.Module != "" {
					updateCves(cves.ManualCves, cve.String, pkg, []string{erratum}, cpe, &module)
				} else {
					updateCves(cves.ManualCves, cve.String, pkg, []string{erratum}, cpe, nil)
				}
			}
		}
	}
}

func updateManualCvesFromRepositories(cves *VulnerabilitiesCvesDetails,
	newerReleaseReposCves map[string]VulnerabilityDetail,
	allAlreadyFixed map[string]map[string]bool,
) {
	for cve, detail := range newerReleaseReposCves {
		if _, ok := cves.Cves[cve]; !ok {
			fixedCurRelease := true
			for pkg := range detail.Packages {
				if !allAlreadyFixed[pkg][cve] {
					// `cve` is not fixed by the `pkg` from current release
					fixedCurRelease = false
					break
				}
			}

			if fixedCurRelease {
				// `cve` is fixed in the current release
				continue
			}

			if _, ok := cves.ManualCves[cve]; !ok {
				// append to ManualCves
				cves.ManualCves[cve] = detail
				continue
			}
			// update CVE in ManualCves
			vd := cves.ManualCves[cve]
			for pkg := range detail.Packages {
				vd.Packages[pkg] = true
			}
			for erratum := range detail.Errata {
				vd.Errata[erratum] = true
			}
			vd.Affected = append(vd.Affected, detail.Affected...)
		}
	}
}

func evaluateManualCves(c *Cache, products []ProductsPackage, cves *VulnerabilitiesCvesDetails,
	newerReleaseReposCves map[string]VulnerabilityDetail, opts *options,
) {
	allAlreadyFixed := make(map[string]map[string]bool) // map[package]map[cve]bool
	for _, pp := range products {
		seenProducts := make(map[CSAFProduct]bool, len(pp.ProductsFixed))
		// already fixed pkg-cve per product to include product information into VulnerabilitiesExtended
		alreadyFixed := make(map[string]map[string]bool) // map[package]map[cve]bool
		for _, product := range pp.ProductsFixed {
			updateManualCvesFromProducts(c, pp.Package, product, seenProducts, alreadyFixed, cves, opts)
		}
		for _, product := range pp.ProductsFixedNewerRelease {
			updateManualCvesFromProducts(c, pp.Package, product, seenProducts, alreadyFixed, cves, opts)
		}
		for k, v := range alreadyFixed {
			allAlreadyFixed[k] = v
		}
	}

	updateManualCvesFromRepositories(cves, newerReleaseReposCves, allAlreadyFixed)
}

// process repos into CPEs and ContentSets needed for vulnerability evaluation
func (r *ProcessedRequest) processRepos(c *Cache) {
	repoIDs, newerReleaseverRepoIDs, contentSetIDs := repos2IDs(c, r.OriginalRequest)
	cpes := repos2cpes(c, repoIDs)
	variants, cpeIDs := cpes2variantsCpes(c, cpes, nil)

	newerReleaseverCpes := repos2cpes(c, newerReleaseverRepoIDs)
	newerVariants, newerCpes := cpes2variantsCpes(c, newerReleaseverCpes, variants)

	csCpes := contentSets2cpes(c, contentSetIDs)
	csVariants, csCpeIDs := cpes2variantsCpes(c, csCpes, nil)

	r.Cpes = cpeIDs
	r.Variants = variants
	r.NewerCpes = newerCpes
	r.NewerVariants = newerVariants
	r.ContentSetCpes = csCpeIDs
	r.ContentSetVariants = csVariants
}

func (r *ProcessedRequest) processProducts(c *Cache, opts *options) []ProductsPackage {
	productsPackages := make([]ProductsPackage, 0)
	for _, pkg := range r.Packages {
		nameID := c.Packagename2ID[pkg.Nevra.Name]
		evrID := c.Evr2ID[utils.Evr{Epoch: pkg.Nevra.Epoch, Release: pkg.Nevra.Release, Version: pkg.Nevra.Version}]
		archID := c.Arch2ID[pkg.Nevra.Arch]
		pkgID := c.Nevra2PkgID[Nevra{NameID: nameID, EvrID: evrID, ArchID: archID}]
		products := cpes2products(c, r.Variants, r.Cpes, nameID, pkgID, r.Updates.ModuleList, pkg, opts)
		if opts.newerReleaseverCsaf && len(r.Cpes) > 0 {
			// look at newer releasever cpes only when there is a CPE hit for EUS repo
			newerReleaseverProducts := cpes2products(
				c, r.NewerVariants, r.NewerCpes, nameID, pkgID, r.Updates.ModuleList, pkg, opts)
			products.ProductsFixedNewerRelease = append(
				products.ProductsFixedNewerRelease,
				newerReleaseverProducts.ProductsFixed..., // ProductsFixedNewerRelease is not returned from cpes2products
			)
			products.ProductsUnfixed = append(products.ProductsUnfixed, newerReleaseverProducts.ProductsUnfixed...)
		}

		if len(r.Cpes) == 0 {
			// use CPEs from Content Sets if we haven't found any Cpes from repos
			products = cpes2products(c, r.ContentSetVariants, r.ContentSetCpes, nameID, pkgID, r.Updates.ModuleList, pkg, opts)
		}
		productsPackages = append(productsPackages, products)
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
				if r.Organization != "" && c.RepoDetails[repoID].Organization != r.Organization {
					continue
				}
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

func productsWithUnfixedCVEs(c *Cache, cpe CpeID, nameID NameID, modules []ModuleStream) []CSAFProduct {
	products := make([]CSAFProduct, 0, len(modules))
	cn := CpeIDNameID{CpeID: cpe, NameID: nameID}
	// VariantSuffix for Unfixed products is always "N/A" and hopefully SECDATA-1025 won't change it
	product := CSAFProduct{CpeID: cpe, VariantSuffix: DefaultVariantSuffix, PackageNameID: nameID}
	for _, ms := range modules {
		product.ModuleStream = ms
		if _, ok := c.CSAFCVEs[DefaultVariantSuffix][cn][product]; ok {
			products = append(products, product)
		}
	}
	return products
}

func productWithFixedCVEs(
	c *Cache, variant VariantSuffix, cpe CpeID, nameID NameID, modules []ModuleStream,
) ([]CSAFProduct, bool) {
	cn := CpeIDNameID{CpeID: cpe, NameID: nameID}
	productCves, ok := c.CSAFCVEs[variant][cn]
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

func cpes2products(c *Cache, variants []VariantSuffix, cpes []CpeID, nameID NameID, pkgID PkgID,
	modules []ModuleStream, pkg NevraString, opts *options,
) ProductsPackage {
	productsUnfixed := make([]CSAFProduct, 0, len(cpes))
	productsFixed := make([]CSAFProduct, 0, len(variants))
	// add empty module to module list to find affected products without modules
	modules = append(modules, ModuleStream{})
	for _, cpe := range cpes {
		seenNameIDs := make(map[NameID]bool)
		seenSrcNameIDs := make(map[NameID]bool)
		// create unfixed products for every CPE, unfixed product has PackageID=0
		pkgDetail := c.PackageDetails[pkgID]
		srcNameID := pkgDetail.NameID
		if pkgDetail.SrcPkgID != nil {
			srcPkgDetail := c.PackageDetails[*pkgDetail.SrcPkgID]
			srcNameID = srcPkgDetail.NameID
		}

		srcName := c.ID2Packagename[srcNameID]
		if opts.excludedPackages[srcName] {
			seenSrcNameIDs[srcNameID] = true
			continue
		}

		if !seenSrcNameIDs[srcNameID] {
			productsUnfixed = append(productsUnfixed, productsWithUnfixedCVEs(c, cpe, srcNameID, modules)...)
			seenSrcNameIDs[srcNameID] = true
		}

		if !seenNameIDs[nameID] {
			if srcNameID != nameID {
				// find unfixed products for installed package name not name of source package in case CSAF
				// shows vulnerability for package name and not source package name
				productsUnfixed = append(productsUnfixed, productsWithUnfixedCVEs(c, cpe, nameID, modules)...)
			}

			for _, variant := range variants {
				// create fixed products for every CPE and every product variant
				if products, ok := productWithFixedCVEs(c, variant, cpe, nameID, modules); ok {
					productsFixed = append(productsFixed, products...)
				}
			}
			seenNameIDs[nameID] = true
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

func getCveStrings(c *Cache, cveIDs []CVEID) []CveIDString {
	// TODO: rewrite with iterators introduced in go1.23 https://pkg.go.dev/iter
	cves := make([]CveIDString, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		cve, ok := c.CveNames[int(cveID)]
		if !ok {
			utils.LogWarn("cve_id", cveID, "Missing cve_id to name mapping, CVE might be removed by ProdSec")
			continue
		}
		cves = append(cves, CveIDString{ID: cveID, String: cve})
	}
	return cves
}
