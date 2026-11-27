package vmaas

import (
	"cmp"
	"regexp"
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

// UnpatchedPackageCPEs maps CPEs to module:stream keys (or "-" for non-modular packages).
type UnpatchedPackageCPEs map[string]map[string][]string

// UnpatchedPackageList maps affected binary package names to their CPEs.
type UnpatchedPackageList map[string]UnpatchedPackageCPEs

type UnpatchedPackages struct {
	Packages   UnpatchedPackageList `json:"unpatched_packages"`
	LastChange time.Time            `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
	Exported   time.Time            `json:"exported" example:"2024-11-20T12:37:47.605526Z"`
	utils.Pagination
}

type unpatchedPackageKey struct {
	name   string
	cpe    string
	module string
}

type unpatchedModuleFilter struct {
	name   *regexp.Regexp
	stream *regexp.Regexp
}

func compileUnpatchedPatterns(patterns []string, field string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		// Validate before wrapping: otherwise a malformed pattern such as "*"
		// could become valid after adding anchors.
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, errors.Wrapf(ErrProcessingInput, "invalid regex in %s: %s", field, err)
		}
		re, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
		if err != nil {
			return nil, errors.Wrapf(ErrProcessingInput, "invalid regex in %s: %s", field, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func matchesUnpatchedPatterns(patterns []*regexp.Regexp, value string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func compileUnpatchedModules(modules []ModuleStreamPtrs) ([]unpatchedModuleFilter, error) {
	compiled := make([]unpatchedModuleFilter, 0, len(modules))
	for _, module := range modules {
		if module.Module == nil || module.Stream == nil {
			return nil, errors.Wrap(ErrProcessingInput, "module_name and module_stream are required in modules_list")
		}
		names, err := compileUnpatchedPatterns([]string{*module.Module}, "module_name")
		if err != nil {
			return nil, err
		}
		streams, err := compileUnpatchedPatterns([]string{*module.Stream}, "module_stream")
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, unpatchedModuleFilter{names[0], streams[0]})
	}
	return compiled, nil
}

func matchesUnpatchedModule(filters []unpatchedModuleFilter, module ModuleStream) bool {
	if module.Module == "" {
		return false // supplied modules_list selects modular packages only
	}
	for _, filter := range filters {
		if filter.name.MatchString(module.Module) && filter.stream.MatchString(module.Stream) {
			return true
		}
	}
	return false
}

// forEachUnpatchedPackage visits each matching binary name / CPE / module
// combination. It does not materialize CVEs for rows outside the requested page.
func (c *Cache) forEachUnpatchedPackage(names, cpes []*regexp.Regexp, modules []unpatchedModuleFilter,
	moduleFilterSupplied bool, visit func(unpatchedPackageKey, []CVEID),
) {
	for cn, products := range c.CSAFCVEs[DefaultVariantSuffix] {
		cpe := string(c.CpeID2Label[cn.CpeID])
		if cpe == "" || (cpes != nil && !matchesUnpatchedPatterns(cpes, cpe)) {
			continue
		}
		for productID, cves := range products {
			if len(cves.Unfixed) == 0 {
				continue
			}
			// Removed CVEs may still be referenced by CSAF; don't return an
			// empty leaf if none of the IDs has a name in this dump.
			hasNamedCVE := false
			for _, id := range cves.Unfixed {
				if c.CveNames[int(id)] != "" {
					hasNamedCVE = true
					break
				}
			}
			if !hasNamedCVE {
				continue
			}
			product, ok := c.CSAFProductID2Product[productID]
			if !ok || product.PackageID != 0 ||
				(moduleFilterSupplied && !matchesUnpatchedModule(modules, product.ModuleStream)) {
				continue
			}

			moduleKey := "-"
			if product.ModuleStream.Module != "" {
				moduleKey = product.ModuleStream.Module + ":" + product.ModuleStream.Stream
			}
			for _, nameID := range c.UnpatchedName2BinaryNameIDs[cn.NameID] {
				name := c.ID2Packagename[nameID]
				if name != "" && matchesUnpatchedPatterns(names, name) {
					visit(unpatchedPackageKey{name, cpe, moduleKey}, cves.Unfixed)
				}
			}
		}
	}
}

func (req *UnpatchedPackagesRequest) unpatchedPackages(c *Cache) (*UnpatchedPackages, error) {
	if req == nil || len(req.PackageNames) == 0 {
		return nil, errors.Wrap(ErrProcessingInput, "'package_name_list' is a required property")
	}
	names, err := compileUnpatchedPatterns(req.PackageNames, "package_name_list")
	if err != nil {
		return nil, err
	}
	var cpes []*regexp.Regexp
	if req.Cpes != nil {
		cpes, err = compileUnpatchedPatterns(req.Cpes, "cpe_list")
		if err != nil {
			return nil, err
		}
	}
	var modules []unpatchedModuleFilter
	if req.Modules != nil {
		modules, err = compileUnpatchedModules(req.Modules)
		if err != nil {
			return nil, err
		}
	}

	keys := make(map[unpatchedPackageKey]bool)
	c.forEachUnpatchedPackage(names, cpes, modules, req.Modules != nil, func(key unpatchedPackageKey, _ []CVEID) {
		keys[key] = true
	})
	sortedKeys := make([]unpatchedPackageKey, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	slices.SortFunc(sortedKeys, func(a, b unpatchedPackageKey) int {
		if n := cmp.Compare(a.name, b.name); n != 0 {
			return n
		}
		if n := cmp.Compare(a.cpe, b.cpe); n != 0 {
			return n
		}
		return cmp.Compare(a.module, b.module)
	})
	pageKeys, pagination := utils.Paginate(sortedKeys, req.PaginationRequest)

	pageCVEs := make(map[unpatchedPackageKey]map[string]bool, len(pageKeys))
	for _, key := range pageKeys {
		pageCVEs[key] = make(map[string]bool)
	}
	if len(pageCVEs) > 0 {
		c.forEachUnpatchedPackage(names, cpes, modules, req.Modules != nil, func(key unpatchedPackageKey, cveIDs []CVEID) {
			cveSet, onPage := pageCVEs[key]
			if !onPage {
				return
			}
			for _, id := range cveIDs {
				if cve := c.CveNames[int(id)]; cve != "" {
					cveSet[cve] = true
				}
			}
		})
	}

	result := UnpatchedPackages{
		Packages:   make(UnpatchedPackageList),
		LastChange: c.DBChange.LastChange,
		Exported:   c.DBChange.Exported,
		Pagination: pagination,
	}
	for _, key := range pageKeys {
		if result.Packages[key.name] == nil {
			result.Packages[key.name] = make(UnpatchedPackageCPEs)
		}
		if result.Packages[key.name][key.cpe] == nil {
			result.Packages[key.name][key.cpe] = make(map[string][]string)
		}
		cves := make([]string, 0, len(pageCVEs[key]))
		for cve := range pageCVEs[key] {
			cves = append(cves, cve)
		}
		slices.Sort(cves)
		result.Packages[key.name][key.cpe][key.module] = cves
	}
	return &result, nil
}
