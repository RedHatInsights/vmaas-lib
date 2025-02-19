package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultOptions(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, defaultOpts, *api.options)
	}(api)
}

func TestMaxGoroutinesOption(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, 9, api.options.maxGoroutines)
	}(api, WithMaxGoroutines(9))
}

func TestEvalUnfixedOption(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, false, api.options.evalUnfixed)
	}(api, WithUnfixed(false))
}

func TestExcludedPackagesOption(t *testing.T) {
	api := new(API)
	pkg := map[string]bool{"kernel-alt": true}
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, pkg, api.options.excludedPackages)
	}(api, WithExcludedPackages(pkg))
}

func TestExcludedReleasesOption(t *testing.T) {
	api := new(API)
	rel := map[string]bool{"el7a": true}
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, rel, api.options.excludedReleases)
	}(api, WithExcludedReleases(rel))
}

func TestNewerReleaseverReposOption(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, false, api.options.newerReleaseverRepos)
	}(api, WithNewerReleaseverRepos(false))
}

func TestNewerReleaseverCsafOption(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, false, api.options.newerReleaseverCsaf)
	}(api, WithNewerReleaseverCsaf(false))
}

func TestAllOptions(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, false, api.options.evalUnfixed)
		assert.Equal(t, 1, api.options.maxGoroutines)
	}(api, WithUnfixed(false), WithMaxGoroutines(1))
}
