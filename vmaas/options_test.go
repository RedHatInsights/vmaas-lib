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

func TestAllOptions(t *testing.T) {
	api := new(API)
	func(api *API, opts ...Option) {
		applyOptions(api, opts)
		assert.Equal(t, false, api.options.evalUnfixed)
		assert.Equal(t, 1, api.options.maxGoroutines)
	}(api, WithUnfixed(false), WithMaxGoroutines(1))
}
