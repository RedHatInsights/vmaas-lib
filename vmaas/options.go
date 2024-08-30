package vmaas

var defaultOpts = options{20, true, map[string]bool{"kernel-alt": true}}

type options struct {
	maxGoroutines    int
	evalUnfixed      bool
	excludedPackages map[string]bool
}

type Option interface {
	apply(*options)
}

type goroutinesOption int

func (g goroutinesOption) apply(opts *options) {
	opts.maxGoroutines = int(g)
}

// Option to set maximum number of goroutines used by the lib
func WithMaxGoroutines(g int) Option {
	return goroutinesOption(g)
}

type unfixedOption bool

func (u unfixedOption) apply(opts *options) {
	opts.evalUnfixed = bool(u)
}

// Option to evaluate unfixed CVEs by CSAF
func WithUnfixed(u bool) Option {
	return unfixedOption(u)
}

func applyOptions(api *API, opts []Option) {
	api.options = &defaultOpts

	for _, o := range opts {
		o.apply(api.options)
	}
}

type excludedPkgsOption map[string]bool

func (p excludedPkgsOption) apply(opts *options) {
	opts.excludedPackages = p
}

// Option to set excluded package names
func WithExcludedPackages(pkgs map[string]bool) Option {
	return excludedPkgsOption(pkgs)
}
