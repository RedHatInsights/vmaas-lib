package vmaas

var defaultOpts = options{20, true}

type options struct {
	maxGoroutines int
	evalUnfixed   bool
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

// Option to evaluate unfixed CVEs by OVAL
func WithUnfixed(u bool) Option {
	return unfixedOption(u)
}

func applyOptions(api *API, opts []Option) {
	api.options = &defaultOpts

	for _, o := range opts {
		o.apply(api.options)
	}
}
