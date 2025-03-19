package vmaas

var defaultOpts = options{
	20, true, map[string]bool{"kernel-alt": true}, map[string]bool{"el7a": true}, true, true, "",
}

type options struct {
	maxGoroutines        int
	evalUnfixed          bool
	excludedPackages     map[string]bool
	excludedReleases     map[string]bool
	newerReleaseverRepos bool
	newerReleaseverCsaf  bool
	vmaasVersionFilePath string
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

type excludedRelsOption map[string]bool

func (p excludedRelsOption) apply(opts *options) {
	opts.excludedReleases = p
}

// Option to set excluded package releases
func WithExcludedReleases(rel map[string]bool) Option {
	return excludedRelsOption(rel)
}

type newerReleaseverReposOption bool

func (n newerReleaseverReposOption) apply(opts *options) {
	opts.newerReleaseverRepos = bool(n)
}

// Option to look for updates/cves in newer release version
// when evaluating from repositories
func WithNewerReleaseverRepos(n bool) Option {
	return newerReleaseverReposOption(n)
}

type newerReleaseverCsafOption bool

func (n newerReleaseverCsafOption) apply(opts *options) {
	opts.newerReleaseverCsaf = bool(n)
}

// Option to look for updates/cves in newer release version
// when evaluating from CSAF
func WithNewerReleaseverCsaf(n bool) Option {
	return newerReleaseverCsafOption(n)
}

type vmaasVersionFilePath string

func (path vmaasVersionFilePath) apply(opts *options) {
	opts.vmaasVersionFilePath = string(path)
}

// Option that specifies VMaaS version file path
func WithVmaasVersionFilePath(path string) Option {
	return vmaasVersionFilePath(path)
}
