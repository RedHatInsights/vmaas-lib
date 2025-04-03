package vmaas

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const Dump = "/data/vmaas.db"

type API struct {
	Cache   *Cache
	path    string
	url     string
	options *options
}

func InitFromFile(cachePath string, opts ...Option) (*API, error) {
	api := new(API)
	api.path = cachePath
	applyOptions(api, opts)

	if err := api.LoadCacheFromFile(cachePath); err != nil {
		return api, errors.Wrap(err, "couldn't init from file")
	}
	return api, nil
}

func InitFromURL(cacheURL string, opts ...Option) (*API, error) {
	api := new(API)
	api.url = cacheURL
	api.path = Dump
	applyOptions(api, opts)

	if err := api.LoadCacheFromURL(cacheURL); err != nil {
		return api, errors.Wrap(err, "couldn't init from url")
	}
	return api, nil
}

func (api *API) Updates(request *Request) (*Updates, error) {
	return request.updates(api.Cache, api.options)
}

func (api *API) Vulnerabilities(request *Request) (*Vulnerabilities, error) {
	return request.vulnerabilities(api.Cache, api.options)
}

func (api *API) VulnerabilitiesExtended(request *Request) (*VulnerabilitiesExtended, error) {
	return request.vulnerabilitiesExtended(api.Cache, api.options)
}

func (api *API) Cves(request *CvesRequest) (*Cves, error) {
	return request.cves(api.Cache)
}

func (api *API) Errata(request *ErrataRequest) (*Errata, error) {
	return request.errata(api.Cache)
}

func (api *API) Repos(request *ReposRequest) (*Repos, error) {
	return request.repos(api.Cache)
}

func (api *API) Packages(request *PackagesRequest) (*Packages, error) {
	return request.packages(api.Cache)
}

func (api *API) PkgList(request *PkgListRequest) (*PkgList, error) {
	return request.pkglist(api.Cache)
}

func (api *API) PkgTree(request *PkgTreeRequest) (*PkgTree, error) {
	return request.pkgtree(api.Cache)
}

func (api *API) Patches(request *Request) (*Patches, error) {
	return request.patches(api.Cache, api.options)
}

func (api *API) RPMPkgNames(request *RPMPkgNamesRequest) (*RPMPkgNames, error) {
	return request.rpmPkgNames(api.Cache)
}

func (api *API) SRPMPkgNames(request *SRPMPkgNamesRequest) (*SRPMPkgNames, error) {
	return request.srpmPkgNames(api.Cache)
}

func (api *API) Version() *string {
	return vmaasVersion(api.options)
}

func (api *API) OSVulnerabilityReport() (*VulnerabilityReport, error) {
	return vulnerabilityReport(api.Cache, api.options)
}

func (api *API) LoadCacheFromFile(cachePath string) error {
	var err error
	api.Cache, err = loadCache(cachePath, api.options)
	if err != nil {
		return errors.Wrap(err, "couldn't load cache from file")
	}
	return nil
}

func (api *API) LoadCacheFromURL(cacheURL string) error {
	if err := DownloadCache(cacheURL, api.path); err != nil {
		return errors.Wrap(err, "couldn't download cache")
	}
	err := api.LoadCacheFromFile(api.path)
	return err
}

func (api *API) PeriodicCacheReload(interval time.Duration, latestDumpEndpoint string, cacheURL *string) {
	ticker := time.NewTicker(interval)
	// preserve api.url set by InitFromURL
	url := api.url
	if cacheURL != nil {
		url = *cacheURL
	}

	go func() {
		for range ticker.C {
			reloadNeeded := ShouldReload(api.Cache, latestDumpEndpoint)
			if !reloadNeeded {
				continue
			}
			utils.LogInfo("Reloading cache")
			// invalidate cache and manually run GC to free memory
			api.Cache = nil
			utils.RunGC()
			if len(url) > 0 {
				if err := api.LoadCacheFromURL(url); err != nil {
					utils.LogError("err", err.Error(), "Cache reload failed")
				}
				continue
			}
			utils.LogWarn("url", url, "filepath", api.path,
				"URL not set, loading cache from last known filepath")
			if err := api.LoadCacheFromFile(api.path); err != nil {
				utils.LogError("err", err.Error(), "Cache reload failed")
			}
		}
	}()
}

func DownloadCache(url, dest string) error {
	utils.LogInfo("Downloading cache")
	resp, err := http.Get(url) //nolint:gosec // url is user's input
	if err != nil {
		return errors.Wrap(err, "couldn't download cache")
	}
	defer resp.Body.Close()

	fd, err := os.Create(dest)
	if err != nil {
		return errors.Wrap(err, "couldn't create file")
	}
	defer fd.Close()

	size, err := io.Copy(fd, resp.Body)
	if err != nil {
		return errors.Wrap(err, "couldn't stream response to a file")
	}

	utils.LogInfo("size", size, "Cache downloaded - URL")
	return nil
}
