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

var defaultCfg = Config{true, 20}

type API struct {
	Cache  *Cache
	path   string
	url    string
	Config *Config
}

type Config struct {
	OvalUnfixedEvalEnabled bool
	MaxGoroutines          int
}

func InitFromFile(cachePath string, cfg *Config) (*API, error) {
	api := new(API)
	api.path = cachePath
	api.Config = cfg
	if cfg == nil {
		api.Config = &defaultCfg
	}
	if err := api.LoadCacheFromFile(cachePath); err != nil {
		return api, errors.Wrap(err, "couldn't init from file")
	}
	return api, nil
}

func InitFromURL(cacheURL string, cfg *Config) (*API, error) {
	api := new(API)
	api.url = cacheURL
	api.path = Dump
	api.Config = cfg
	if cfg == nil {
		api.Config = &defaultCfg
	}
	if err := api.LoadCacheFromURL(cacheURL); err != nil {
		return api, errors.Wrap(err, "couldn't init from url")
	}
	return api, nil
}

func (api *API) Updates(request *Request) (*Updates, error) {
	return request.Updates(api.Cache, api.Config)
}

func (api *API) Vulnerabilities(request *Request) (*Vulnerabilities, error) {
	return request.Vulnerabilities(api.Cache, api.Config)
}

func (api *API) VulnerabilitiesExtended(request *Request) (*VulnerabilitiesExtended, error) {
	return request.VulnerabilitiesExtended(api.Cache, api.Config)
}

func (api *API) LoadCacheFromFile(cachePath string) error {
	var err error
	api.Cache, err = loadCache(cachePath, api.Config)
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
			reloadNeeded, err := api.IsReloadNeeded(latestDumpEndpoint)
			if err != nil {
				utils.LogWarn("err", err.Error(), "Error getting latest dump timestamp")
			}
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

func (api *API) IsReloadNeeded(latestDumpEndpoint string) (bool, error) {
	if api.Cache == nil {
		return true, nil
	}

	resp, err := http.Get(latestDumpEndpoint) //nolint:gosec // url is user's input
	if err != nil {
		return true, errors.Wrap(err, "couldn't get latest dump info")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, errors.Wrap(err, "couldn't read response body")
	}

	latest, err := time.Parse(time.RFC3339, string(body))
	if err != nil {
		return true, errors.Wrap(err, "couldn't parse latest timestamp")
	}

	exported, err := time.Parse(time.RFC3339, api.Cache.DBChange.Exported)
	if err != nil {
		return true, errors.Wrap(err, "couldn't parse exported timestamp")
	}

	if latest.After(exported) {
		utils.LogDebug("latest", latest, "exported", exported, "Reload needed")
		return true, nil
	}
	utils.LogDebug("latest", latest, "exported", exported, "Reload not needed")
	return false, nil
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
