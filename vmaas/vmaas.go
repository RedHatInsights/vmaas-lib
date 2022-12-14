package vmaas

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

const Dump = "/data/vmaas.db"

type API struct {
	Cache *Cache
	path  string
	url   string
}

func InitFromFile(cachePath string) (*API, error) {
	api := new(API)
	api.path = cachePath
	if err := api.LoadCacheFromFile(cachePath); err != nil {
		return api, errors.Wrap(err, "couldn't init from file")
	}
	return api, nil
}

func InitFromURL(cacheURL string) (*API, error) {
	api := new(API)
	api.url = cacheURL
	api.path = Dump
	if err := api.LoadCacheFromURL(cacheURL); err != nil {
		return api, errors.Wrap(err, "couldn't init from url")
	}
	return api, nil
}

func (api *API) Updates(request *Request) (*Updates, error) {
	return request.Updates(api.Cache)
}

func (api *API) Vulnerabilities(request *Request) (*Vulnerabilities, error) {
	return request.Vulnerabilities(api.Cache)
}

func (api *API) VulnerabilitiesExtended(request *Request) (*VulnerabilitiesExtended, error) {
	return request.VulnerabilitiesExtended(api.Cache)
}

func (api *API) LoadCacheFromFile(cachePath string) error {
	var err error
	api.Cache, err = loadCache(cachePath)
	if err != nil {
		return errors.Wrap(err, "couldn't load cache from file")
	}
	return nil
}

func (api *API) LoadCacheFromURL(cacheURL string) error {
	useRsync := strings.Contains(cacheURL, "rsync")
	if err := DownloadCache(cacheURL, Dump, useRsync); err != nil {
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
				utils.Log("err", err.Error()).Warn("Error getting latest dump timestamp")
			}
			if !reloadNeeded {
				continue
			}
			utils.Log().Info("Reloading cache")
			// invalidate cache and manually run GC to free memory
			api.Cache = nil
			utils.RunGC()
			if len(url) > 0 {
				if err := api.LoadCacheFromURL(url); err != nil {
					utils.Log("err", err.Error()).Error("Cache reload failed")
				}
				continue
			}
			utils.Log("url", url, "filepath", api.path).Warn(
				"URL not set, loading cache from last known filepath")
			if err := api.LoadCacheFromFile(api.path); err != nil {
				utils.Log("err", err.Error()).Error("Cache reload failed")
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
		utils.Log("latest", latest, "exported", exported).Debug("Reload needed")
		return true, nil
	}
	utils.Log("latest", latest, "exported", exported).Debug("Reload not needed")
	return false, nil
}

func DownloadCache(url, dest string, useRsync bool) error {
	utils.Log().Info("Downloading cache")
	if useRsync {
		cmd := exec.Command("/usr/bin/rsync", "-a", "--copy-links", "--quiet", url, dest)
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "couldn't rsync cache")
		}
		utils.Log().Info("Cache downloaded - rsync")
		return nil
	}
	resp, err := http.Get(url) //nolint:gosec // url is user's input
	if err != nil {
		return errors.Wrap(err, "couldn't download cache")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "couldn't read response body")
	}

	err = os.WriteFile(dest, body, 0o644) //nolint:gosec // file needs 0644 permissions
	if err != nil {
		return errors.Wrap(err, "couldn't write file")
	}
	utils.Log().Info("Cache downloaded - URL")
	return nil
}
