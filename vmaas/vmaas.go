package vmaas

import (
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type API struct {
	Cache *Cache
	path  string
	url   string
}

func InitFromFile(cachePath string) *API {
	api := new(API)
	api.LoadCacheFromFile(cachePath)
	return api
}

func InitFromUrl(cacheUrl string) *API {
	api := new(API)
	api.LoadCacheFromUrl(cacheUrl)
	return api
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

func (api *API) LoadCacheFromFile(cachePath string) {
	api.path = cachePath
	api.Cache = loadCache(cachePath)
}

func (api *API) LoadCacheFromUrl(cacheUrl string) {
	var path string
	// TODO: download cache
	// path, err := DownloadCache(cacheUrl)
	// if err != nil {
	// panic(err)
	// }
	api.url = cacheUrl
	api.path = path
	api.LoadCacheFromFile(path)
}

func (api *API) PeriodicCacheReload(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			utils.Log().Info("Reloading cache")
			if len(api.url) > 0 {
				api.LoadCacheFromUrl(api.url)
				return
			}
			api.LoadCacheFromFile(api.path)
		}
	}()
}
