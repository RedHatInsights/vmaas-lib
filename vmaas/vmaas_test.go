package vmaas

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloadCacheNotFoundDoesNotWriteFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dest := "/tmp/download_cache_404_test.db"
	defer os.Remove(dest)

	err := DownloadCache(srv.URL, dest)
	assert.Error(t, err)
	_, statErr := os.Stat(dest)
	assert.True(t, os.IsNotExist(statErr), "destination file should not be created on a non-200 response")
}

func TestDownloadCacheNotFoundPreservesExistingFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dest := "/tmp/download_cache_404_preserve_test.db"
	defer os.Remove(dest)
	want := []byte("previously valid cache contents")
	assert.Nil(t, os.WriteFile(dest, want, 0o644))

	err := DownloadCache(srv.URL, dest)
	assert.Error(t, err)
	got, readErr := os.ReadFile(dest)
	assert.Nil(t, readErr)
	assert.Equal(t, want, got, "existing cache file must not be clobbered by a failed download")
}

func TestDownloadCacheOK(t *testing.T) {
	want := "totally real sqlite db bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	dest := "/tmp/download_cache_ok_test.db"
	defer os.Remove(dest)

	err := DownloadCache(srv.URL, dest)
	assert.Nil(t, err)
	got, readErr := os.ReadFile(dest)
	assert.Nil(t, readErr)
	assert.Equal(t, want, string(got))
}
