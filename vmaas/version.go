package vmaas

import (
	"os"
)

func vmaasVersion(opts *options) *string {
	path := opts.vmaasVersionFilePath
	if path == "" {
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	res := string(bytes)
	return &res
}
