package vmaas

import (
	"github.com/pkg/errors"
)

func (r *Request) updates(c *Cache, opts *options) (*Updates, error) {
	// process request
	processed, err := r.processRequest(c)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't process request")
	}
	updates := processed.evaluateRepositories(c, opts)
	return updates, nil
}
