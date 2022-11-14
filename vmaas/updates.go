package vmaas

import (
	"github.com/pkg/errors"
)

func (r *Request) Updates(c *Cache) (*Updates, error) {
	// process request
	processed, err := r.processRequest(c)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't process request")
	}
	updates := processed.evaluateRepositories(c)
	return updates, nil
}
