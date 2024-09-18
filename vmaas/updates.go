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
	if updates == nil {
		return updates, nil
	}

	// filter out manually fixable updates from updates response
	res := Updates{
		UpdateList: make(UpdateList, len(updates.UpdateList)),
		RepoList:   updates.RepoList,
		RepoPaths:  updates.RepoPaths,
		ModuleList: updates.ModuleList,
		Releasever: updates.Releasever,
		Basearch:   updates.Basearch,
		LastChange: updates.LastChange,
	}
	for pkg, detail := range updates.UpdateList {
		updates := make([]Update, len(detail.AvailableUpdates))
		for _, u := range detail.AvailableUpdates {
			if !u.manuallyFixable {
				updates = append(updates, u)
			}
		}
		res.UpdateList[pkg] = UpdateDetail{AvailableUpdates: updates}
	}
	return &res, nil
}
