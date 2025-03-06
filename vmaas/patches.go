package vmaas

import (
	"github.com/pkg/errors"
)

type Patches struct {
	Errata     []string `json:"errata_list"`
	LastChange string   `json:"last_change"`
}

func extractUpdatesErrata(updates *Updates) []string {
	errata := []string{}
	if updates == nil {
		return errata
	}
	for _, updateDetail := range updates.UpdateList {
		for _, update := range updateDetail.AvailableUpdates {
			errata = append(errata, update.Erratum)
		}
	}
	return errata
}

func (r *Request) patches(c *Cache, opts *options) (*Patches, error) {
	packages := r.Packages
	if len(packages) == 0 {
		return &Patches{}, errors.Wrap(ErrProcessingInput, "'package_list' is a required property")
	}

	r.SecurityOnly = false
	updates, err := r.updates(c, opts)
	if err != nil {
		return &Patches{}, err
	}

	res := Patches{
		Errata:     extractUpdatesErrata(updates),
		LastChange: c.DBChange.LastChange,
	}
	return &res, nil
}
