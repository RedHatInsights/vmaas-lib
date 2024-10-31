package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJSON(t *testing.T) {
	var val StringSlice
	parseToNilJSONs := [][]byte{[]byte("null"), []byte(""), []byte(`""`)}
	justStringJSON := []byte(`"foo"`)
	stringArrayJSON := []byte(`["foo", "bar"]`)

	for _, json := range parseToNilJSONs {
		err := val.UnmarshalJSON(json)
		assert.NoError(t, err)
		assert.Nil(t, val)
	}

	err := val.UnmarshalJSON(justStringJSON)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(val))

	err = val.UnmarshalJSON(stringArrayJSON)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(val))
}
