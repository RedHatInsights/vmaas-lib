package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypeTUnmarshalJSON(t *testing.T) {
	var val TypeT
	invalidJSONs := [][]byte{[]byte(""), []byte(`""`), []byte("null")}
	justStringJSON := []byte(`"foo"`)
	stringArrayJSON := []byte(`["foo", "bar"]`)

	for _, json := range invalidJSONs {
		err := val.UnmarshalJSON(json)
		assert.Error(t, err)
	}

	err := val.UnmarshalJSON(justStringJSON)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(val))

	err = val.UnmarshalJSON(stringArrayJSON)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(val))
}

func TestSeverityTUnmarshalJSON(t *testing.T) {
	var val SeverityT
	invalidJSONs := [][]byte{[]byte(""), []byte(`""`), []byte("Foo")}
	justStringJSON := []byte(`"Low"`)
	stringArrayJSON := []byte(`["Moderate", "Critical"]`)

	for _, json := range invalidJSONs {
		err := val.UnmarshalJSON(json)
		assert.Error(t, err)
	}

	err := val.UnmarshalJSON(justStringJSON)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(val))

	err = val.UnmarshalJSON(stringArrayJSON)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(val))

	err = val.UnmarshalJSON([]byte("null"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(val))
	assert.Nil(t, val[0])
}
