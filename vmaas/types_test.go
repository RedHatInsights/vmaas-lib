package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJSON(t *testing.T) {
	var val StringSlice
	invalidJSONs := [][]byte{[]byte(""), []byte(`""`)}
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

	err = val.UnmarshalJSON([]byte("null"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(val))
	assert.Equal(t, "", val[0])
}

func TestMarshalJSON(t *testing.T) {
	var val StringSlice

	bytes, err := val.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "null", string(bytes))

	val = StringSlice{}
	bytes, err = val.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "[]", string(bytes))

	val = StringSlice{"foo", "", "buz"}
	bytes, err = val.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, `["foo",null,"buz"]`, string(bytes))
}
