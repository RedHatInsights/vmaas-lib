package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBool2Int(t *testing.T) {
	res := Bool2Int(true)
	assert.Equal(t, 1, res)
	res = Bool2Int(false)
	assert.Equal(t, 0, res)
}

func TestApplyMap_StringToInt(t *testing.T) {
	src := []string{"a", "b", "c"}
	mapping := map[string]int{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	result := ApplyMap(src, mapping)

	expected := []int{1, 2, 3}
	assert.Equal(t, expected, result)
}

func TestApplyMap_IntToString(t *testing.T) {
	src := []int{1, 2, 3}
	mapping := map[int]string{
		1: "one",
		2: "two",
		3: "three",
	}

	result := ApplyMap(src, mapping)

	expected := []string{"one", "two", "three"}
	assert.Equal(t, expected, result)
}

func TestApplyMap_EmptySlice(t *testing.T) {
	src := []string{}
	mapping := map[string]int{
		"a": 1,
		"b": 2,
	}

	result := ApplyMap(src, mapping)

	assert.Empty(t, result)
	assert.Equal(t, []int{}, result)
}

func TestApplyMap_EmptyMapping(t *testing.T) {
	src := []string{"a", "b"}
	mapping := map[string]int{}

	result := ApplyMap(src, mapping)

	// This will contain zero values since keys aren't in the map
	expected := []int{0, 0}
	assert.Equal(t, expected, result)
}

func TestApplyMap_DuplicateKeys(t *testing.T) {
	src := []string{"a", "b", "a", "c", "b"}
	mapping := map[string]int{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	result := ApplyMap(src, mapping)

	expected := []int{1, 2, 1, 3, 2}
	assert.Equal(t, expected, result)
}

func TestApplyMap_BoolToString(t *testing.T) {
	src := []bool{true, false, true}
	mapping := map[bool]string{
		true:  "yes",
		false: "no",
	}

	result := ApplyMap(src, mapping)

	expected := []string{"yes", "no", "yes"}
	assert.Equal(t, expected, result)
}
