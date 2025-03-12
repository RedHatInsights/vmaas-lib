package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntersection(t *testing.T) {
	slice := []string{"a", "b", "b", "c"}
	set := map[string]bool{
		"b": true,
		"c": true,
	}
	res := Intersection(slice, set)
	assert.Equal(t, 2, len(res))
}
