package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPaginate(t *testing.T) {
	slice := []int{42, 43, 44, 45, 46}

	// empty slice
	subslice, paginationDetails := Paginate([]int{}, 1, 2)
	assert.Equal(t, 0, len(subslice))
	assert.Equal(t, 1, paginationDetails.PageNumber)
	assert.Equal(t, 0, paginationDetails.PageSize)
	assert.Equal(t, 1, paginationDetails.TotalPages)

	// use default values of pageNumber and pageSize
	subslice, paginationDetails = Paginate(slice, 0, -1)
	assert.Equal(t, len(slice), len(subslice))
	assert.Equal(t, 1, paginationDetails.PageNumber)
	assert.LessOrEqual(t, paginationDetails.PageSize, 5000)

	// usual case
	subslice, paginationDetails = Paginate(slice, 2, 2)
	assert.Equal(t, 2, len(subslice))
	assert.Equal(t, 44, subslice[0])
	assert.Equal(t, 45, subslice[1])
	assert.Equal(t, 2, paginationDetails.PageNumber)
	assert.Equal(t, 2, paginationDetails.PageSize)
	assert.Equal(t, 3, paginationDetails.TotalPages)

	// the last page
	subslice, paginationDetails = Paginate(slice, 2, 3)
	assert.LessOrEqual(t, len(subslice), 3)
}
