package utils

import (
	"math"
)

const (
	DefaultPageNumber = 1
	DefaultPageSize   = 5000
)

type PaginationDetails struct {
	PageNumber int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalPages int `json:"pages"`
}

// Paginate returns pageSize-long sub-slice of items corresponding to the pageNumber.
// For the last page, there may be fewer than pageSize items.
func Paginate[T any](slice []T, pageNumber, pageSize int) ([]T, PaginationDetails) {
	if pageNumber <= 0 {
		pageNumber = DefaultPageNumber
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}

	start := (pageNumber - 1) * pageSize
	if start > len(slice) {
		start = len(slice)
	}
	end := pageNumber * pageSize
	if end > len(slice) {
		end = len(slice)
	}
	subslice := slice[start:end]

	totalPages := int(math.Ceil(float64(len(slice))/float64(pageSize) + 1e-6))

	paginationDetails := PaginationDetails{
		PageNumber: pageNumber,
		PageSize:   len(subslice),
		TotalPages: totalPages,
	}
	return subslice, paginationDetails
}
