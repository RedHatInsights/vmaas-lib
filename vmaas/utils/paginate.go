package utils

const (
	DefaultPageNumber = 1
	DefaultPageSize   = 5000
)

type PaginationRequest struct {
	PageNumber int `json:"page" example:"1"`
	PageSize   int `json:"page_size" example:"10"`
}

type Pagination struct {
	PageNumber int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalPages int `json:"pages"`
}

// Paginate returns pagination.PageSize-long sub-slice of items corresponding to the pagination.PageNumber.
// For the last page, there may be fewer than pagination.PageSize items.
func Paginate[T any](slice []T, req PaginationRequest) ([]T, Pagination) {
	number := max(DefaultPageNumber, req.PageNumber)
	size := req.PageSize
	if size <= 0 {
		size = DefaultPageSize
	}

	length := len(slice)
	start := min((number-1)*size, length)
	end := min(number*size, length)
	subslice := slice[start:end]

	pagination := Pagination{
		PageNumber: number,
		PageSize:   len(subslice),
		TotalPages: (length + size - 1) / size,
	}
	return subslice, pagination
}
