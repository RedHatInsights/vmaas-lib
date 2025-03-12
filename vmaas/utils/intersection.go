package utils

func Intersection[T comparable](slice []T, set map[T]bool) []T {
	isDuplicate := make(map[T]bool, len(slice))
	intersection := make([]T, 0, len(slice))
	for _, item := range slice {
		if set[item] && !isDuplicate[item] {
			intersection = append(intersection, item)
			isDuplicate[item] = true
		}
	}
	return intersection
}
