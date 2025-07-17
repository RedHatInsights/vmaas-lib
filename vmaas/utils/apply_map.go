package utils //nolint:var-naming

func ApplyMap[K comparable, V any](src []K, mapping map[K]V) []V {
	dst := make([]V, 0, len(src))
	for _, x := range src {
		dst = append(dst, mapping[x])
	}
	return dst
}
