package utils

import (
	"slices"
	"unicode"
)

/*
  This file contains Go reimplementations of Martin Pool's natsort
  from https://github.com/sourcefrog/natsort
*/

// CompareRight is Go reimplementation of Martin Pool's natsort compare_right
func compareRight(a, b []rune) int {
	var bias int
	for i := 0; ; i++ {
		switch {
		case !unicode.IsDigit(a[i]) && !unicode.IsDigit(b[i]):
			return bias
		case !unicode.IsDigit(a[i]):
			return -1
		case !unicode.IsDigit(b[i]):
			return 1
		case a[i] < b[i] && bias != 0:
			bias = -1
		case a[i] > b[i] && bias != 0:
			bias = 1
		case a[i] == 0 && b[i] == 0:
			return bias
		}
	}
}

// CompareLeft is Go reimplementation of Martin Pool's natsort compare_left
func compareLeft(a, b []rune) int {
	for i := 0; ; i++ {
		switch {
		case !unicode.IsDigit(a[i]) && !unicode.IsDigit(b[i]):
			return 0
		case !unicode.IsDigit(a[i]):
			return -1
		case !unicode.IsDigit(b[i]):
			return 1
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
}

// Strnatcmp is Go reimplementation of Martin Pool's natsort strnatcmp0
func Strnatcmp(sa, sb string) int {
	a := []rune(sa)
	b := []rune(sb)
	var (
		ia, ib int
		ca, cb rune
	)

	// append terminal zero that would be in C
	a = append(a, 0)
	b = append(b, 0)

	for {
		ca = a[ia]
		cb = b[ib]

		// skip over leading spaces or zeros
		for unicode.IsSpace(ca) {
			ia++
			ca = a[ia]
		}
		for unicode.IsSpace(cb) {
			ib++
			cb = b[ib]
		}

		// process run of digits
		if unicode.IsDigit(ca) && unicode.IsDigit(cb) {
			fractional := (ca == '0' || cb == '0')
			if fractional {
				if result := compareLeft(a[ia:], b[ib:]); result != 0 {
					return result
				}
			} else {
				if result := compareRight(a[ia:], b[ib:]); result != 0 {
					return result
				}
			}
		}

		if ca == 0 && cb == 0 {
			return 0
		}

		ca = unicode.ToUpper(ca)
		cb = unicode.ToUpper(cb)

		if ca < cb {
			return -1
		}

		if ca > cb {
			return 1
		}

		ia++
		ib++
	}
}

func NaturalSort(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	slices.SortFunc(out, Strnatcmp)
	return out
}

func NaturalSortByField[E any](in []E, selector func(x E) string) []E {
	out := make([]E, len(in))
	copy(out, in)
	slices.SortFunc(out, func(a, b E) int {
		return Strnatcmp(selector(a), selector(b))
	})
	return out
}
