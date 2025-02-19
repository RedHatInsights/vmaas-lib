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

//nolint:funlen
func TestParsedCpeCmpByVersion(t *testing.T) {
	// Helper to create a string pointer.
	sp := func(s string) *string {
		return &s
	}

	tests := []struct {
		name string
		l    ParsedCpe
		r    ParsedCpe
		// expected outcome: negative if l < r, 0 if equal, positive if l > r.
		cmp int
	}{
		{
			name: "all fields nil",
			l:    ParsedCpe{},
			r:    ParsedCpe{},
			cmp:  0,
		},
		{
			name: "l version '8' > r version '8.8'",
			l:    ParsedCpe{Version: sp("8")},
			r:    ParsedCpe{Version: sp("8.8")},
			cmp:  1,
		},
		{
			name: "l version '8.8' < r version '8'",
			l:    ParsedCpe{Version: sp("8.8")},
			r:    ParsedCpe{Version: sp("8")},
			cmp:  -1,
		},
		{
			name: "same version, different Part",
			l:    ParsedCpe{Version: sp("8.8"), Part: sp("a")},
			r:    ParsedCpe{Version: sp("8.8"), Part: sp("b")},
			cmp:  -1,
		},
		{
			name: "same version and part, different Vendor",
			l:    ParsedCpe{Version: sp("8.8"), Part: sp("a"), Vendor: sp("aaa")},
			r:    ParsedCpe{Version: sp("8.8"), Part: sp("a"), Vendor: sp("bbb")},
			cmp:  -1,
		},
		{
			name: "compare Product field",
			l:    ParsedCpe{Version: sp("8.8"), Part: sp("a"), Vendor: sp("aaa"), Product: sp("foo")},
			r:    ParsedCpe{Version: sp("8.8"), Part: sp("a"), Vendor: sp("aaa"), Product: sp("zoo")},
			cmp:  -1,
		},
		{
			name: "compare Update field",
			l:    ParsedCpe{Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"), Product: sp("foo"), Update: sp("u1")},
			r:    ParsedCpe{Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"), Product: sp("foo"), Update: sp("u2")},
			cmp:  -1,
		},
		{
			name: "compare Edition field",
			l: ParsedCpe{
				Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"),
				Product: sp("foo"), Update: sp("u1"), Edition: sp("e1"),
			},
			r: ParsedCpe{
				Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"),
				Product: sp("foo"), Update: sp("u1"), Edition: sp("e2"),
			},
			cmp: -1,
		},
		{
			name: "compare Language field",
			l: ParsedCpe{
				Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"),
				Product: sp("foo"), Update: sp("u1"), Edition: sp("e1"), Language: sp("en"),
			},
			r: ParsedCpe{
				Version: sp("1.0.0"), Part: sp("a"), Vendor: sp("aaa"),
				Product: sp("foo"), Update: sp("u1"), Edition: sp("e1"), Language: sp("fr"),
			},
			cmp: -1,
		},
		{
			name: "handle version with dot vs without dot",
			l:    ParsedCpe{Version: sp("8")},
			r:    ParsedCpe{Version: sp("8.0")},
			cmp:  1, // "8" becomes "8.999" so it is considered greater than "8.0"
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.l.CmpByVersion(&tc.r)
			assert.Equal(t, tc.cmp, result)
		})
	}
}

func TestParsedCpeCmpByVersion_VersionParsingError(t *testing.T) {
	// Test that if version parsing fails, it uses a zero-version.
	// Here, an invalid version string is forced by a non-numeric version.
	sp := func(s string) *string {
		return &s
	}

	l := ParsedCpe{
		Version: sp("not-a-version"),
		Part:    sp("a"),
	}
	r := ParsedCpe{
		Version: sp("another-bad-version"),
		Part:    sp("a"),
	}

	result := l.CmpByVersion(&r)
	// Both versions should fallback to new(version.Version) therefore they are equal
	assert.Equal(t, 0, result)
}
