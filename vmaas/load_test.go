package vmaas

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const TestDump = "../example/vmaas.db"

func TestOpenDB(t *testing.T) {
	assert.Nil(t, sqlDB)

	err := openDB(TestDump)
	assert.Nil(t, err)
	assert.NotNil(t, sqlDB)

	sqlDB = nil
}

func TestOpenDBNotExists(t *testing.T) {
	assert.Nil(t, sqlDB)

	err := openDB("/tmp/does/not/exists/valid.file")
	assert.Error(t, err)
	assert.Nil(t, sqlDB)
}

func TestOpenDBEmpty(t *testing.T) {
	assert.Nil(t, sqlDB)

	fd, err := os.CreateTemp("/tmp", "empty.db")
	if err != nil {
		assert.Fail(t, "couldn't create file")
	}
	defer fd.Close()

	err = openDB("/tmp/empty.db")
	assert.Error(t, err)
	assert.Nil(t, sqlDB)
}

func TestLoadCache(t *testing.T) {
	assert.Nil(t, sqlDB)

	cache, err := loadCache(TestDump, &defaultOpts)
	assert.Nil(t, err)
	assert.NotNil(t, cache)
}

func TestBuildIndexes(t *testing.T) {
	t1, _ := time.Parse(time.RFC3339, "2025-01-20T13:41:00+02:00")
	t2, _ := time.Parse(time.RFC3339, "2025-01-21T13:41:00+02:00")
	c := Cache{
		PackageDetails: map[PkgID]PackageDetail{
			1: {Modified: &t2},
			2: {Modified: nil},
			3: {Modified: &t1},
		},
	}
	buildIndexes(&c)
	assert.NotNil(t, c.PackageDetailsModifiedIndex)
	assert.Equal(t, PkgID(3), c.PackageDetailsModifiedIndex[1])
	assert.Equal(t, PkgID(1), c.PackageDetailsModifiedIndex[2])
}
