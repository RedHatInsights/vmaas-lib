package vmaas

import (
	"os"
	"testing"

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
