package vmaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const TestDump = "../example/vmaas.db"

func TestOpenDB(t *testing.T) {
	assert.Nil(t, db)

	err := openDB(TestDump)
	assert.Nil(t, err)
	assert.NotNil(t, db)
	assert.NotNil(t, sqlDB)

	db = nil
	sqlDB = nil
}

func TestOpenDBIncorrectFile(t *testing.T) {
	assert.Nil(t, db)
	assert.Nil(t, sqlDB)

	err := openDB("/tmp/not/valid.file")
	assert.Error(t, err)
	assert.Nil(t, db)
	assert.Nil(t, sqlDB)
}

func TestLoadCache(t *testing.T) {
	assert.Nil(t, db)
	assert.Nil(t, sqlDB)

	cache, err := loadCache(TestDump)
	assert.Nil(t, err)
	assert.NotNil(t, cache)
}
