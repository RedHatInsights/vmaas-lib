package vmaas

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVmaasVersion_EmptyPath(t *testing.T) {
	opts := &options{
		vmaasVersionFilePath: "",
	}

	result := vmaasVersion(opts)

	assert.Nil(t, result)
}

func TestVmaasVersion_FileNotExists(t *testing.T) {
	opts := &options{
		vmaasVersionFilePath: "/nonexistent/path/version.txt",
	}

	result := vmaasVersion(opts)

	assert.Nil(t, result)
}

func TestVmaasVersion_ValidFile(t *testing.T) {
	// Create a temporary file with version content
	tmpDir := t.TempDir()
	versionFile := filepath.Join(tmpDir, "version.txt")
	expectedContent := "1.2.3"

	err := os.WriteFile(versionFile, []byte(expectedContent), 0644)
	assert.NoError(t, err)

	opts := &options{
		vmaasVersionFilePath: versionFile,
	}

	result := vmaasVersion(opts)

	assert.NotNil(t, result)
	assert.Equal(t, expectedContent, *result)
}

func TestVmaasVersion_ValidFileWithNewline(t *testing.T) {
	// Test that newlines are preserved
	tmpDir := t.TempDir()
	versionFile := filepath.Join(tmpDir, "version.txt")
	expectedContent := "1.2.3\n"

	err := os.WriteFile(versionFile, []byte(expectedContent), 0644)
	assert.NoError(t, err)

	opts := &options{
		vmaasVersionFilePath: versionFile,
	}

	result := vmaasVersion(opts)

	assert.NotNil(t, result)
	assert.Equal(t, expectedContent, *result)
}
