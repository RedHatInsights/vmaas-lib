// tests copied from github.com/RedHatInsights/patchman-engine
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNevraParse(t *testing.T) {
	nevra, err := ParseNevra("389-ds-base-1.3.7-1.fc27.src", false)
	assert.Equal(t, nil, err)
	assert.Equal(t, "389-ds-base", nevra.Name)
	assert.Equal(t, "1.3.7", nevra.Version)
	assert.Equal(t, 0, nevra.Epoch)
	assert.Equal(t, "1.fc27", nevra.Release)
	assert.Equal(t, "src", nevra.Arch)

	nevra2, err := ParseNameEVRA("389-ds-base", "1.3.7-1.fc27.src", false)
	assert.Equal(t, nil, err)
	assert.Equal(t, nevra, nevra2)
}

func TestNevraParse2(t *testing.T) {
	nevra, err := ParseNevra("firefox-1:76.0.1-1.fc31.x86_64", false)
	assert.NoError(t, err)
	assert.Equal(t, "firefox", nevra.Name)
	assert.Equal(t, 1, nevra.Epoch)
	_, err = ParseNevra("kernel-5.6.13-200.fc31.x86_64", false)
	assert.NoError(t, err)
}

func TestNevraParse3(t *testing.T) {
	nevra, err := ParseNevra("connectwisecontrol-1330664eb22f9e21-0:21.14.5924.8013-.noarch", false)
	assert.NoError(t, err)
	assert.Equal(t, "connectwisecontrol-1330664eb22f9e21", nevra.Name)
	assert.Equal(t, 0, nevra.Epoch)
	assert.Equal(t, "", nevra.Release)
}

func TestNevraParse4(t *testing.T) {
	nevra1, err := ParseNevra("rh-ruby24-rubygems-2.6.14.4-92.el7.noarch", false)
	assert.Equal(t, nil, err)
	assert.Equal(t, "rh-ruby24-rubygems", nevra1.Name)
	assert.Equal(t, "2.6.14.4", nevra1.Version)
	assert.Equal(t, 0, nevra1.Epoch)
	assert.Equal(t, "92.el7", nevra1.Release)

	nevra2, err := ParseNevra("rh-ruby24-rubygems-2.6.14-90.el7.noarch", false)
	assert.Equal(t, nil, err)
	assert.Equal(t, "rh-ruby24-rubygems", nevra2.Name)
	assert.Equal(t, "2.6.14", nevra2.Version)
	assert.Equal(t, 0, nevra2.Epoch)
	assert.Equal(t, "90.el7", nevra2.Release)

	cmp := nevra1.Cmp(&nevra2)
	assert.Equal(t, 1, cmp)
}

func TestNevraParseInvalid(t *testing.T) {
	nevra, err := ParseNevra("1.3.7-1.fc27.src", false)
	assert.NotNil(t, err)
	assert.Equal(t, Nevra{}, nevra)

	nevra, err = ParseNevra("invalid", false)
	assert.NotNil(t, err)
	assert.Equal(t, Nevra{}, nevra)
}

func TestNevraCmp(t *testing.T) {
	ff0, err := ParseNevra("firefox-76.0.1-1.fc31.x86_64", false)
	assert.NoError(t, err)
	ff1, err := ParseNevra("firefox-0:76.0.1-1.fc31.x86_64", false)
	assert.NoError(t, err)
	ff2, err := ParseNevra("firefox-1:76.0.1-1.fc31.x86_64", false)
	assert.NoError(t, err)
	ff3, err := ParseNevra("firefox-1:77.0.1-1.fc31.x86_64", false)
	assert.NoError(t, err)
	ff4, err := ParseNevra("firefox-1:77.0.1-1.fc33.x86_64", false)
	assert.NoError(t, err)
	fb4, err := ParseNevra("firebird-1:77.0.1-1.fc33.x86_64", false)
	assert.NoError(t, err)

	assert.Equal(t, 0, ff0.Cmp(&ff1))
	// epoch
	assert.Equal(t, -1, ff1.Cmp(&ff2))
	// version
	assert.Equal(t, 1, ff3.Cmp(&ff2))
	// release
	assert.Equal(t, 1, ff4.Cmp(&ff3))
	// name
	assert.Equal(t, 1, ff4.Cmp(&fb4))
}

func TestNevraString(t *testing.T) {
	pkg := "389-ds-base-1.3.7-1.fc27.src"
	nevra, _ := ParseNevra(pkg, false)
	assert.Equal(t, pkg, nevra.String())
	assert.Equal(t, "389-ds-base-0:1.3.7-1.fc27.src", nevra.StringE(true))
	assert.Equal(t, "0:1.3.7-1.fc27.src", nevra.EVRAStringE(true))
	assert.Equal(t, "1.3.7-1.fc27.src", nevra.EVRAString())
	assert.Equal(t, "0:1.3.7-1.fc27", nevra.EVRStringE(true))
	assert.Equal(t, "1.3.7-1.fc27", nevra.EVRString())
}

func TestNevraString_EmptyNevra(t *testing.T) {
	nevra := Nevra{}
	assert.Equal(t, "", nevra.String())
	assert.Equal(t, "", nevra.StringE(true))
	assert.Equal(t, "", nevra.EVRAStringE(true))
	assert.Equal(t, "", nevra.EVRAString())
	assert.Equal(t, "", nevra.EVRStringE(true))
	assert.Equal(t, "", nevra.EVRString())
}

func TestGetEvr(t *testing.T) {
	nevra := Nevra{Epoch: 1, Version: "1", Release: "1"}
	evr := nevra.GetEvr()
	assert.Equal(t, evr.Epoch, 1)
	assert.Equal(t, evr.Version, "1")
	assert.Equal(t, evr.Release, "1")
}
