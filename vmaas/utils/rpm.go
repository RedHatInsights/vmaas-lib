package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	rpm "github.com/ezamriy/gorpm"
	"github.com/pkg/errors"
)

var (
	nevraRegex = regexp.MustCompile(
		`((?P<e1>[0-9]+):)?(?P<pn>[^:]+)-((?P<e2>[0-9]+):)?(?P<ver>[^-:]*)-(?P<rel>[^-:]*)\.(?P<arch>[a-z0-9_]*)`)
	nevraRegexIndices map[string]int
)

func init() {
	nevraRegexIndices = make(map[string]int)
	for i, name := range nevraRegex.SubexpNames() {
		if i != 0 && name != "" {
			nevraRegexIndices[name] = i
		}
	}
}

type Nevra struct {
	Name    string
	Epoch   int
	Version string
	Release string
	Arch    string
}

type Evr struct {
	Epoch   int
	Version string
	Release string
}

func ParseNevra(nevra string, epochRequired bool) (Nevra, error) {
	nevra = strings.TrimSuffix(nevra, ".rpm")
	nevra = strings.TrimSuffix(nevra, ".srpm")
	parsed := nevraRegex.FindStringSubmatch(nevra)

	if len(parsed) != 9 {
		return Nevra{}, errors.Errorf("unable to parse (%s)", nevra)
	}
	var err error
	epoch := 0
	if epochRequired {
		epoch = -1
	}
	if parsed[2] != "" {
		epoch, err = strconv.Atoi(parsed[2])
		if err != nil {
			return Nevra{}, err
		}
	} else if parsed[5] != "" {
		epoch, err = strconv.Atoi(parsed[5])
		if err != nil {
			return Nevra{}, err
		}
	}
	res := Nevra{
		Name:    parsed[3],
		Epoch:   epoch,
		Version: parsed[6],
		Release: parsed[7],
		Arch:    parsed[8],
	}
	return res, nil
}

func ParseNameEVRA(name, evra string, epochRequired bool) (Nevra, error) {
	return ParseNevra(fmt.Sprintf("%s-%s", name, evra), epochRequired)
}

func (n *Nevra) StringE(showEpoch bool) string {
	if evra := n.EVRAStringE(showEpoch); n.Name != "" && evra != "" {
		return fmt.Sprintf("%s-%s", n.Name, evra)
	}
	return ""
}

func (n *Nevra) String() string {
	return n.StringE(false)
}

func (n *Nevra) EVRStringE(showEpoch bool) string {
	if n.Epoch == 0 && n.Version == "" && n.Release == "" {
		return ""
	}
	if n.Epoch != 0 || showEpoch {
		return fmt.Sprintf("%d:%s-%s", n.Epoch, n.Version, n.Release)
	}
	return fmt.Sprintf("%s-%s", n.Version, n.Release)
}

func (n *Nevra) EVRString() string {
	return n.EVRStringE(false)
}

func (n *Nevra) EVRAStringE(showEpoch bool) string {
	if evr := n.EVRStringE(showEpoch); evr != "" {
		return fmt.Sprintf("%s.%s", evr, n.Arch)
	}
	return ""
}

func (n *Nevra) EVRAString() string {
	return n.EVRAStringE(false)
}

func (n *Nevra) EVRACmp(other *Nevra) int {
	ret := n.EVRCmp(other)
	if ret == 0 {
		ret = strings.Compare(n.Arch, other.Arch)
	}
	return ret
}

func (n *Nevra) EVRCmp(other *Nevra) int {
	evr := Evr{
		Epoch:   other.Epoch,
		Version: other.Version,
		Release: other.Release,
	}
	return n.NevraCmpEvr(evr)
}

func (n *Nevra) NevraCmpEvr(other Evr) int {
	return rpm.LabelCompare(
		&rpm.EVR{Epoch: fmt.Sprint(n.Epoch), Version: n.Version, Release: n.Release},
		&rpm.EVR{Epoch: fmt.Sprint(other.Epoch), Version: other.Version, Release: other.Release},
	)
}

func (n *Nevra) Cmp(other *Nevra) int {
	ret := strings.Compare(n.Name, other.Name)
	if ret != 0 {
		return ret
	}
	return n.EVRACmp(other)
}

func (n *Nevra) GetEvr() Evr {
	return Evr{
		Epoch:   n.Epoch,
		Version: n.Version,
		Release: n.Release,
	}
}
