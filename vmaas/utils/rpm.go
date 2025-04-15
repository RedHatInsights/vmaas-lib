package utils

import (
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
	return ParseNevra(name+"-"+evra, epochRequired)
}

func (n *Nevra) String() string {
	return n.StringE(false)
}

func (n *Nevra) StringE(showEpoch bool) string {
	var builder strings.Builder
	err := n.stringE(&builder, showEpoch)
	if err != nil {
		return ""
	}
	return builder.String()
}

func (n *Nevra) stringE(builder *strings.Builder, showEpoch bool) error {
	if n.Name == "" {
		return errors.New("missing nevra name")
	}

	// push name
	builder.WriteString(n.Name)
	builder.WriteByte('-')

	// push evra
	return n.evraStringE(builder, showEpoch)
}

func (n *Nevra) EVRAString() string {
	return n.EVRAStringE(false)
}

func (n *Nevra) EVRAStringE(showEpoch bool) string {
	var builder strings.Builder
	err := n.evraStringE(&builder, showEpoch)
	if err != nil {
		return ""
	}
	return builder.String()
}

func (n *Nevra) evraStringE(builder *strings.Builder, showEpoch bool) error {
	// push evr
	err := n.evrStringE(builder, showEpoch)
	if err != nil {
		return err
	}

	// push arch
	builder.WriteByte('.')
	builder.WriteString(n.Arch)
	return nil
}

func (n *Nevra) EVRString() string {
	return n.EVRStringE(false)
}

func (n *Nevra) EVRStringE(showEpoch bool) string {
	var builder strings.Builder
	err := n.evrStringE(&builder, showEpoch)
	if err != nil {
		return ""
	}
	return builder.String()
}

func (n *Nevra) evrStringE(builder *strings.Builder, showEpoch bool) error {
	if n.Epoch == 0 && n.Version == "" && n.Release == "" {
		return errors.New("empty nevra evr")
	}

	// push evr
	if n.Epoch != 0 || showEpoch {
		builder.WriteString(strconv.Itoa(n.Epoch))
		builder.WriteByte(':')
	}
	builder.WriteString(n.Version)
	builder.WriteByte('-')
	builder.WriteString(n.Release)
	return nil
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
		&rpm.EVR{Epoch: strconv.Itoa(n.Epoch), Version: n.Version, Release: n.Release},
		&rpm.EVR{Epoch: strconv.Itoa(other.Epoch), Version: other.Version, Release: other.Release},
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
