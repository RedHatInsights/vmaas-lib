package vmaas

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type (
	RepoID        int
	PkgID         int
	NameID        int
	EvrID         int
	ArchID        int
	ErratumID     int
	ContentSetID  int
	CpeID         int
	CpeLabel      string
	CSAFProductID int
	CSAFCVEID     int
	CVEID         int
)

type Request struct {
	Packages []string  `json:"package_list"`
	Repos    *[]string `json:"repository_list"`
	// we need to use pointers to modules to distinguish between nil and ""
	// to keep consistency with python implementation
	Modules    []ModuleStreamPtrs `json:"modules_list"`
	Releasever *string            `json:"releasever"`
	Basearch   *string            `json:"basearch"`
	RepoPaths  []string           `json:"repository_paths"`

	ThirdParty   bool `json:"third_party"`
	LatestOnly   bool `json:"latest_only"`
	SecurityOnly bool `json:"security_only"`

	Extended      bool `json:"extended"`
	EpochRequired bool `json:"epoch_required"`
}

type CvesRequest struct {
	Cves                []string   `json:"cve_list"`
	PublishedSince      *time.Time `json:"published_since"`
	ModifiedSince       *time.Time `json:"modified_since"`
	RHOnly              bool       `json:"rh_only"`
	AreErrataAssociated bool       `json:"errata_associated"`
	ThirdParty          bool       `json:"third_party"`
}

type Update struct {
	Package     string `json:"package"`
	PackageName string `json:"package_name"`
	EVRA        string `json:"evra"`
	Erratum     string `json:"erratum"`
	Repository  string `json:"repository"`
	Basearch    string `json:"basearch"`
	Releasever  string `json:"releasever"`
	// helper for sorting
	nevra utils.Nevra `json:"-"`
	// helper to determine manually fixable errata/cves
	manuallyFixable bool `json:"-"`
}

type UpdateDetail struct {
	AvailableUpdates []Update `json:"available_updates,omitempty"`
}

type UpdateList map[string]UpdateDetail

type Updates struct {
	UpdateList UpdateList     `json:"update_list"`
	RepoList   *[]string      `json:"repository_list,omitempty"`
	RepoPaths  []string       `json:"repository_paths,omitempty"`
	ModuleList []ModuleStream `json:"modules_list,omitempty"`
	Releasever *string        `json:"releasever,omitempty"`
	Basearch   *string        `json:"basearch,omitempty"`
	LastChange time.Time      `json:"last_change"`
}

type Vulnerability string

type VulnerabilityDetail struct {
	CVE      string `json:"cve"`
	Packages map[string]bool
	Errata   map[string]bool
	Affected []AffectedPackage `json:"affected,omitempty"`
}

// marshal VulnerabilityDetail Packages and Errata as json arrays for backward compatibility
func (d VulnerabilityDetail) MarshalJSON() ([]byte, error) {
	var out struct {
		CVE      string            `json:"cve"`
		Packages []string          `json:"affected_packages"`
		Errata   []string          `json:"errata"`
		Affected []AffectedPackage `json:"affected,omitempty"`
	}
	out.CVE = d.CVE
	out.Packages = make([]string, 0, len(d.Packages))
	out.Errata = make([]string, 0, len(d.Errata))
	out.Affected = d.Affected
	for p := range d.Packages {
		out.Packages = append(out.Packages, p)
	}
	sort.Strings(out.Packages)

	for e := range d.Errata {
		out.Errata = append(out.Errata, e)
	}
	sort.Strings(out.Errata)

	return json.Marshal(out)
}

type AffectedPackage struct {
	Name string   `json:"package_name"`
	EVRA string   `json:"evra"`
	Cpe  CpeLabel `json:"cpe"`
	ModuleStreamPtrs
}

type Vulnerabilities struct {
	CVEs                []Vulnerability `json:"cve_list"`
	ManuallyFixableCVEs []Vulnerability `json:"manually_fixable_cve_list"`
	UnpatchedCVEs       []Vulnerability `json:"unpatched_cve_list"`
	LastChange          time.Time       `json:"last_change"`
}

type VulnerabilitiesExtended struct {
	CVEs                []VulnerabilityDetail `json:"cve_list"`
	ManuallyFixableCVEs []VulnerabilityDetail `json:"manually_fixable_cve_list"`
	UnpatchedCVEs       []VulnerabilityDetail `json:"unpatched_cve_list"`
	LastChange          time.Time             `json:"last_change"`
}

type NevraIDs struct {
	NameID NameID
	EvrIDs []int
	ArchID ArchID
}

type PackageDetail struct {
	NameID        NameID
	EvrID         EvrID
	ArchID        ArchID
	SummaryID     int
	DescriptionID int

	SrcPkgID   *PkgID
	Modified   *time.Time
	ModifiedID int
}

type Nevra struct {
	NameID NameID
	EvrID  EvrID
	ArchID ArchID
}

type RepoDetail struct {
	Label      string
	Name       string
	URL        string
	Basearch   string
	Releasever string
	Product    string
	ProductID  int
	Revision   *string
	LastChange *string
	ThirdParty bool
}

type CveDetail struct {
	Name          string     `json:"synopsis"`
	RedHatURL     string     `json:"redhat_url"`
	SecondaryURL  string     `json:"secondary_url"`
	Cvss3Score    string     `json:"cvss3_score"`
	Cvss3Metrics  string     `json:"cvss3_metrics"`
	Impact        string     `json:"impact"`
	PublishedDate *time.Time `json:"public_date"`
	ModifiedDate  *time.Time `json:"modified_date"`
	Iava          string     `json:"-"`
	Description   string     `json:"description"`
	Cvss2Score    string     `json:"cvss2_score"`
	Cvss2Metrics  string     `json:"cvss2_metrics"`
	Source        string     `json:"-"`

	CWEs      []string `json:"cwe_list"`
	PkgIDs    []int    `json:"-"`
	ErrataIDs []int    `json:"-"`

	Errata         []string `json:"errata_list"`
	Packages       []string `json:"package_list"`
	SourcePackages []string `json:"source_package_list"`
}

type PkgErratum struct {
	PkgID     PkgID
	ErratumID ErratumID
}

type Module struct {
	Name              string
	StreamID          int
	Stream            string
	Version           string
	Context           string
	PackageList       []string
	SourcePackageList []string
}

type ModuleStream struct {
	Module string `json:"module_name"`
	Stream string `json:"module_stream"`
}

type ModuleStreamPtrs struct {
	Module *string `json:"module_name"`
	Stream *string `json:"module_stream"`
}

type DBChange struct {
	ErrataChanges string `json:"errata_changes"`
	CveChanges    string `json:"cve_changes"`
	RepoChanges   string `json:"repository_changes"`
	LastChange    string `json:"last_change"`
	Exported      string `json:"exported"`
}

type ErratumDetail struct {
	ID             ErratumID
	Synopsis       string
	Summary        *string
	Type           string
	Severity       *string
	Description    *string
	CVEs           []string
	PkgIDs         []int
	ModulePkgIDs   []int
	Bugzillas      []string
	Refs           []string
	Modules        []Module
	Solution       *string
	Issued         *string
	Updated        *string
	URL            string
	ThirdParty     bool
	RequiresReboot bool
}

type NameArch struct {
	Name string
	Arch string
}

type NevraString struct {
	Nevra utils.Nevra
	Pkg   string
}

type CSAFProduct struct {
	CpeID         CpeID
	PackageNameID NameID
	PackageID     PkgID
	ModuleStream  ModuleStream
}

type CSAFCVEProduct struct {
	CVEID         CVEID
	CSAFProductID CSAFProductID
}

type CSAFCVEs struct {
	Fixed   []CVEID
	Unfixed []CVEID
}

// Implement the Scan method for the ModuleStream type
func (ms *ModuleStream) Scan(value interface{}) error {
	if value == nil || value == "" {
		return nil
	}

	// Convert the value to string
	strValue, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected type %T for ModuleStream", value)
	}

	// Split the string into module and stream parts
	parts := strings.Split(strValue, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for ModuleStream: %s", strValue)
	}

	ms.Module = parts[0]
	ms.Stream = parts[1]

	return nil
}

type ParsedCpe struct {
	Part     *string
	Vendor   *string
	Product  *string
	Version  *string
	Update   *string
	Edition  *string
	Language *string
}

func (l CpeLabel) Parse() (*ParsedCpe, error) {
	if !strings.HasPrefix(string(l), "cpe:/") {
		return nil, errors.New("cpe doesn't start with `cpe:/`")
	}
	trimmed := strings.TrimPrefix(string(l), "cpe:/")
	splitted := strings.Split(trimmed, ":")
	if len(splitted) > 7 {
		return nil, errors.New("too many cpe components")
	}

	parsed := make([]*string, 7)
	for i, component := range splitted {
		component := component
		if len(component) > 0 {
			parsed[i] = &component
		}
	}
	res := &ParsedCpe{
		Part:     parsed[0],
		Vendor:   parsed[1],
		Product:  parsed[2],
		Version:  parsed[3],
		Update:   parsed[4],
		Edition:  parsed[5],
		Language: parsed[6],
	}
	return res, nil
}

func (l *ParsedCpe) match(r *ParsedCpe) bool {
	cmp := func(l, r *string) bool {
		if l != nil && r == nil {
			return false
		}
		if l != nil && r != nil && !strings.HasPrefix(*r, *l) {
			return false
		}
		return true
	}

	if l.Part != nil && r.Part == nil {
		return false
	}
	if l.Part != nil && r.Part != nil && *l.Part != "o" && *r.Part == "o" {
		// treat "o" as a superset
		return false
	}

	if !cmp(l.Vendor, r.Vendor) {
		return false
	}
	if !cmp(l.Product, r.Product) {
		return false
	}
	if !cmp(l.Version, r.Version) {
		return false
	}
	if !cmp(l.Update, r.Update) {
		return false
	}
	if !cmp(l.Edition, r.Edition) {
		return false
	}
	return cmp(l.Language, r.Language)
}

type CpeIDNameID struct {
	CpeID  CpeID
	NameID NameID
}
