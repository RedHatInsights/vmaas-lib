package vmaas

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type (
	RepoID       int
	PkgID        int
	NameID       int
	EvrID        int
	ArchID       int
	ErratumID    int
	ContentSetID int
	DefinitionID int
	CpeID        int
	CriteriaID   int
	TestID       int
	ModuleTestID int
	OvalStateID  int
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
	Name string `json:"package_name"`
	EVRA string `json:"evra"`
	Cpe  string `json:"cpe"`
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
	RedHatURL     *string
	SecondaryURL  *string
	Cvss3Score    *string
	Cvss3Metrics  *string
	Impact        string
	PublishedDate *string
	ModifiedDate  *string
	Iava          *string
	Description   string
	Cvss2Score    *string
	Cvss2Metrics  *string
	Source        string

	CWEs      []string
	PkgIDs    []int
	ErrataIDs []int
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

type DefinitionDetail struct {
	ID               DefinitionID
	DefinitionTypeID int
	CriteriaID       CriteriaID
}

type OvalTestDetail struct {
	PkgNameID      NameID
	CheckExistence int
}

type OvalModuleTestDetail struct {
	ModuleStream ModuleStream
}

type OvalState struct {
	ID           OvalStateID
	EvrID        EvrID
	OperationEvr int
}

type NameArch struct {
	Name string
	Arch string
}

type NevraString struct {
	Nevra utils.Nevra
	Pkg   string
}
