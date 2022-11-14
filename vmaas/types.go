package vmaas

import (
	"time"

	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type RepoID int
type PkgID int
type NameID int
type EvrID int
type ArchID int
type ErrataID int
type ContentSetID int
type DefinitionID int
type CpeID int
type CriteriaID int
type TestID int
type ModuleTestID int
type OvalStateID int

type Request struct {
	Packages   []string       `json:"package_list"`
	Repos      []string       `json:"repository_list"`
	Modules    []ModuleStream `json:"modules_list"`
	Releasever *string        `json:"releasever"`
	Basearch   *string        `json:"basearch"`

	ThirdParty   bool `json:"thirdparty"`
	Optimistic   bool `json:"optimistic_updates"`
	LatestOnly   bool `json:"latest_only"`
	SecurityOnly bool `json:"security_only"`

	Extended bool `json:"extended"`
}

type Update struct {
	Package    string  `json:"package"`
	Erratum    string  `json:"erratum"`
	Repository string  `json:"repository"`
	Basearch   *string `json:"basearch"`
	Releasever *string `json:"releasever"`
}

type UpdateDetail struct {
	AvailableUpdates []Update `json:"available_updates,omitempty"`
}

type UpdateList map[string]UpdateDetail

type Updates struct {
	UpdateList UpdateList     `json:"update_list"`
	RepoList   []string       `json:"repository_list,omitempty"`
	ModuleList []ModuleStream `json:"modules_list,omitempty"`
	Releasever *string        `json:"releasever,omitempty"`
	BaseArch   *string        `json:"basearch,omitempty"`
	LastChange time.Time      `json:"last_change"`
}

type Vulnerability string

type VulnerabilityDetail struct {
	CVE      string   `json:"cve"`
	Packages []string `json:"affected_packages"`
	Errata   []string `json:"errata"`
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
	NameId        NameID
	EvrId         EvrID
	ArchId        ArchID
	SummaryId     int
	DescriptionId int

	SrcPkgId   *PkgID
	Modified   *time.Time
	ModifiedID int
}

type Nevra struct {
	NameId NameID
	EvrId  EvrID
	ArchId ArchID
}

type RepoDetail struct {
	Label      string
	Name       string
	Url        string
	BaseArch   *string
	ReleaseVer *string
	Product    string
	ProductId  int
	Revision   *string
	ThirdParty bool
}

type CveDetail struct {
	RedHatUrl     *string
	SecondaryUrl  *string
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
	PkgIds    []int
	ErrataIds []int
}

type PkgErrata struct {
	PkgId    int
	ErrataId int
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

type DbChange struct {
	ErrataChanges string `json:"errata_changes"`
	CveChanges    string `json:"cve_changes"`
	RepoChanges   string `json:"repository_changes"`
	LastChange    string `json:"last_change"`
	Exported      string `json:"exported"`
}

type ErrataDetail struct {
	ID             ErrataID
	Synopsis       string
	Summary        *string
	Type           string
	Severity       *string
	Description    *string
	CVEs           []string
	PkgIds         []int
	ModulePkgIds   []int
	Bugzillas      []string
	Refs           []string
	Modules        []Module
	Solution       *string
	Issued         *string
	Updated        *string
	Url            string
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
