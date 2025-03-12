package vmaas

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
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
	SeverityT     []*string
	TypeT         []string
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

type PaginationRequest struct {
	PageNumber int `json:"page"`
	PageSize   int `json:"page_size"`
}

type CvesRequest struct {
	Cves                []string   `json:"cve_list"`
	PublishedSince      *time.Time `json:"published_since"`
	ModifiedSince       *time.Time `json:"modified_since"`
	RHOnly              bool       `json:"rh_only"`
	AreErrataAssociated bool       `json:"errata_associated"`
	ThirdParty          bool       `json:"third_party"`
	PageNumber          int        `json:"page"`
	PageSize            int        `json:"page_size"`
}
type PkgListRequest struct {
	ModifiedSince  *time.Time `json:"modified_since"`
	ReturnModified bool       `json:"return_modified"`
	PageNumber     int        `json:"page"`
	PageSize       int        `json:"page_size"`
}

type PkgTreeRequest struct {
	PackageNames       []string   `json:"package_name_list"`
	ModifiedSince      *time.Time `json:"modified_since"`
	ThirdParty         bool       `json:"third_party"`
	ReturnRepositories *bool      `json:"return_repositories"`
	ReturnErrata       *bool      `json:"return_errata"`
	ReturnSummary      bool       `json:"return_summary"`
	ReturnDescription  bool       `json:"return_description"`
	PaginationRequest
}

// UnmarshalJSON is ment only for TypeT.UnmarshalJSON and SeverityT.UnmarshalJSON
func unmarshalJSON[T string | *string](dst *[]T, data []byte) error {
	if string(data) == `""` || string(data) == `''` || len(data) == 0 {
		return errors.Wrap(ErrProcessingInput, "invalid severity or type: ''")
	}

	if data[0] == '[' {
		var val []T
		err := json.Unmarshal(data, &val)
		if err != nil {
			return errors.Wrap(ErrProcessingInput, err.Error())
		}
		*dst = val
		return nil
	}

	if data[0] == '"' {
		var val T
		err := json.Unmarshal(data, &val)
		if err != nil {
			return errors.Wrap(ErrProcessingInput, err.Error())
		}
		*dst = []T{val}
		return nil
	}

	return errors.Wrap(ErrProcessingInput, "failed to unmarshall severity or type")
}

func (slice *SeverityT) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*slice = []*string{nil}
		return nil
	}

	var res []*string
	err := unmarshalJSON(&res, data)
	if err != nil {
		return err
	}

	for _, item := range res {
		if item != nil && !slices.Contains(
			[]string{LowCveImpact, ModerateCveImpact, ImportantCveImpact, CriticalCveImpact},
			*item,
		) {
			return errors.Wrapf(ErrProcessingInput, "invalid severity value: '%s'", *item)
		}
	}

	*slice = res
	return nil
}

// Contains returns true if item is nil and slice contains nil,
// or if the value pointed to by item is equal to a value pointed to by x from slice.
func (slice SeverityT) contains(item *string) bool {
	for _, x := range slice {
		if x == nil && item == nil {
			return true
		}
		if x != nil && item != nil && *x == *item {
			return true
		}
	}
	return false
}

func (slice *TypeT) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return errors.Wrap(ErrProcessingInput, "invalid type: 'null'")
	}

	var res []string
	err := unmarshalJSON(&res, data)
	if err != nil {
		return err
	}
	*slice = res
	return nil
}

type ErrataRequest struct {
	Errata        []string   `json:"errata_list"`
	ModifiedSince *time.Time `json:"modified_since"`
	ThirdParty    bool       `json:"third_party"`
	Type          TypeT      `json:"type"`
	Severity      SeverityT  `json:"severity"`
	PageNumber    int        `json:"page"`
	PageSize      int        `json:"page_size"`
}

type ReposRequest struct {
	Repos         []string   `json:"repository_list"`
	ModifiedSince *time.Time `json:"modified_since"`
	ThirdParty    bool       `json:"third_party"`
	ShowPackages  bool       `json:"show_packages"`
	HasPackages   bool       `json:"has_packages"`
	PageNumber    int        `json:"page"`
	PageSize      int        `json:"page_size"`
}

type PackagesRequest struct {
	Packages   []string `json:"package_list"`
	ThirdParty bool     `json:"third_party"`
}

type RPMPkgNamesRequest struct {
	RPMNames    []string `json:"rpm_name_list"`
	ContentSets []string `json:"content_set_list"`
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

type RepoDetailCommon struct {
	Label      string `json:"label"`
	Name       string `json:"name"`
	Basearch   string `json:"basearch"`
	Releasever string `json:"releasever"`
}

type RepoDetail struct {
	RepoDetailCommon
	URL        string     `json:"url"`
	Product    string     `json:"product"`
	ProductID  int        `json:"-"`
	Revision   string     `json:"revision"`
	LastChange *time.Time `json:"last_change"`
	ThirdParty bool       `json:"third_party"`

	CPEs                []CpeLabel `json:"cpes"`
	UpdatedPackageNames *[]string  `json:"updated_package_names,omitempty"`
}

type PackageDetailResponse struct {
	Summary       string             `json:"summary"`
	Description   string             `json:"description"`
	SourcePackage string             `json:"source_package"`
	Packages      []string           `json:"package_list"`
	Repositories  []RepoDetailCommon `json:"repositories"`
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

	CWEs      []string    `json:"cwe_list"`
	PkgIDs    []int       `json:"-"`
	ErrataIDs []ErratumID `json:"-"`

	Errata         []string `json:"errata_list"`
	Packages       []string `json:"package_list"`
	SourcePackages []string `json:"source_package_list"`
}

type PkgErratum struct {
	PkgID     PkgID
	ErratumID ErratumID
}

type Module struct {
	Name              string   `json:"module_name"`
	Stream            string   `json:"module_stream"`
	Version           int      `json:"module_version"`
	Context           string   `json:"module_context"`
	PackageList       []string `json:"package_list"`
	SourcePackageList []string `json:"source_package_list"`
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
	Synopsis       string  `json:"synopsis"`
	Summary        string  `json:"summary"`
	Type           string  `json:"type"`
	Severity       *string `json:"severity"`
	Description    string  `json:"description"`
	Solution       string  `json:"solution"`
	URL            string  `json:"url"`
	ThirdParty     bool    `json:"third_party"`
	RequiresReboot bool    `json:"requires_reboot"`

	ID        ErratumID  `json:"-"`
	Issued    *time.Time `json:"issued"`
	Updated   *time.Time `json:"updated"`
	CVEs      []string   `json:"cve_list"`
	PkgIDs    []int      `json:"-"`
	Bugzillas []string   `json:"bugzilla_list"`
	Refs      []string   `json:"reference_list"`
	Modules   []Module   `json:"modules_list"`

	PackageList       []string `json:"package_list"`
	SourcePackageList []string `json:"source_package_list"`
	ReleaseVersions   []string `json:"release_versions"`
}

type PkgListItem struct {
	Nevra       string     `json:"nevra"`
	Summary     string     `json:"summary"`
	Description string     `json:"description"`
	Modified    *time.Time `json:"modified,omitempty"`
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

func (l *ParsedCpe) Match(r *ParsedCpe) bool {
	match := func(l, r *string) bool {
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

	if !match(l.Vendor, r.Vendor) {
		return false
	}
	if !match(l.Product, r.Product) {
		return false
	}
	if !match(l.Version, r.Version) {
		return false
	}
	if !match(l.Update, r.Update) {
		return false
	}
	if !match(l.Edition, r.Edition) {
		return false
	}
	return match(l.Language, r.Language)
}

func (l *ParsedCpe) CmpByVersion(r *ParsedCpe) int {
	getStr := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}

	// Compare CPEs by Version first since we need this mainly for sorting CPEs by version
	lVersionStr := getStr(l.Version)
	rVersionStr := getStr(r.Version)
	// hack to treat 8 > 8.8 because releasever=8 should contain all fixes released in all minor versions
	if !strings.Contains(lVersionStr, ".") {
		lVersionStr += ".999"
	}
	if !strings.Contains(rVersionStr, ".") {
		rVersionStr += ".999"
	}
	lVersion, err := version.NewVersion(lVersionStr)
	if err != nil {
		lVersion = new(version.Version)
	}
	rVersion, err := version.NewVersion(rVersionStr)
	if err != nil {
		rVersion = new(version.Version)
	}
	if x := lVersion.Compare(rVersion); x != 0 {
		return x
	}

	if x := cmp.Compare(getStr(l.Part), getStr(r.Part)); x != 0 {
		return x
	}
	if x := cmp.Compare(getStr(l.Vendor), getStr(r.Vendor)); x != 0 {
		return x
	}
	if x := cmp.Compare(getStr(l.Product), getStr(r.Product)); x != 0 {
		return x
	}

	if x := cmp.Compare(getStr(l.Update), getStr(r.Update)); x != 0 {
		return x
	}
	if x := cmp.Compare(getStr(l.Edition), getStr(r.Edition)); x != 0 {
		return x
	}
	return cmp.Compare(getStr(l.Language), getStr(r.Language))
}

type CpeIDNameID struct {
	CpeID  CpeID
	NameID NameID
}

type ems struct {
	ErratumID      int
	ModuleStreamID int
}

type ensvc struct {
	ErratumID int
	Name      string
	Stream    string
	Version   int
	Context   string
}

type OSReleaseDetail struct {
	Name                   string `json:"name"`
	Major                  int    `json:"major"`
	Minor                  int    `json:"minor"`
	LifecyclePhase         string `json:"lifecycle_phase"`
	SystemProfile          string `json:"-"`
	CvesCritical           int    `json:"cves_critical"`
	CvesImportant          int    `json:"cves_important"`
	CvesModerate           int    `json:"cves_moderate"`
	CvesLow                int    `json:"cves_low"`
	CvesUnpatchedCritical  int    `json:"cves_unpatched_critical"`
	CvesUnpatchedImportant int    `json:"cves_unpatched_important"`
	CvesUnpatchedModerate  int    `json:"cves_unpatched_moderate"`
	CvesUnpatchedLow       int    `json:"cves_unpatched_low"`
}

type CveIDString struct {
	ID     CVEID
	String string
}
