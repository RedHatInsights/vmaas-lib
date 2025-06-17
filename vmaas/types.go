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
	VariantSuffix string
)

const DefaultVariantSuffix = "N/A"

type Request struct {
	Packages   []string           `json:"package_list" example:"kernel-2.6.32-696.20.1.el6.x86_64" validate:"required"`
	Repos      *[]string          `json:"repository_list" example:"rhel-6-server-rpms"`
	Modules    []ModuleStreamPtrs `json:"modules_list"`
	Releasever *string            `json:"releasever" example:"6Server"`
	Basearch   *string            `json:"basearch" example:"x86_64"`
	RepoPaths  []string           `json:"repository_paths" example:"/content/dist/rhel/rhui/server/7/7Server/x86_64/os/"`

	// Include content from "third party" repositories into the response, disabled by default.
	ThirdParty   bool `json:"third_party" default:"false"`
	LatestOnly   bool `json:"latest_only"`
	SecurityOnly bool `json:"security_only"`

	Extended      bool   `json:"extended"`
	EpochRequired bool   `json:"epoch_required"`
	Organization  string `json:"organization"`
}

type CvesRequest struct {
	Cves           []string   `json:"cve_list" example:"CVE-2017-57.*" minItems:"1" validate:"required"`
	PublishedSince *time.Time `json:"published_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	ModifiedSince  *time.Time `json:"modified_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	RHOnly         bool       `json:"rh_only"`
	// Return only those CVEs which are associated with at least one errata. Defaults to false.
	AreErrataAssociated bool `json:"errata_associated"`
	// Include content from \"third party\" repositories into the response, disabled by default.
	ThirdParty bool `json:"third_party" default:"false"`
	utils.PaginationRequest
}

type PkgListRequest struct {
	ModifiedSince *time.Time `json:"modified_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	// Include 'modified' package attribute into the response
	ReturnModified bool `json:"return_modified" default:"false"`
	utils.PaginationRequest
}

type PkgTreeRequest struct {
	PackageNames  []string   `json:"package_name_list" example:"kernel-rt" minItems:"1" validate:"required"`
	ModifiedSince *time.Time `json:"modified_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	// Include content from "third party" repositories into the response, disabled by default.
	ThirdParty bool `json:"third_party" default:"false"`
	// Include nevra repositories info into the response.
	ReturnRepositories *bool `json:"return_repositories" default:"true"`
	// Include nevra errata info into the response.
	ReturnErrata *bool `json:"return_errata" default:"true"`
	// Include nevra summary info into the response.
	ReturnSummary bool `json:"return_summary" default:"false"`
	// Include nevra description info into the response.
	ReturnDescription bool `json:"return_description" default:"false"`
	utils.PaginationRequest
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
	Errata        []string   `json:"errata_list" example:"RHSA-2018:05.*" minItems:"1" validate:"required"`
	ModifiedSince *time.Time `json:"modified_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	// Include content from \"third party\" repositories into the response, disabled by default.
	ThirdParty bool      `json:"third_party" default:"false"`
	Type       TypeT     `json:"type" example:"security"`
	Severity   SeverityT `json:"severity" enums:"Low,Moderate,Important,Critical,null"`
	utils.PaginationRequest
}

type ReposRequest struct {
	Repos []string `json:"repository_list" example:"rhel-6-server-rpms" minItems:"1" validate:"required"`
	// Return only repositories changed after the given date
	ModifiedSince *time.Time `json:"modified_since" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
	// Include content from \"third party\" repositories into the response, disabled by default.
	ThirdParty bool `json:"third_party" default:"false"`
	// Show updated package names in a repo since the last modified_since
	ShowPackages bool `json:"show_packages" default:"false"`
	// Return only repositories having advisories with packages released since the last modified_since
	HasPackages  bool   `json:"has_packages" default:"false"`
	Organization string `json:"organization"`
	utils.PaginationRequest
}

type PackagesRequest struct {
	Packages []string `json:"package_list" example:"kernel-2.6.32-696.20.1.el6.x86_64" minItems:"1" validate:"required"`
	// Include content from "third party" repositories into the response, disabled by default.
	ThirdParty bool `json:"third_party" default:"false"`
}

type RPMPkgNamesRequest struct {
	RPMNames    []string `json:"rpm_name_list" example:"openssl-libs" validate:"required"`
	ContentSets []string `json:"content_set_list" example:"rhel-7-desktop-rpms"`
}

type SRPMPkgNamesRequest struct {
	SRPMNames   []string `json:"srpm_name_list" example:"openssl" validate:"required"`
	ContentSets []string `json:"content_set_list" example:"rhel-7-desktop-rpms"`
}

type Update struct {
	Package     string `json:"package" example:"kernel-2.6.32-696.23.1.el6.x86_64"`
	PackageName string `json:"package_name" example:"kernel"`
	EVRA        string `json:"evra" example:"0:2.6.32-696.23.1.el6.x86_64"`
	Erratum     string `json:"erratum" example:"RHSA-2018:0512"`
	Repository  string `json:"repository" example:"rhel-6-server-rpms"`
	Basearch    string `json:"basearch" example:"x86_64"`
	Releasever  string `json:"releasever" example:"6Server"`
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
	UpdateList UpdateList `json:"update_list"`
	RepoList   *[]string  `json:"repository_list,omitempty" example:"rhel-6-server-rpms"`
	// Example: /content/dist/rhel/rhui/server/7/7Server/x86_64/os/
	RepoPaths  []string       `json:"repository_paths,omitempty"`
	ModuleList []ModuleStream `json:"modules_list,omitempty"`
	Releasever *string        `json:"releasever,omitempty" example:"6Server"`
	Basearch   *string        `json:"basearch,omitempty" example:"x86_64"`
	LastChange time.Time      `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
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
		CVE      string            `json:"cve" example:"CVE-2017-15089" validate:"required"`
		Packages []string          `json:"affected_packages" example:"libxml2-0:2.9.1-6.el7_2.3.x86_64" validate:"required"`
		Errata   []string          `json:"errata" example:"RHSA-2018:0512" validate:"required"`
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
	CVEs                []Vulnerability `json:"cve_list" validate:"required"`
	ManuallyFixableCVEs []Vulnerability `json:"manually_fixable_cve_list" validate:"required"`
	UnpatchedCVEs       []Vulnerability `json:"unpatched_cve_list" validate:"required"`
	LastChange          time.Time       `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
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
	Label        string `json:"label" example:"rhel-6-server-rpms" validate:"required"`
	Name         string `json:"name" example:"Red Hat Enterprise Linux 6 Server (RPMs)" validate:"required"`
	Basearch     string `json:"basearch" example:"x86_64" validate:"required"`
	Releasever   string `json:"releasever" example:"6Server" validate:"required"`
	Organization string `json:"organization"`
}

type RepoDetail struct {
	RepoDetailCommon
	URL        string     `json:"url" example:"https://cdn.redhat.com/content/dist/rhel/server/6/6Server/x86_64/os/"`
	Product    string     `json:"product" example:"Red Hat Enterprise Linux Server"`
	ProductID  int        `json:"-"`
	Revision   string     `json:"revision" example:"2018-03-27T10:55:16+00:00"`
	LastChange *time.Time `json:"last_change"`
	ThirdParty bool       `json:"third_party"`

	CPEs                []CpeLabel `json:"cpes" example:"cpe:/a:redhat"`
	UpdatedPackageNames *[]string  `json:"updated_package_names,omitempty" example:"kernel"`
}

type PackageDetailResponse struct {
	Summary       string             `json:"summary" example:"package summary"`
	Description   string             `json:"description" example:"package description"`
	SourcePackage string             `json:"source_package" example:"kernel-2.6.32-696.23.1.el6.src"`
	Packages      []string           `json:"package_list" example:"kernel-2.6.32-696.23.1.el6.x86_64"`
	Repositories  []RepoDetailCommon `json:"repositories"`
}

type CveDetail struct {
	Name          string     `json:"synopsis" example:"CVE-2017-5715"`
	RedHatURL     string     `json:"redhat_url" example:"https://access.redhat.com/security/cve/cve-2017-5715"`
	SecondaryURL  string     `json:"secondary_url" example:"https://seconday.url.com"`
	Cvss3Score    string     `json:"cvss3_score" example:"5.1"`
	Cvss3Metrics  string     `json:"cvss3_metrics" example:"AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N"`
	Impact        string     `json:"impact" enums:"NotSet,None,Low,Medium,Moderate,Important,High,Critical"`
	PublishedDate *time.Time `json:"public_date" example:"2018-01-04T13:29:00+00:00" format:"date-time"`
	ModifiedDate  *time.Time `json:"modified_date" example:"2018-03-31T01:29:00+00:00" format:"date-time"`
	Iava          string     `json:"-"`
	Description   string     `json:"description" example:"description text"`
	Cvss2Score    string     `json:"cvss2_score" example:"5.600"`
	Cvss2Metrics  string     `json:"cvss2_metrics" example:"AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N"`
	Source        string     `json:"-"`

	CWEs       []string    `json:"cwe_list" example:"CWE-20"`
	PkgIDs     []int       `json:"-"`
	ErratumIDs []ErratumID `json:"-"`

	Errata         []string `json:"errata_list" example:"RHSA-2015:1981"`
	Packages       []string `json:"package_list" example:"nss-devel-3.16.1-9.el6_5.x86_64"`
	SourcePackages []string `json:"source_package_list" example:"nss-devel-3.16.1-9.el6_5.src"`
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
	Module *string `json:"module_name" example:"rhn-tools" validate:"required"`
	Stream *string `json:"module_stream" example:"1" validate:"required"`
}

// @Description VMaaS DB last-updated time stramps
type DBChange struct {
	ErrataChanges time.Time `json:"errata_changes" example:"2024-11-20T12:24:23.488871Z"`
	CveChanges    time.Time `json:"cve_changes" example:"2024-11-20T12:26:20.009512Z"`
	RepoChanges   time.Time `json:"repository_changes" example:"2024-11-20T12:24:23.486827Z"`
	LastChange    time.Time `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
	Exported      time.Time `json:"exported" example:"2024-11-20T12:37:47.605526Z"`
}

type ErratumDetail struct {
	Synopsis       string  `json:"synopsis" example:"Important: kernel security and bug fix update"`
	Summary        string  `json:"summary" example:"summary text"`
	Type           string  `json:"type" example:"security"`
	Severity       *string `json:"severity" enums:"Low,Moderate,Important,Critical,null"`
	Description    string  `json:"description" example:"description text"`
	Solution       string  `json:"solution" example:"solution text"`
	URL            string  `json:"url" example:"https://access.redhat.com/errata/RHSA-2018:0512"`
	ThirdParty     bool    `json:"third_party"`
	RequiresReboot bool    `json:"requires_reboot"`

	ID        ErratumID  `json:"-"`
	Issued    *time.Time `json:"issued" example:"2018-03-13T17:31:28+00:00" format:"date-time"`
	Updated   *time.Time `json:"updated" example:"2018-03-13T17:31:41+00:00"`
	CVEs      []string   `json:"cve_list" example:"CVE-2017-5715"`
	PkgIDs    []int      `json:"-"`
	Bugzillas []string   `json:"bugzilla_list" example:"1519778"`
	Refs      []string   `json:"reference_list" example:"classification-RHSA-2018:0512"`
	Modules   []Module   `json:"modules_list"`

	PackageList       []string `json:"package_list" example:"kernel-2.6.32-696.23.1.el6.x86_64"`
	SourcePackageList []string `json:"source_package_list" example:"kernel-2.6.32-696.23.1.el6.src"`
	ReleaseVersions   []string `json:"release_versions" example:"8.1"`
}

type PkgListItem struct {
	Nevra       string     `json:"nevra" example:"kernel-rt-4.18.0-147.rt24.93.el8.x86_64"`
	Summary     string     `json:"summary" example:"My package summary"`
	Description string     `json:"description" example:"My package description"`
	Modified    *time.Time `json:"modified,omitempty" example:"2018-04-05T01:23:45+02:00" format:"date-time"`
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
	VariantSuffix VariantSuffix
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

// Split variant into slice of version numbers followed by string
func (x *VariantSuffix) Split() ([]string, string) {
	if x == nil {
		return nil, ""
	}
	// variant suffix should consist of 3 numbers separated by "."
	// followed by strings with dots
	splitted := strings.SplitN(string(*x), ".", 4)
	if len(splitted) <= 3 {
		// we always want 4 items so append "0"
		for i := 0; i < 4-len(splitted); i++ {
			splitted = append(splitted, "0")
		}
	}
	return splitted[:3], splitted[3]
}

// Compare compares this variant to another variant.
// Returns -1, 0, or 1 if this variant is smaller, equal, or larger than the other variant.
func (x *VariantSuffix) Compare(y *VariantSuffix) int {
	switch {
	case x == y:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return 1
	case *x == *y:
		return 0
	}

	xVersion, xRest := x.Split()
	yVersion, yRest := y.Split()

	cmp := slices.Compare(xVersion, yVersion)
	if cmp == 0 {
		cmp = strings.Compare(xRest, yRest)
	}
	return cmp
}
