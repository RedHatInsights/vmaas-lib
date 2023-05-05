package vmaas

import "github.com/redhatinsights/vmaas-lib/vmaas/utils"

type Cache struct {
	Packagename2ID map[string]NameID
	ID2Packagename map[NameID]string

	// name -> []pkg ordered by e-v-r ordering
	Updates map[NameID][]PkgID
	// name -> evr -> idx into updates[name]
	UpdatesIndex map[NameID]map[EvrID][]int

	Evr2ID map[utils.Evr]EvrID
	ID2Evr map[EvrID]utils.Evr

	ID2Arch map[ArchID]string
	Arch2ID map[string]ArchID

	ArchCompat map[ArchID]map[ArchID]bool

	PackageDetails map[PkgID]PackageDetail
	Nevra2PkgID    map[Nevra]PkgID

	RepoIDs            []RepoID
	RepoDetails        map[RepoID]RepoDetail
	RepoLabel2IDs      map[string][]RepoID
	RepoPath2IDs       map[string][]RepoID
	Label2ContentSetID map[string]ContentSetID

	ProductID2RepoIDs map[int][]RepoID
	PkgID2RepoIDs     map[PkgID][]RepoID

	ErratumID2Name    map[ErratumID]string
	PkgID2ErrataIDs   map[PkgID][]ErratumID
	ErratumID2RepoIDs map[ErratumID]map[RepoID]bool

	CveDetail map[string]CveDetail
	CveNames  map[int]string

	PkgErratum2Module map[PkgErratum][]int
	Module2IDs        map[ModuleStream][]int
	ModuleRequires    map[int][]int
	DBChange          DBChange
	ErratumDetails    map[string]ErratumDetail
	SrcPkgID2PkgID    map[PkgID][]PkgID
	String            map[int]string

	// OVAL
	PackagenameID2definitionIDs map[NameID][]DefinitionID
	RepoID2CpeIDs               map[RepoID][]CpeID
	ContentSetID2CpeIDs         map[ContentSetID][]CpeID

	OvaldefinitionDetail            map[DefinitionID]DefinitionDetail
	OvaldefinitionID2Cves           map[DefinitionID][]string
	CpeID2OvalDefinitionIDs         map[CpeID][]DefinitionID
	OvalCriteriaID2DepModuleTestIDs map[CriteriaID][]ModuleTestID
	OvalCriteriaID2DepTestIDs       map[CriteriaID][]TestID
	OvalCriteriaID2DepCriteriaIDs   map[CriteriaID][]CriteriaID
	OvalCriteriaID2Type             map[CriteriaID]int
	OvalStateID2Arches              map[OvalStateID][]ArchID
	OvalModuleTestDetail            map[ModuleTestID]OvalModuleTestDetail
	OvalTestDetail                  map[TestID]OvalTestDetail
	OvalTestID2States               map[TestID][]OvalState
	OvalDefinitionID2ErrataIDs      map[DefinitionID][]ErratumID
	CpeID2Label                     map[CpeID]string
}
