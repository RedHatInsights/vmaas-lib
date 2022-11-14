package vmaas

import "github.com/redhatinsights/vmaas-lib/vmaas/utils"

type Cache struct {
	Packagename2Id map[string]NameID
	Id2Packagename map[NameID]string

	// name -> []pkg ordered by e-v-r ordering
	Updates map[NameID][]PkgID
	// name -> evr -> idx into updates[name]
	UpdatesIndex map[NameID]map[EvrID][]int

	Evr2Id map[utils.Evr]EvrID
	Id2Evr map[EvrID]utils.Evr

	Id2Arch map[ArchID]string
	Arch2Id map[string]ArchID

	ArchCompat map[ArchID]map[ArchID]bool

	PackageDetails map[PkgID]PackageDetail
	Nevra2PkgId    map[Nevra]PkgID

	RepoDetails        map[RepoID]RepoDetail
	RepoLabel2Ids      map[string][]RepoID
	Label2ContentSetID map[string]ContentSetID

	ProductId2RepoIds map[int][]RepoID
	PkgId2RepoIds     map[PkgID][]RepoID

	ErrataId2Name    map[ErrataID]string
	PkgId2ErrataIds  map[PkgID][]ErrataID
	ErrataId2RepoIds map[ErrataID][]RepoID

	CveDetail map[string]CveDetail
	CveNames  map[int]string

	PkgErrata2Module map[PkgErrata][]int
	Module2Ids       map[ModuleStream][]int
	ModuleRequires   map[int][]int
	DbChange         DbChange
	ErrataDetail     map[string]ErrataDetail
	SrcPkgId2PkgId   map[PkgID][]PkgID
	String           map[int]string

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
}
