package vmaas

import (
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	lock  = &sync.Mutex{}
	db    *gorm.DB
	sqlDB *sql.DB
)

func openDb(path string) error {
	tmpDb, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return errors.Wrap(err, "couldn't open sqlite")
	}
	db = tmpDb
	sqlDB, err = db.DB()
	if err != nil {
		return errors.Wrap(err, "couldn't return *sql.DB")
	}
	return nil
}

// Make sure only one load at a time is performed
func loadCache(path string) (*Cache, error) {
	lock.Lock()
	start := time.Now()

	if err := openDb(path); err != nil {
		return nil, err
	}
	c := Cache{}
	c.Id2Packagename, c.Packagename2Id = loadPkgNames()
	c.Updates = loadUpdates()
	c.UpdatesIndex = loadUpdatesIndex()

	c.Id2Evr, c.Evr2Id = loadEvrMaps()
	c.Id2Arch, c.Arch2Id = loadArchs()
	c.ArchCompat = loadArchCompat()

	c.PackageDetails, c.Nevra2PkgId, c.SrcPkgId2PkgId = loadPkgDetails("PackageDetails, Nevra2PkgId, SrcPkgId2PkgId")

	c.RepoDetails, c.RepoLabel2Ids, c.ProductId2RepoIds = loadRepoDetails("RepoDetails, RepoLabel2Ids, ProductId2RepoIds")
	c.Label2ContentSetID = loadLabel2ContentSetID("Label2ContentSetID")

	c.PkgId2RepoIds = loadPkgRepos()
	c.ErrataDetail, c.ErrataId2Name = loadErrata("ErrataDetail, ErrataId2Name")
	c.PkgId2ErrataIds = LoadPkgErratas()
	c.ErrataId2RepoIds = loadErrataRepoIds()
	c.CveDetail, c.CveNames = loadCves("CveDetail")
	c.PkgErrata2Module = loadPkgErrataModule("PkgErrata2Module")
	c.Module2Ids = loadModule2Ids("ModuleName2Ids")
	c.ModuleRequires = loadModuleRequires("ModuleRequire")
	c.DbChange = loadDbChanges("DbChange")
	c.String = loadString("String")

	// OVAL
	c.OvaldefinitionDetail = loadOvalDefinitionDetail()
	c.OvaldefinitionID2Cves = loadOvalDefinitionCves("oval_definition_cve")
	c.PackagenameID2definitionIDs = loadPackagenameID2DefinitionIDs("PackagenameID2definitionIDs")
	c.RepoID2CpeIDs = loadRepoCpes("RepoID2CpeIDs")
	c.ContentSetID2CpeIDs = loadContentSet2Cpes("ContentSetID2CpeIDs")
	c.CpeID2OvalDefinitionIDs = loadCpeID2DefinitionIDs("CpeID2OvalDefinitionIDs")
	c.OvalCriteriaID2DepCriteriaIDs, c.OvalCriteriaID2DepTestIDs, c.OvalCriteriaID2DepModuleTestIDs = loadOvalCriteriaDependency(
		"OvalCriteriaID2DepCriteriaIDs, OvalCriteriaID2DepTestIDs, OvalCriteriaID2DepModuleTestIDs",
	)

	c.OvalCriteriaID2Type = loadOvalCriteriaID2Type("OvalCriteriaID2Type")
	c.OvalStateID2Arches = loadOvalStateID2Arches("OvalStateID2Arches")
	c.OvalModuleTestDetail = loadOvalModuleTestDetail("OvalModuleTestDetail")
	c.OvalTestDetail = loadOvalTestDetail("OvalTestDetail")
	c.OvalTestID2States = loadOvalTestID2States("OvalTestID2States")

	utils.Log("elapsed", time.Since(start)).Info("Cache loaded successfully")
	lock.Unlock()
	return &c, nil
}

func loadErrataRepoIds() map[ErrataID][]RepoID {
	res := make(map[ErrataID][]RepoID)
	for k, v := range loadInt2Ints("errata_repo", "errata_id,repo_id", "ErrataId2RepoIds") {
		id := ErrataID(k)
		for _, i := range v {
			res[id] = append(res[id], RepoID(i))
		}
	}
	return res
}

func LoadPkgErratas() map[PkgID][]ErrataID {
	pkgToErrata := make(map[PkgID][]ErrataID)
	for k, v := range loadInt2Ints("pkg_errata", "pkg_id,errata_id", "PkgId2ErrataIds") {
		id := PkgID(k)
		for _, i := range v {
			pkgToErrata[id] = append(pkgToErrata[id], ErrataID(i))
		}
	}

	return pkgToErrata
}

func loadPkgRepos() map[PkgID][]RepoID {
	defer utils.TimeTrack(time.Now(), "PkgRepos")

	res := map[PkgID][]RepoID{}
	doForRows("select pkg_id, repo_id from pkg_repo", func(row *sql.Rows) {
		var n PkgID
		var p RepoID
		err := row.Scan(&n, &p)
		if err != nil {
			panic(err)
		}
		res[n] = append(res[n], p)
	})
	return res
}

func loadPkgNames() (map[NameID]string, map[string]NameID) {
	defer utils.TimeTrack(time.Now(), "PkgNames")

	type PkgName struct {
		Id          NameID
		Packagename string
	}

	var rows []PkgName
	err := db.Table("packagename").Find(&rows).Error
	if err != nil {
		panic(err)
	}
	id2name := map[NameID]string{}
	name2id := map[string]NameID{}

	for _, r := range rows {
		id2name[r.Id] = r.Packagename
		name2id[r.Packagename] = r.Id
	}
	return id2name, name2id
}

func loadUpdates() map[NameID][]PkgID {
	defer utils.TimeTrack(time.Now(), "Updates")

	res := map[NameID][]PkgID{}
	doForRows("select name_id, package_id from updates order by package_order", func(row *sql.Rows) {
		var n NameID
		var p PkgID
		err := row.Scan(&n, &p)
		if err != nil {
			panic(err)
		}
		res[n] = append(res[n], p)
	})
	return res
}

func loadUpdatesIndex() map[NameID]map[EvrID][]int {
	defer utils.TimeTrack(time.Now(), "Updates index")
	res := map[NameID]map[EvrID][]int{}
	doForRows("select name_id, evr_id, package_order from updates_index order by package_order", func(row *sql.Rows) {
		var n NameID
		var e EvrID
		var o int
		err := row.Scan(&n, &e, &o)
		if err != nil {
			panic(err)
		}
		nmap := res[n]
		if nmap == nil {
			nmap = map[EvrID][]int{}
		}
		nmap[e] = append(nmap[e], o)
		res[n] = nmap
	})
	return res
}

func getAllRows(tableName, cols, orderBy string) *sql.Rows {
	rows, err := sqlDB.Query(fmt.Sprintf("SELECT %s FROM %s ORDER BY %s",
		cols, tableName, orderBy))
	if err != nil {
		panic(err)
	}
	return rows
}

func doForRows(q string, f func(row *sql.Rows)) {
	rows, err := sqlDB.Query(q)
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		f(rows)
	}
}

func loadIntArray(tableName, col, orderBy string) []int {
	rows := getAllRows(tableName, col, orderBy)
	defer rows.Close()

	var arr []int
	for rows.Next() {
		var num int
		err := rows.Scan(&num)
		if err != nil {
			panic(err)
		}

		arr = append(arr, num)
	}
	return arr
}

func loadStrArray(tableName, col, orderBy string) []string {
	rows := getAllRows(tableName, col, orderBy)
	defer rows.Close()

	var arr []string
	for rows.Next() {
		var val string
		err := rows.Scan(&val)
		if err != nil {
			panic(err)
		}

		arr = append(arr, val)
	}
	return arr
}

func loadEvrMaps() (map[EvrID]utils.Evr, map[utils.Evr]EvrID) {
	defer utils.TimeTrack(time.Now(), "EVR")

	type IdEvr struct {
		ID EvrID
		utils.Evr
	}

	var rows []IdEvr
	err := db.Table("evr").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	id2evr := map[EvrID]utils.Evr{}
	evr2id := map[utils.Evr]EvrID{}

	for _, r := range rows {
		id2evr[r.ID] = r.Evr
		evr2id[r.Evr] = r.ID
	}
	return id2evr, evr2id
}

func loadArchs() (map[ArchID]string, map[string]ArchID) {
	defer utils.TimeTrack(time.Now(), "Arch")

	type Arch struct {
		ID   ArchID
		Arch string
	}
	var rows []Arch
	err := db.Table("arch").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	id2arch := map[ArchID]string{}
	arch2id := map[string]ArchID{}

	for _, r := range rows {
		id2arch[r.ID] = r.Arch
		arch2id[r.Arch] = r.ID
	}
	return id2arch, arch2id
}
func loadArchCompat() map[ArchID]map[ArchID]bool {
	defer utils.TimeTrack(time.Now(), "ArchCompat")

	type ArchCompat struct {
		FromArchId ArchID
		ToArchId   ArchID
	}
	var rows []ArchCompat
	err := db.Table("arch_compat").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	m := map[ArchID]map[ArchID]bool{}

	for _, r := range rows {
		fromMap := m[r.FromArchId]
		if fromMap == nil {
			fromMap = map[ArchID]bool{}
		}
		fromMap[r.ToArchId] = true
		m[r.FromArchId] = fromMap
	}
	return m
}

func loadPkgDetails(info string) (map[PkgID]PackageDetail, map[Nevra]PkgID, map[PkgID][]PkgID) {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("package_detail", "*", "ID")
	id2pkdDetail := map[PkgID]PackageDetail{}
	nevra2id := map[Nevra]PkgID{}
	srcPkgId2PkgId := map[PkgID][]PkgID{}
	for rows.Next() {
		var pkgId PkgID
		var det PackageDetail
		err := rows.Scan(&pkgId, &det.NameId, &det.EvrId, &det.ArchId, &det.SummaryId, &det.DescriptionId,
			&det.SrcPkgId, &det.Modified)
		if err != nil {
			panic(err)
		}
		id2pkdDetail[pkgId] = det

		nevra := Nevra{det.NameId, det.EvrId, det.ArchId}
		nevra2id[nevra] = pkgId

		if det.SrcPkgId == nil {
			continue
		}

		_, ok := srcPkgId2PkgId[*det.SrcPkgId]
		if !ok {
			srcPkgId2PkgId[*det.SrcPkgId] = []PkgID{}
		}

		srcPkgId2PkgId[*det.SrcPkgId] = append(srcPkgId2PkgId[*det.SrcPkgId], pkgId)
	}
	// FIXME: build ModifiedID index
	return id2pkdDetail, nevra2id, srcPkgId2PkgId
}

func loadRepoDetails(info string) (map[RepoID]RepoDetail, map[string][]RepoID, map[int][]RepoID) {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("repo_detail", "*", "label")
	id2repoDetail := map[RepoID]RepoDetail{}
	repoLabel2id := map[string][]RepoID{}
	prodId2RepoIds := map[int][]RepoID{}
	for rows.Next() {
		var repoId RepoID
		var det RepoDetail

		err := rows.Scan(&repoId, &det.Label, &det.Name, &det.Url, &det.BaseArch, &det.ReleaseVer,
			&det.Product, &det.ProductId, &det.Revision, &det.ThirdParty)
		if err != nil {
			panic(err)
		}

		id2repoDetail[repoId] = det

		_, ok := repoLabel2id[det.Label]
		if !ok {
			repoLabel2id[det.Label] = []RepoID{}
		}
		repoLabel2id[det.Label] = append(repoLabel2id[det.Label], repoId)

		_, ok = prodId2RepoIds[det.ProductId]
		if !ok {
			prodId2RepoIds[det.ProductId] = []RepoID{}
		}
		prodId2RepoIds[det.ProductId] = append(prodId2RepoIds[det.ProductId], repoId)
	}
	return id2repoDetail, repoLabel2id, prodId2RepoIds
}

func loadLabel2ContentSetID(info string) map[string]ContentSetID {
	defer utils.TimeTrack(time.Now(), info)

	type LabelContent struct {
		ID    ContentSetID
		Label string
	}

	var rows []LabelContent
	label2contentSetID := make(map[string]ContentSetID)
	err := db.Table("content_set").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	for _, r := range rows {
		label2contentSetID[r.Label] = r.ID
	}
	return label2contentSetID
}

func loadErrata(info string) (map[string]ErrataDetail, map[ErrataID]string) {
	defer utils.TimeTrack(time.Now(), info)

	erId2cves := loadInt2Strings("errata_cve", "errata_id,cve", "erId2cves")
	erId2pkgIds := loadInt2Ints("pkg_errata", "errata_id,pkg_id", "erId2pkgId")
	erId2modulePkgIds := loadInt2Ints("errata_modulepkg", "errata_id,pkg_id", "erId2modulePkgIds")
	erId2bzs := loadInt2Strings("errata_bugzilla", "errata_id,bugzilla", "erId2bzs")
	erId2refs := loadInt2Strings("errata_refs", "errata_id,ref", "erId2refs")
	erId2modules := loadErrataModules()

	cols := "ID,name,synopsis,summary,type,severity,description,solution,issued,updated,url,third_party,requires_reboot"
	rows := getAllRows("errata_detail", cols, "ID")
	errataDetail := map[string]ErrataDetail{}
	errataId2Name := map[ErrataID]string{}
	for rows.Next() {
		var errataId ErrataID
		var errataName string
		var det ErrataDetail
		err := rows.Scan(&errataId, &errataName, &det.Synopsis, &det.Summary, &det.Type, &det.Severity,
			&det.Description, &det.Solution, &det.Issued, &det.Updated, &det.Url, &det.ThirdParty, &det.RequiresReboot)
		if err != nil {
			panic(err)
		}
		errataId2Name[errataId] = errataName

		det.ID = errataId
		if cves, ok := erId2cves[int(errataId)]; ok {
			det.CVEs = cves
		}

		if pkgIds, ok := erId2pkgIds[int(errataId)]; ok {
			det.PkgIds = pkgIds
		}

		if modulePkgIds, ok := erId2modulePkgIds[int(errataId)]; ok {
			det.ModulePkgIds = modulePkgIds
		}

		if bzs, ok := erId2bzs[int(errataId)]; ok {
			det.Bugzillas = bzs
		}

		if refs, ok := erId2refs[int(errataId)]; ok {
			det.Refs = refs
		}

		if modules, ok := erId2modules[int(errataId)]; ok {
			det.Modules = modules
		}
		errataDetail[errataName] = det
	}
	return errataDetail, errataId2Name
}

func loadCves(info string) (map[string]CveDetail, map[int]string) {
	defer utils.TimeTrack(time.Now(), info)

	cveId2cwes := loadInt2Strings("cve_cwe", "cve_id,cwe", "cveId2cwes")
	cveId2pkg := loadInt2Ints("cve_pkg", "cve_id,pkg_id", "cveId2pkg")
	cve2eid := loadString2Ints("errata_cve", "cve,errata_id", "cve2eid")

	rows := getAllRows("cve_detail", "*", "id")
	cveDetails := map[string]CveDetail{}
	cveNames := map[int]string{}
	for rows.Next() {
		var cveId int
		var cveName string
		var det CveDetail
		err := rows.Scan(&cveId, &cveName, &det.RedHatUrl, &det.SecondaryUrl, &det.Cvss3Score, &det.Cvss3Metrics,
			&det.Impact, &det.PublishedDate, &det.ModifiedDate, &det.Iava, &det.Description, &det.Cvss2Score,
			&det.Cvss2Metrics, &det.Source)
		if err != nil {
			panic(err)
		}

		cwes, ok := cveId2cwes[cveId]
		sort.Strings(cwes)
		if ok {
			det.CWEs = cwes
		}

		pkgs, ok := cveId2pkg[cveId]
		if ok {
			det.PkgIds = pkgs
		}

		eids, ok := cve2eid[cveName]
		if ok {
			det.ErrataIds = eids
		}
		cveDetails[cveName] = det
		cveNames[cveId] = cveName
	}
	return cveDetails, cveNames
}

func loadPkgErrataModule(info string) map[PkgErrata][]int {
	defer utils.TimeTrack(time.Now(), info)

	orderBy := "pkg_id,errata_id,module_stream_id"
	table := "errata_modulepkg"
	pkgIds := loadIntArray(table, "pkg_id", orderBy)
	errataIds := loadIntArray(table, "errata_id", orderBy)
	moduleStreamIds := loadIntArray(table, "module_stream_id", orderBy)

	m := map[PkgErrata][]int{}

	for i := 0; i < len(pkgIds); i++ {
		pkgErrata := PkgErrata{pkgIds[i], errataIds[i]}
		_, ok := m[pkgErrata]
		if !ok {
			m[pkgErrata] = []int{}
		}

		m[pkgErrata] = append(m[pkgErrata], moduleStreamIds[i])
	}
	return m
}

func loadModule2Ids(info string) map[ModuleStream][]int {
	defer utils.TimeTrack(time.Now(), info)

	orderBy := "module,stream"
	table := "module_stream"
	modules := loadStrArray(table, "module", orderBy)
	streams := loadStrArray(table, "stream", orderBy)
	streamIds := loadIntArray(table, "stream_id", orderBy)

	m := map[ModuleStream][]int{}

	for i := 0; i < len(modules); i++ {
		pkgErrata := ModuleStream{modules[i], streams[i]}
		_, ok := m[pkgErrata]
		if !ok {
			m[pkgErrata] = []int{}
		}

		m[pkgErrata] = append(m[pkgErrata], streamIds[i])
	}
	return m
}

func loadModuleRequires(info string) map[int][]int {
	defer utils.TimeTrack(time.Now(), info)

	table := "module_stream_require"
	moduleRequires := loadInt2Ints(table, "stream_id,require_id", "module2requires")
	return moduleRequires
}

func loadString(info string) map[int]string {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("string", "*", "ID")
	m := map[int]string{}
	for rows.Next() {
		var id int
		var str *string
		err := rows.Scan(&id, &str)
		if err != nil {
			panic(err)
		}
		if str != nil {
			m[id] = *str
		}
	}
	return m
}

func loadDbChanges(info string) DbChange {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("dbchange", "*", "errata_changes")
	arr := []DbChange{}
	for rows.Next() {
		var item DbChange
		err := rows.Scan(&item.ErrataChanges, &item.CveChanges, &item.RepoChanges,
			&item.LastChange, &item.Exported)
		if err != nil {
			panic(err)
		}
		arr = append(arr, item)
	}
	return arr[0]
}

func loadInt2Ints(table, cols, info string) map[int][]int {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows(table, cols, cols)
	int2ints := map[int][]int{}
	for rows.Next() {
		var key int
		var val int
		err := rows.Scan(&key, &val)
		if err != nil {
			panic(err)
		}

		_, ok := int2ints[key]
		if !ok {
			int2ints[key] = []int{}
		}
		int2ints[key] = append(int2ints[key], val)
	}
	return int2ints
}

func loadInt2Strings(table, cols, info string) map[int][]string {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows(table, cols, cols)
	int2strs := map[int][]string{}
	for rows.Next() {
		var key int
		var val string
		err := rows.Scan(&key, &val)
		if err != nil {
			panic(err)
		}

		_, ok := int2strs[key]
		if !ok {
			int2strs[key] = []string{}
		}

		int2strs[key] = append(int2strs[key], val)
	}
	return int2strs
}

func loadString2Ints(table, cols, info string) map[string][]int {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows(table, cols, cols)
	int2strs := map[string][]int{}
	for rows.Next() {
		var key string
		var val int
		err := rows.Scan(&key, &val)
		if err != nil {
			panic(err)
		}

		_, ok := int2strs[key]
		if !ok {
			int2strs[key] = []int{}
		}

		int2strs[key] = append(int2strs[key], val)
	}
	return int2strs
}

func loadKey2Vals(table, key, val string, row interface{}, info string) interface{} {
	defer utils.TimeTrack(time.Now(), info)

	// get type of struct fields by `key`, `val` strings
	r := reflect.ValueOf(row)
	k := reflect.Indirect(r).FieldByName(key)
	v := reflect.Indirect(r).FieldByName(val)
	keyType := k.Type()
	valueType := v.Type()

	// create map of slices
	var sliceType = reflect.SliceOf(valueType)
	var mapType = reflect.MapOf(keyType, sliceType)
	value := reflect.New(sliceType)
	out := reflect.MakeMap(mapType)

	rows, err := db.Table(table).Rows()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		if err := db.ScanRows(rows, row); err != nil {
			panic(err)
		}

		// get values from `row` struct
		r := reflect.ValueOf(row)
		k := reflect.Indirect(r).FieldByName(key)
		v := reflect.Indirect(r).FieldByName(val)

		mapValue := out.MapIndex(k)
		if !mapValue.IsValid() {
			// key is not found in map
			// initialize empty inner slice
			value = reflect.New(sliceType)
		}
		value = reflect.Append(reflect.Indirect(value), v)
		out.SetMapIndex(k, value)
	}
	return out.Interface()
}

func loadErrataModules() map[int][]Module {
	defer utils.TimeTrack(time.Now(), "errata2module")

	rows := getAllRows("errata_module", "*", "errata_id")

	erId2modules := map[int][]Module{}
	for rows.Next() {
		var erId int
		var mod Module
		err := rows.Scan(&erId, &mod.Name, &mod.StreamID, &mod.Stream, &mod.Version, &mod.Context)
		if err != nil {
			panic(err)
		}

		_, ok := erId2modules[erId]
		if !ok {
			erId2modules[erId] = []Module{}
		}

		erId2modules[erId] = append(erId2modules[erId], mod)
	}
	return erId2modules
}

func loadOvalDefinitionDetail() map[DefinitionID]DefinitionDetail {
	defer utils.TimeTrack(time.Now(), "oval_definition_detail")

	type OvalDefinitionDetail struct {
		ID               DefinitionID
		DefinitionTypeID int
		CriteriaID       CriteriaID
	}

	var rows []OvalDefinitionDetail
	defDetail := make(map[DefinitionID]DefinitionDetail)
	err := db.Table("oval_definition_detail").Find(&rows).Error
	if err != nil {
		panic(err)
	}
	for _, r := range rows {
		defDetail[r.ID] = DefinitionDetail{
			DefinitionTypeID: r.DefinitionTypeID,
			CriteriaID:       r.CriteriaID,
		}
	}
	return defDetail
}

func loadOvalDefinitionCves(info string) map[DefinitionID][]string {
	type OvalDefinitionCve struct {
		DefinitionID DefinitionID
		Cve          string
	}
	row := OvalDefinitionCve{}
	keyVals := loadKey2Vals("oval_definition_cve", "DefinitionID", "Cve", &row, info)
	return keyVals.(map[DefinitionID][]string)
}

func loadPackagenameID2DefinitionIDs(info string) map[NameID][]DefinitionID {
	type NameDefinition struct {
		NameID       NameID
		DefinitionID DefinitionID
	}
	row := NameDefinition{}
	keyVals := loadKey2Vals("packagename_oval_definition", "NameID", "DefinitionID", &row, info)
	return keyVals.(map[NameID][]DefinitionID)
}

func loadRepoCpes(info string) map[RepoID][]CpeID {
	type CpeRepo struct {
		RepoID RepoID
		CpeID  CpeID
	}
	row := CpeRepo{}
	keyVals := loadKey2Vals("cpe_repo", "RepoID", "CpeID", &row, info)
	return keyVals.(map[RepoID][]CpeID)
}

func loadContentSet2Cpes(info string) map[ContentSetID][]CpeID {
	type CpeCS struct {
		ContentSetID ContentSetID
		CpeID        CpeID
	}
	row := CpeCS{}
	keyVals := loadKey2Vals("cpe_content_set", "ContentSetID", "CpeID", &row, info)
	return keyVals.(map[ContentSetID][]CpeID)
}

func loadCpeID2DefinitionIDs(info string) map[CpeID][]DefinitionID {
	type DefinitionCpe struct {
		CpeID        CpeID
		DefinitionID DefinitionID
	}
	row := DefinitionCpe{}
	keyVals := loadKey2Vals("oval_definition_cpe", "CpeID", "DefinitionID", &row, info)
	return keyVals.(map[CpeID][]DefinitionID)
}

func loadOvalCriteriaDependency(info string) (map[CriteriaID][]CriteriaID, map[CriteriaID][]TestID, map[CriteriaID][]ModuleTestID) {
	defer utils.TimeTrack(time.Now(), info)

	type OvalCriteriaDep struct {
		ParentCriteriaID CriteriaID
		DepCriteriaID    CriteriaID
		DepTestID        TestID
		DepModuleTestID  ModuleTestID
	}

	var rows = []OvalCriteriaDep{}
	criteriaID2DepCriteriaIDs := make(map[CriteriaID][]CriteriaID)
	criteriaID2DepTestIDs := make(map[CriteriaID][]TestID)
	criteriaID2DepModuleTestIDs := make(map[CriteriaID][]ModuleTestID)
	err := db.Table("oval_criteria_dependency").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	for _, r := range rows {
		if _, ok := criteriaID2DepCriteriaIDs[r.ParentCriteriaID]; !ok {
			criteriaID2DepCriteriaIDs[r.ParentCriteriaID] = []CriteriaID{}
			criteriaID2DepTestIDs[r.ParentCriteriaID] = []TestID{}
			criteriaID2DepModuleTestIDs[r.ParentCriteriaID] = []ModuleTestID{}
		}
		if r.DepCriteriaID != 0 {
			criteriaID2DepCriteriaIDs[r.ParentCriteriaID] = append(criteriaID2DepCriteriaIDs[r.ParentCriteriaID], r.DepCriteriaID)
		}
		if r.DepTestID != 0 {
			criteriaID2DepTestIDs[r.ParentCriteriaID] = append(criteriaID2DepTestIDs[r.ParentCriteriaID], r.DepTestID)
		}
		if r.DepModuleTestID != 0 {
			criteriaID2DepModuleTestIDs[r.ParentCriteriaID] = append(criteriaID2DepModuleTestIDs[r.ParentCriteriaID], r.DepModuleTestID)
		}
	}

	return criteriaID2DepCriteriaIDs, criteriaID2DepTestIDs, criteriaID2DepModuleTestIDs
}

func loadOvalCriteriaID2Type(info string) map[CriteriaID]int {
	defer utils.TimeTrack(time.Now(), info)

	type OvalCriteriaType struct {
		CriteriaID CriteriaID
		TypeID     int
	}

	var rows = []OvalCriteriaType{}
	criteriaID2Type := make(map[CriteriaID]int)
	err := db.Table("oval_criteria_type").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	for _, r := range rows {
		criteriaID2Type[r.CriteriaID] = r.TypeID
	}
	return criteriaID2Type
}

func loadOvalStateID2Arches(info string) map[OvalStateID][]ArchID {
	type StateArch struct {
		StateID OvalStateID
		ArchID  ArchID
	}
	row := StateArch{}
	keyVals := loadKey2Vals("oval_state_arch", "StateID", "ArchID", &row, info)
	return keyVals.(map[OvalStateID][]ArchID)
}

func loadOvalModuleTestDetail(info string) map[ModuleTestID]OvalModuleTestDetail {
	defer utils.TimeTrack(time.Now(), info)

	type ModuleTestDetail struct {
		ID           ModuleTestID
		ModuleStream string
	}

	var rows = []ModuleTestDetail{}
	details := make(map[ModuleTestID]OvalModuleTestDetail)
	err := db.Table("oval_module_test_detail").Find(&rows).Error
	if err != nil {
		panic(err)
	}

	for _, r := range rows {
		splitted := strings.Split(r.ModuleStream, ":")
		details[r.ID] = OvalModuleTestDetail{
			ModuleStream: ModuleStream{Module: splitted[0], Stream: splitted[1]},
		}
	}
	return details
}

func loadOvalTestDetail(info string) map[TestID]OvalTestDetail {
	defer utils.TimeTrack(time.Now(), info)

	type TestDetail struct {
		ID               TestID
		PackageNameID    NameID
		CheckExistenceID int
	}

	var rows = []TestDetail{}
	testDetail := make(map[TestID]OvalTestDetail)
	err := db.Table("oval_test_detail").Find(&rows).Error
	if err != nil {
		panic(err)
	}
	for _, r := range rows {
		testDetail[r.ID] = OvalTestDetail{PkgNameID: r.PackageNameID, CheckExistence: r.CheckExistenceID}
	}
	return testDetail
}

func loadOvalTestID2States(info string) map[TestID][]OvalState {
	defer utils.TimeTrack(time.Now(), info)
	type TestState struct {
		TestID         TestID
		StateID        OvalStateID
		EvrID          EvrID
		EvrOperationID int
	}

	var rows = []TestState{}
	test2State := make(map[TestID][]OvalState)
	err := db.Table("oval_test_state").Find(&rows).Error
	if err != nil {
		panic(err)
	}
	for _, r := range rows {
		test2State[r.TestID] = append(test2State[r.TestID], OvalState{
			ID:           r.StateID,
			EvrID:        r.EvrID,
			OperationEvr: r.EvrOperationID,
		})
	}
	return test2State
}
