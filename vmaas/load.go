package vmaas

import (
	"database/sql"
	"fmt"
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

func openDB(path string) error {
	tmpDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return errors.Wrap(err, "couldn't open sqlite")
	}
	db = tmpDB
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

	if err := openDB(path); err != nil {
		return nil, err
	}
	c := Cache{}
	c.ID2Packagename, c.Packagename2ID = loadPkgNames()
	c.Updates = loadUpdates()
	c.UpdatesIndex = loadUpdatesIndex()

	c.ID2Evr, c.Evr2ID = loadEvrMaps()
	c.ID2Arch, c.Arch2ID = loadArchs()
	c.ArchCompat = loadArchCompat()

	c.PackageDetails, c.Nevra2PkgID, c.SrcPkgID2PkgID = loadPkgDetails("PackageDetails, Nevra2PkgID, SrcPkgID2PkgID")

	c.RepoIDs, c.RepoDetails, c.RepoLabel2IDs, c.ProductID2RepoIDs = loadRepoDetails(
		"RepoIDs, RepoDetails, RepoLabel2IDs, ProductID2RepoIDs",
	)
	c.Label2ContentSetID = loadLabel2ContentSetID("Label2ContentSetID")

	c.PkgID2RepoIDs = loadPkgRepos()
	c.ErrataDetail, c.ErrataID2Name = loadErrata("ErrataDetail, ErrataID2Name")
	c.PkgID2ErrataIDs = LoadPkgErratas()
	c.ErrataID2RepoIDs = loadErrataRepoIDs()
	c.CveDetail, c.CveNames = loadCves("CveDetail")
	c.PkgErrata2Module = loadPkgErrataModule("PkgErrata2Module")
	c.Module2IDs = loadModule2IDs("ModuleName2IDs")
	c.ModuleRequires = loadModuleRequires("ModuleRequire")
	c.DBChange = loadDBChanges("DBChange")
	c.String = loadString("String")

	// OVAL
	c.OvaldefinitionDetail = loadOvalDefinitionDetail()
	c.OvaldefinitionID2Cves = loadOvalDefinitionCves("oval_definition_cve")
	c.PackagenameID2definitionIDs = loadPackagenameID2DefinitionIDs("PackagenameID2definitionIDs")
	c.RepoID2CpeIDs = loadRepoCpes("RepoID2CpeIDs")
	c.ContentSetID2CpeIDs = loadContentSet2Cpes("ContentSetID2CpeIDs")
	c.CpeID2OvalDefinitionIDs = loadCpeID2DefinitionIDs("CpeID2OvalDefinitionIDs")
	c.OvalCriteriaID2DepCriteriaIDs, c.OvalCriteriaID2DepTestIDs, c.OvalCriteriaID2DepModuleTestIDs = loadOvalCriteriaDependency( //nolint:lll,nolintlint
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

func loadErrataRepoIDs() map[ErrataID][]RepoID {
	res := make(map[ErrataID][]RepoID)
	for k, v := range loadInt2Ints("errata_repo", "errata_id,repo_id", "ErrataID2RepoIDs") {
		id := ErrataID(k)
		for _, i := range v {
			res[id] = append(res[id], RepoID(i))
		}
	}
	return res
}

func LoadPkgErratas() map[PkgID][]ErrataID {
	pkgToErrata := make(map[PkgID][]ErrataID)
	for k, v := range loadInt2Ints("pkg_errata", "pkg_id,errata_id", "PkgID2ErrataIDs") {
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
		ID          NameID
		Packagename string
	}

	r := PkgName{}
	id2name := map[NameID]string{}
	name2id := map[string]NameID{}
	rows := getAllRows("packagename", "id,packagename", "id")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Packagename); err != nil {
			panic(err)
		}
		id2name[r.ID] = r.Packagename
		name2id[r.Packagename] = r.ID
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

	type IDEvr struct {
		ID EvrID
		utils.Evr
	}

	r := IDEvr{}
	id2evr := map[EvrID]utils.Evr{}
	evr2id := map[utils.Evr]EvrID{}
	rows := getAllRows("evr", "id,epoch,version,release", "id")

	for rows.Next() {
		//nolint:typecheck,nolintlint // false-positive, r.Epoch undefined (type IDEvr has no field or method Epoch)
		if err := rows.Scan(&r.ID, &r.Epoch, &r.Version, &r.Release); err != nil {
			panic(err)
		}
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
	r := Arch{}
	id2arch := map[ArchID]string{}
	arch2id := map[string]ArchID{}
	rows := getAllRows("arch", "id,arch", "id")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Arch); err != nil {
			panic(err)
		}
		id2arch[r.ID] = r.Arch
		arch2id[r.Arch] = r.ID
	}
	return id2arch, arch2id
}

func loadArchCompat() map[ArchID]map[ArchID]bool {
	defer utils.TimeTrack(time.Now(), "ArchCompat")

	type ArchCompat struct {
		FromArchID ArchID
		ToArchID   ArchID
	}
	r := ArchCompat{}
	m := map[ArchID]map[ArchID]bool{}
	rows := getAllRows("arch_compat", "from_arch_id,to_arch_id", "from_arch_id,to_arch_id")

	for rows.Next() {
		if err := rows.Scan(&r.FromArchID, &r.ToArchID); err != nil {
			panic(err)
		}
		fromMap := m[r.FromArchID]
		if fromMap == nil {
			fromMap = map[ArchID]bool{}
		}
		fromMap[r.ToArchID] = true
		m[r.FromArchID] = fromMap
	}
	return m
}

func loadPkgDetails(info string) (map[PkgID]PackageDetail, map[Nevra]PkgID, map[PkgID][]PkgID) {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("package_detail", "*", "ID")
	id2pkdDetail := map[PkgID]PackageDetail{}
	nevra2id := map[Nevra]PkgID{}
	srcPkgID2PkgID := map[PkgID][]PkgID{}
	for rows.Next() {
		var pkgID PkgID
		var det PackageDetail
		err := rows.Scan(&pkgID, &det.NameID, &det.EvrID, &det.ArchID, &det.SummaryID, &det.DescriptionID,
			&det.SrcPkgID, &det.Modified)
		if err != nil {
			panic(err)
		}
		id2pkdDetail[pkgID] = det

		nevra := Nevra{det.NameID, det.EvrID, det.ArchID}
		nevra2id[nevra] = pkgID

		if det.SrcPkgID == nil {
			continue
		}

		_, ok := srcPkgID2PkgID[*det.SrcPkgID]
		if !ok {
			srcPkgID2PkgID[*det.SrcPkgID] = []PkgID{}
		}

		srcPkgID2PkgID[*det.SrcPkgID] = append(srcPkgID2PkgID[*det.SrcPkgID], pkgID)
	}
	// FIXME: build ModifiedID index
	return id2pkdDetail, nevra2id, srcPkgID2PkgID
}

func loadRepoDetails(info string) ([]RepoID, map[RepoID]RepoDetail, map[string][]RepoID, map[int][]RepoID) {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("repo_detail", "*", "label")
	id2repoDetail := map[RepoID]RepoDetail{}
	repoLabel2id := map[string][]RepoID{}
	prodID2RepoIDs := map[int][]RepoID{}
	repoIDs := []RepoID{}
	for rows.Next() {
		var repoID RepoID
		var det RepoDetail

		err := rows.Scan(&repoID, &det.Label, &det.Name, &det.URL, &det.Basearch, &det.Releasever,
			&det.Product, &det.ProductID, &det.Revision, &det.ThirdParty)
		if err != nil {
			panic(err)
		}

		repoIDs = append(repoIDs, repoID)
		id2repoDetail[repoID] = det

		_, ok := repoLabel2id[det.Label]
		if !ok {
			repoLabel2id[det.Label] = []RepoID{}
		}
		repoLabel2id[det.Label] = append(repoLabel2id[det.Label], repoID)

		_, ok = prodID2RepoIDs[det.ProductID]
		if !ok {
			prodID2RepoIDs[det.ProductID] = []RepoID{}
		}
		prodID2RepoIDs[det.ProductID] = append(prodID2RepoIDs[det.ProductID], repoID)
	}
	return repoIDs, id2repoDetail, repoLabel2id, prodID2RepoIDs
}

func loadLabel2ContentSetID(info string) map[string]ContentSetID {
	defer utils.TimeTrack(time.Now(), info)

	type LabelContent struct {
		ID    ContentSetID
		Label string
	}

	r := LabelContent{}
	label2contentSetID := make(map[string]ContentSetID)
	rows := getAllRows("content_set", "id,label", "id")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Label); err != nil {
			panic(err)
		}
		label2contentSetID[r.Label] = r.ID
	}
	return label2contentSetID
}

func loadErrata(info string) (map[string]ErrataDetail, map[ErrataID]string) {
	defer utils.TimeTrack(time.Now(), info)

	erID2cves := loadInt2Strings("errata_cve", "errata_id,cve", "erID2cves")
	erID2pkgIDs := loadInt2Ints("pkg_errata", "errata_id,pkg_id", "erID2pkgID")
	erID2modulePkgIDs := loadInt2Ints("errata_modulepkg", "errata_id,pkg_id", "erID2modulePkgIDs")
	erID2bzs := loadInt2Strings("errata_bugzilla", "errata_id,bugzilla", "erID2bzs")
	erID2refs := loadInt2Strings("errata_refs", "errata_id,ref", "erID2refs")
	erID2modules := loadErrataModules()

	cols := "ID,name,synopsis,summary,type,severity,description,solution,issued,updated,url,third_party,requires_reboot" //nolint:lll,nolintlint
	rows := getAllRows("errata_detail", cols, "ID")
	errataDetail := map[string]ErrataDetail{}
	errataID2Name := map[ErrataID]string{}
	for rows.Next() {
		var errataID ErrataID
		var errataName string
		var det ErrataDetail
		err := rows.Scan(&errataID, &errataName, &det.Synopsis, &det.Summary, &det.Type, &det.Severity,
			&det.Description, &det.Solution, &det.Issued, &det.Updated, &det.URL, &det.ThirdParty, &det.RequiresReboot)
		if err != nil {
			panic(err)
		}
		errataID2Name[errataID] = errataName

		det.ID = errataID
		if cves, ok := erID2cves[int(errataID)]; ok {
			det.CVEs = cves
		}

		if pkgIDs, ok := erID2pkgIDs[int(errataID)]; ok {
			det.PkgIDs = pkgIDs
		}

		if modulePkgIDs, ok := erID2modulePkgIDs[int(errataID)]; ok {
			det.ModulePkgIDs = modulePkgIDs
		}

		if bzs, ok := erID2bzs[int(errataID)]; ok {
			det.Bugzillas = bzs
		}

		if refs, ok := erID2refs[int(errataID)]; ok {
			det.Refs = refs
		}

		if modules, ok := erID2modules[int(errataID)]; ok {
			det.Modules = modules
		}
		errataDetail[errataName] = det
	}
	return errataDetail, errataID2Name
}

func loadCves(info string) (map[string]CveDetail, map[int]string) {
	defer utils.TimeTrack(time.Now(), info)

	cveID2cwes := loadInt2Strings("cve_cwe", "cve_id,cwe", "cveID2cwes")
	cveID2pkg := loadInt2Ints("cve_pkg", "cve_id,pkg_id", "cveID2pkg")
	cve2eid := loadString2Ints("errata_cve", "cve,errata_id", "cve2eid")

	rows := getAllRows("cve_detail", "*", "id")
	cveDetails := map[string]CveDetail{}
	cveNames := map[int]string{}
	for rows.Next() {
		var cveID int
		var cveName string
		var det CveDetail
		err := rows.Scan(&cveID, &cveName, &det.RedHatURL, &det.SecondaryURL, &det.Cvss3Score, &det.Cvss3Metrics,
			&det.Impact, &det.PublishedDate, &det.ModifiedDate, &det.Iava, &det.Description, &det.Cvss2Score,
			&det.Cvss2Metrics, &det.Source)
		if err != nil {
			panic(err)
		}

		cwes, ok := cveID2cwes[cveID]
		sort.Strings(cwes)
		if ok {
			det.CWEs = cwes
		}

		pkgs, ok := cveID2pkg[cveID]
		if ok {
			det.PkgIDs = pkgs
		}

		eids, ok := cve2eid[cveName]
		if ok {
			det.ErrataIDs = eids
		}
		cveDetails[cveName] = det
		cveNames[cveID] = cveName
	}
	return cveDetails, cveNames
}

func loadPkgErrataModule(info string) map[PkgErrata][]int {
	defer utils.TimeTrack(time.Now(), info)

	orderBy := "pkg_id,errata_id,module_stream_id"
	table := "errata_modulepkg"
	pkgIDs := loadIntArray(table, "pkg_id", orderBy)
	errataIDs := loadIntArray(table, "errata_id", orderBy)
	moduleStreamIDs := loadIntArray(table, "module_stream_id", orderBy)

	m := map[PkgErrata][]int{}

	for i := 0; i < len(pkgIDs); i++ {
		pkgErrata := PkgErrata{pkgIDs[i], errataIDs[i]}
		_, ok := m[pkgErrata]
		if !ok {
			m[pkgErrata] = []int{}
		}

		m[pkgErrata] = append(m[pkgErrata], moduleStreamIDs[i])
	}
	return m
}

func loadModule2IDs(info string) map[ModuleStream][]int {
	defer utils.TimeTrack(time.Now(), info)

	orderBy := "module,stream"
	table := "module_stream"
	modules := loadStrArray(table, "module", orderBy)
	streams := loadStrArray(table, "stream", orderBy)
	streamIDs := loadIntArray(table, "stream_id", orderBy)

	m := map[ModuleStream][]int{}

	for i := 0; i < len(modules); i++ {
		pkgErrata := ModuleStream{modules[i], streams[i]}
		_, ok := m[pkgErrata]
		if !ok {
			m[pkgErrata] = []int{}
		}

		m[pkgErrata] = append(m[pkgErrata], streamIDs[i])
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

func loadDBChanges(info string) DBChange {
	defer utils.TimeTrack(time.Now(), info)

	rows := getAllRows("dbchange", "*", "errata_changes")
	arr := []DBChange{}
	for rows.Next() {
		var item DBChange
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

func loadErrataModules() map[int][]Module {
	defer utils.TimeTrack(time.Now(), "errata2module")

	rows := getAllRows("errata_module", "*", "errata_id")

	erID2modules := map[int][]Module{}
	for rows.Next() {
		var erID int
		var mod Module
		err := rows.Scan(&erID, &mod.Name, &mod.StreamID, &mod.Stream, &mod.Version, &mod.Context)
		if err != nil {
			panic(err)
		}

		_, ok := erID2modules[erID]
		if !ok {
			erID2modules[erID] = []Module{}
		}

		erID2modules[erID] = append(erID2modules[erID], mod)
	}
	return erID2modules
}

func loadOvalDefinitionDetail() map[DefinitionID]DefinitionDetail {
	defer utils.TimeTrack(time.Now(), "oval_definition_detail")

	type OvalDefinitionDetail struct {
		ID               DefinitionID
		DefinitionTypeID int
		CriteriaID       CriteriaID
	}

	row := OvalDefinitionDetail{}
	defDetail := make(map[DefinitionID]DefinitionDetail)
	rows := getAllRows("oval_definition_detail", "id,definition_type_id,criteria_id", "id")

	for rows.Next() {
		if err := rows.Scan(&row.ID, &row.DefinitionTypeID, &row.CriteriaID); err != nil {
			panic(err)
		}
		defDetail[row.ID] = DefinitionDetail{
			DefinitionTypeID: row.DefinitionTypeID,
			CriteriaID:       row.CriteriaID,
		}
	}
	return defDetail
}

func loadOvalDefinitionCves(info string) map[DefinitionID][]string {
	defer utils.TimeTrack(time.Now(), info)

	type OvalDefinitionCve struct {
		DefinitionID DefinitionID
		Cve          string
	}
	r := OvalDefinitionCve{}
	ret := make(map[DefinitionID][]string)
	cols := "definition_id,cve"
	rows := getAllRows("oval_definition_cve", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.DefinitionID, &r.Cve); err != nil {
			panic(err)
		}
		ret[r.DefinitionID] = append(ret[r.DefinitionID], r.Cve)
	}
	return ret
}

func loadPackagenameID2DefinitionIDs(info string) map[NameID][]DefinitionID {
	defer utils.TimeTrack(time.Now(), info)

	type NameDefinition struct {
		NameID       NameID
		DefinitionID DefinitionID
	}
	r := NameDefinition{}
	ret := make(map[NameID][]DefinitionID)
	cols := "name_id,definition_id"
	rows := getAllRows("packagename_oval_definition", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.NameID, &r.DefinitionID); err != nil {
			panic(err)
		}
		ret[r.NameID] = append(ret[r.NameID], r.DefinitionID)
	}
	return ret
}

func loadRepoCpes(info string) map[RepoID][]CpeID {
	defer utils.TimeTrack(time.Now(), info)

	type CpeRepo struct {
		RepoID RepoID
		CpeID  CpeID
	}
	r := CpeRepo{}
	ret := make(map[RepoID][]CpeID)
	cols := "repo_id,cpe_id"
	rows := getAllRows("cpe_repo", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.RepoID, &r.CpeID); err != nil {
			panic(err)
		}
		ret[r.RepoID] = append(ret[r.RepoID], r.CpeID)
	}
	return ret
}

func loadContentSet2Cpes(info string) map[ContentSetID][]CpeID {
	defer utils.TimeTrack(time.Now(), info)

	type CpeCS struct {
		ContentSetID ContentSetID
		CpeID        CpeID
	}
	r := CpeCS{}
	ret := make(map[ContentSetID][]CpeID)
	cols := "content_set_id,cpe_id"
	rows := getAllRows("cpe_content_set", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.ContentSetID, &r.CpeID); err != nil {
			panic(err)
		}
		ret[r.ContentSetID] = append(ret[r.ContentSetID], r.CpeID)
	}
	return ret
}

func loadCpeID2DefinitionIDs(info string) map[CpeID][]DefinitionID {
	defer utils.TimeTrack(time.Now(), info)

	type DefinitionCpe struct {
		CpeID        CpeID
		DefinitionID DefinitionID
	}
	r := DefinitionCpe{}
	ret := make(map[CpeID][]DefinitionID)
	cols := "cpe_id,definition_id"
	rows := getAllRows("oval_definition_cpe", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.CpeID, &r.DefinitionID); err != nil {
			panic(err)
		}
		ret[r.CpeID] = append(ret[r.CpeID], r.DefinitionID)
	}
	return ret
}

func loadOvalCriteriaDependency(info string) (map[CriteriaID][]CriteriaID, map[CriteriaID][]TestID,
	map[CriteriaID][]ModuleTestID,
) {
	defer utils.TimeTrack(time.Now(), info)

	type OvalCriteriaDep struct {
		ParentCriteriaID CriteriaID
		DepCriteriaID    CriteriaID
		DepTestID        TestID
		DepModuleTestID  ModuleTestID
	}

	r := OvalCriteriaDep{}
	criteriaID2DepCriteriaIDs := make(map[CriteriaID][]CriteriaID)
	criteriaID2DepTestIDs := make(map[CriteriaID][]TestID)
	criteriaID2DepModuleTestIDs := make(map[CriteriaID][]ModuleTestID)

	cols := "parent_criteria_id,COALESCE(dep_criteria_id, 0),COALESCE(dep_test_id, 0),COALESCE(dep_module_test_id, 0)"
	rows := getAllRows("oval_criteria_dependency", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.ParentCriteriaID, &r.DepCriteriaID, &r.DepTestID, &r.DepModuleTestID); err != nil {
			panic(err)
		}
		if _, ok := criteriaID2DepCriteriaIDs[r.ParentCriteriaID]; !ok {
			criteriaID2DepCriteriaIDs[r.ParentCriteriaID] = []CriteriaID{}
			criteriaID2DepTestIDs[r.ParentCriteriaID] = []TestID{}
			criteriaID2DepModuleTestIDs[r.ParentCriteriaID] = []ModuleTestID{}
		}
		if r.DepCriteriaID != 0 {
			criteriaID2DepCriteriaIDs[r.ParentCriteriaID] = append(criteriaID2DepCriteriaIDs[r.ParentCriteriaID],
				r.DepCriteriaID)
		}
		if r.DepTestID != 0 {
			criteriaID2DepTestIDs[r.ParentCriteriaID] = append(criteriaID2DepTestIDs[r.ParentCriteriaID], r.DepTestID)
		}
		if r.DepModuleTestID != 0 {
			criteriaID2DepModuleTestIDs[r.ParentCriteriaID] = append(criteriaID2DepModuleTestIDs[r.ParentCriteriaID],
				r.DepModuleTestID)
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

	r := OvalCriteriaType{}
	criteriaID2Type := make(map[CriteriaID]int)
	cols := "criteria_id,type_id"
	rows := getAllRows("oval_criteria_type", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.CriteriaID, &r.TypeID); err != nil {
			panic(err)
		}
		criteriaID2Type[r.CriteriaID] = r.TypeID
	}
	return criteriaID2Type
}

func loadOvalStateID2Arches(info string) map[OvalStateID][]ArchID {
	defer utils.TimeTrack(time.Now(), info)

	type StateArch struct {
		StateID OvalStateID
		ArchID  ArchID
	}
	r := StateArch{}
	ret := make(map[OvalStateID][]ArchID)
	cols := "state_id,arch_id"
	rows := getAllRows("oval_state_arch", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.StateID, &r.ArchID); err != nil {
			panic(err)
		}
		ret[r.StateID] = append(ret[r.StateID], r.ArchID)
	}
	return ret
}

func loadOvalModuleTestDetail(info string) map[ModuleTestID]OvalModuleTestDetail {
	defer utils.TimeTrack(time.Now(), info)

	type ModuleTestDetail struct {
		ID           ModuleTestID
		ModuleStream string
	}

	r := ModuleTestDetail{}
	details := make(map[ModuleTestID]OvalModuleTestDetail)
	cols := "id,module_stream"
	rows := getAllRows("oval_module_test_detail", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.ModuleStream); err != nil {
			panic(err)
		}
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

	r := TestDetail{}
	testDetail := make(map[TestID]OvalTestDetail)
	cols := "id,package_name_id,check_existence_id"
	rows := getAllRows("oval_test_detail", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.PackageNameID, &r.CheckExistenceID); err != nil {
			panic(err)
		}
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

	r := TestState{}
	test2State := make(map[TestID][]OvalState)
	cols := "test_id,state_id,evr_id,evr_operation_id"
	rows := getAllRows("oval_test_state", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.TestID, &r.StateID, &r.EvrID, &r.EvrOperationID); err != nil {
			panic(err)
		}
		test2State[r.TestID] = append(test2State[r.TestID], OvalState{
			ID:           r.StateID,
			EvrID:        r.EvrID,
			OperationEvr: r.EvrOperationID,
		})
	}
	return test2State
}
