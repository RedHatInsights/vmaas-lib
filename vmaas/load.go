package vmaas

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/conf"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"

	_ "github.com/mattn/go-sqlite3" // sqlite driver for cache load
)

var (
	lock  = &sync.Mutex{}
	sqlDB *sql.DB
)

var loadFuncs = []func(c *Cache){
	loadPkgNames, loadUpdates, loadUpdatesIndex, loadEvrMaps, loadArchs, loadArchCompat, loadPkgDetails,
	loadRepoDetails, loadLabel2ContentSetID, loadPkgRepos, loadErrata, loadPkgErratum, loadErrataRepoIDs,
	loadCves, loadPkgErratumModule, loadModule2IDs, loadModuleRequires, loadDBChanges, loadString,
	// OVAL
	loadOvalDefinitionDetail, loadOvalDefinitionCves, loadPackagenameID2DefinitionIDs, loadRepoCpes,
	loadContentSet2Cpes, loadCpeID2DefinitionIDs, loadOvalCriteriaDependency, loadOvalCriteriaID2Type,
	loadOvalStateID2Arches, loadOvalModuleTestDetail, loadOvalTestDetail, loadOvalTestID2States,
	loadOvalDefinitionErrata, loadCpeID2Label,
}

func openDB(path string) error {
	var err error
	if _, err := os.Stat(path); err != nil {
		return errors.Wrap(err, "file does not exist")
	}
	sqlDB, err = sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		return errors.Wrap(err, "couldn't open sqlite")
	}
	// sql.Open does not show error when the file is not a valid sqlite DB
	rows, err := sqlDB.Query("select 1 from updates")
	if err != nil {
		sqlDB = nil
		return errors.Wrap(err, "database is not loaded")
	}
	defer rows.Close()
	return nil
}

func closeDB() {
	if err := sqlDB.Close(); err != nil {
		utils.LogWarn("err", err.Error(), "Could not close DB")
	}
	sqlDB = nil
}

// Make sure only one load at a time is performed
func loadCache(path string) (*Cache, error) {
	lock.Lock()
	defer lock.Unlock()
	start := time.Now()

	if err := openDB(path); err != nil {
		return nil, err
	}
	defer closeDB()

	c := Cache{}

	var wg sync.WaitGroup
	guard := make(chan struct{}, conf.Env.MaxGoroutines)
	for _, fn := range loadFuncs {
		wg.Add(1)
		guard <- struct{}{}
		go func(fn func(c *Cache)) {
			fn(&c)
			<-guard
			wg.Done()
		}(fn)
	}

	wg.Wait()
	utils.LogInfo("elapsed", fmt.Sprint(time.Since(start)), "Cache loaded successfully")
	return &c, nil
}

func loadErrataRepoIDs(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ErratumID2RepoIDs")

	type ErrataRepo struct {
		ErratumID ErratumID
		RepoID    RepoID
	}
	r := ErrataRepo{}
	cnt := getCount("errata_repo", "distinct errata_id")
	m := make(map[ErratumID]map[RepoID]bool, cnt)
	rows := getAllRows("errata_repo", "errata_id,repo_id")

	for rows.Next() {
		if err := rows.Scan(&r.ErratumID, &r.RepoID); err != nil {
			panic(err)
		}
		errataMap := m[r.ErratumID]
		if errataMap == nil {
			errataMap = map[RepoID]bool{}
		}
		errataMap[r.RepoID] = true
		m[r.ErratumID] = errataMap
	}
	c.ErratumID2RepoIDs = m
}

func loadPkgErratum(c *Cache) {
	cnt := getCount("pkg_errata", "distinct pkg_id")
	pkgToErrata := make(map[PkgID][]ErratumID, cnt)
	for k, v := range loadInt2Ints("pkg_errata", "pkg_id,errata_id", "PkgID2ErrataIDs") {
		id := PkgID(k)
		for _, i := range v {
			pkgToErrata[id] = append(pkgToErrata[id], ErratumID(i))
		}
	}
	c.PkgID2ErrataIDs = pkgToErrata
}

func loadPkgRepos(c *Cache) {
	defer utils.TimeTrack(time.Now(), "PkgRepos")

	nPkg := getCount("pkg_repo", "distinct pkg_id")
	res := make(map[PkgID][]RepoID, nPkg)
	var n PkgID
	var p RepoID

	doForRows("select pkg_id, repo_id from pkg_repo", func(row *sql.Rows) {
		err := row.Scan(&n, &p)
		if err != nil {
			panic(err)
		}
		res[n] = append(res[n], p)
	})
	c.PkgID2RepoIDs = res
}

func loadPkgNames(c *Cache) {
	defer utils.TimeTrack(time.Now(), "PkgNames")

	type PkgName struct {
		ID          NameID
		Packagename string
	}

	r := PkgName{}
	cnt := getCount("packagename", "*")
	id2name := make(map[NameID]string, cnt)
	name2id := make(map[string]NameID, cnt)
	rows := getAllRows("packagename", "id,packagename")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Packagename); err != nil {
			panic(err)
		}
		id2name[r.ID] = r.Packagename
		name2id[r.Packagename] = r.ID
	}
	c.ID2Packagename = id2name
	c.Packagename2ID = name2id
}

func loadUpdates(c *Cache) {
	defer utils.TimeTrack(time.Now(), "Updates")

	cnt := getCount("updates", "distinct name_id")
	res := make(map[NameID][]PkgID, cnt)
	var n NameID
	var p PkgID
	doForRows("select name_id, package_id from updates order by package_order", func(row *sql.Rows) {
		err := row.Scan(&n, &p)
		if err != nil {
			panic(err)
		}
		res[n] = append(res[n], p)
	})
	c.Updates = res
}

func loadUpdatesIndex(c *Cache) {
	defer utils.TimeTrack(time.Now(), "Updates index")
	cnt := getCount("updates_index", "distinct name_id")
	res := make(map[NameID]map[EvrID][]int, cnt)
	var n NameID
	var e EvrID
	var o int
	doForRows("select name_id, evr_id, package_order from updates_index order by package_order", func(row *sql.Rows) {
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
	c.UpdatesIndex = res
}

func getCount(tableName, col string) (cnt int) {
	row := sqlDB.QueryRow(fmt.Sprintf("select count(%s) from %s", col, tableName))
	if err := row.Scan(&cnt); err != nil {
		panic(err)
	}
	return cnt
}

func getAllRows(tableName, cols string) *sql.Rows {
	rows, err := sqlDB.Query(fmt.Sprintf("SELECT %s FROM %s", cols, tableName))
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

func loadEvrMaps(c *Cache) {
	defer utils.TimeTrack(time.Now(), "EVR")

	type IDEvr struct {
		ID EvrID
		utils.Evr
	}

	r := IDEvr{}
	cnt := getCount("evr", "*")
	id2evr := make(map[EvrID]utils.Evr, cnt)
	evr2id := map[utils.Evr]EvrID{}
	rows := getAllRows("evr", "id,epoch,version,release")

	for rows.Next() {
		//nolint:typecheck,nolintlint // false-positive, r.Epoch undefined (type IDEvr has no field or method Epoch)
		if err := rows.Scan(&r.ID, &r.Epoch, &r.Version, &r.Release); err != nil {
			panic(err)
		}
		id2evr[r.ID] = r.Evr
		evr2id[r.Evr] = r.ID
	}
	c.ID2Evr = id2evr
	c.Evr2ID = evr2id
}

func loadArchs(c *Cache) {
	defer utils.TimeTrack(time.Now(), "Arch")

	type Arch struct {
		ID   ArchID
		Arch string
	}
	r := Arch{}
	cnt := getCount("arch", "*")
	id2arch := make(map[ArchID]string, cnt)
	arch2id := make(map[string]ArchID, cnt)
	rows := getAllRows("arch", "id,arch")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Arch); err != nil {
			panic(err)
		}
		id2arch[r.ID] = r.Arch
		arch2id[r.Arch] = r.ID
	}
	c.ID2Arch = id2arch
	c.Arch2ID = arch2id
}

func loadArchCompat(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ArchCompat")

	type ArchCompat struct {
		FromArchID ArchID
		ToArchID   ArchID
	}
	r := ArchCompat{}
	cnt := getCount("arch_compat", "distinct from_arch_id")
	m := make(map[ArchID]map[ArchID]bool, cnt)
	rows := getAllRows("arch_compat", "from_arch_id,to_arch_id")

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
	c.ArchCompat = m
}

func loadPkgDetails(c *Cache) {
	defer utils.TimeTrack(time.Now(), "PackageDetails, Nevra2PkgID, SrcPkgID2PkgID")

	rows := getAllRows("package_detail", "*")
	cnt := getCount("package_detail", "*")
	cntSrc := getCount("package_detail", "distinct source_package_id")
	id2pkdDetail := make(map[PkgID]PackageDetail, cnt)
	nevra2id := make(map[Nevra]PkgID, cnt)
	srcPkgID2PkgID := make(map[PkgID][]PkgID, cntSrc)
	var pkgID PkgID
	for rows.Next() {
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
	// FIXME: build ModifiedID index (probably not needed for vulnerabilities/updates)
	c.PackageDetails = id2pkdDetail
	c.Nevra2PkgID = nevra2id
	c.SrcPkgID2PkgID = srcPkgID2PkgID
}

func loadRepoDetails(c *Cache) { //nolint: funlen
	defer utils.TimeTrack(time.Now(), "RepoIDs, RepoDetails, RepoLabel2IDs, RepoPath2IDs, ProductID2RepoIDs")

	rows := getAllRows(
		"repo_detail",
		"id,label,name,url,COALESCE(basearch,''),COALESCE(releasever,''),product,product_id,revision,third_party",
	)
	cntRepo := getCount("repo_detail", "*")
	cntLabel := getCount("repo_detail", "distinct label")
	cntURL := getCount("repo_detail", "distinct url")
	cntProd := getCount("repo_detail", "distinct product_id")
	id2repoDetail := make(map[RepoID]RepoDetail, cntRepo)
	repoLabel2id := make(map[string][]RepoID, cntLabel)
	repoPath2id := make(map[string][]RepoID, cntURL)
	prodID2RepoIDs := make(map[int][]RepoID, cntProd)
	repoIDs := []RepoID{}
	var repoID RepoID
	for rows.Next() {
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

		if len(det.URL) > 0 {
			parsedURL, err := url.Parse(det.URL)
			if err != nil {
				utils.LogWarn("URL", det.URL, "err", err.Error(), "Malformed repository URL")
			}
			repoPath := strings.TrimSuffix(parsedURL.Path, "/")
			_, ok = repoPath2id[repoPath]
			if !ok {
				repoPath2id[repoPath] = []RepoID{}
			}
			repoPath2id[repoPath] = append(repoPath2id[repoPath], repoID)
		}

		_, ok = prodID2RepoIDs[det.ProductID]
		if !ok {
			prodID2RepoIDs[det.ProductID] = []RepoID{}
		}
		prodID2RepoIDs[det.ProductID] = append(prodID2RepoIDs[det.ProductID], repoID)
	}
	c.RepoIDs = repoIDs
	c.RepoDetails = id2repoDetail
	c.RepoLabel2IDs = repoLabel2id
	c.RepoPath2IDs = repoPath2id
	c.ProductID2RepoIDs = prodID2RepoIDs
}

func loadLabel2ContentSetID(c *Cache) {
	defer utils.TimeTrack(time.Now(), "Label2ContentSetID")

	type LabelContent struct {
		ID    ContentSetID
		Label string
	}

	r := LabelContent{}
	cnt := getCount("content_set", "*")
	label2contentSetID := make(map[string]ContentSetID, cnt)
	rows := getAllRows("content_set", "id,label")

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.Label); err != nil {
			panic(err)
		}
		label2contentSetID[r.Label] = r.ID
	}
	c.Label2ContentSetID = label2contentSetID
}

func loadErrata(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ErratumDetails, ErratumID2Name")

	erID2cves := loadInt2Strings("errata_cve", "errata_id,cve", "erID2cves")
	erID2pkgIDs := loadInt2Ints("pkg_errata", "errata_id,pkg_id", "erID2pkgID")
	erID2modulePkgIDs := loadInt2Ints("errata_modulepkg", "errata_id,pkg_id", "erID2modulePkgIDs")
	erID2bzs := loadInt2Strings("errata_bugzilla", "errata_id,bugzilla", "erID2bzs")
	erID2refs := loadInt2Strings("errata_refs", "errata_id,ref", "erID2refs")
	erID2modules := loadErrataModules()

	cols := "ID,name,synopsis,summary,type,severity,description,solution,issued,updated,url,third_party,requires_reboot" //nolint:lll,nolintlint
	rows := getAllRows("errata_detail", cols)
	erratumDetails := map[string]ErratumDetail{}
	erratumID2Name := map[ErratumID]string{}
	var erratumID ErratumID
	var errataName string
	for rows.Next() {
		var det ErratumDetail
		err := rows.Scan(&erratumID, &errataName, &det.Synopsis, &det.Summary, &det.Type, &det.Severity,
			&det.Description, &det.Solution, &det.Issued, &det.Updated, &det.URL, &det.ThirdParty, &det.RequiresReboot)
		if err != nil {
			panic(err)
		}
		erratumID2Name[erratumID] = errataName

		det.ID = erratumID
		if cves, ok := erID2cves[int(erratumID)]; ok {
			det.CVEs = cves
		}

		if pkgIDs, ok := erID2pkgIDs[int(erratumID)]; ok {
			det.PkgIDs = pkgIDs
		}

		if modulePkgIDs, ok := erID2modulePkgIDs[int(erratumID)]; ok {
			det.ModulePkgIDs = modulePkgIDs
		}

		if bzs, ok := erID2bzs[int(erratumID)]; ok {
			det.Bugzillas = bzs
		}

		if refs, ok := erID2refs[int(erratumID)]; ok {
			det.Refs = refs
		}

		if modules, ok := erID2modules[int(erratumID)]; ok {
			det.Modules = modules
		}
		erratumDetails[errataName] = det
	}
	c.ErratumDetails = erratumDetails
	c.ErratumID2Name = erratumID2Name
}

func loadCves(c *Cache) {
	defer utils.TimeTrack(time.Now(), "CveDetail")

	cveID2cwes := loadInt2Strings("cve_cwe", "cve_id,cwe", "cveID2cwes")
	cveID2pkg := loadInt2Ints("cve_pkg", "cve_id,pkg_id", "cveID2pkg")
	cve2eid := loadString2Ints("errata_cve", "cve,errata_id", "cve2eid")

	rows := getAllRows("cve_detail", "*")
	cnt := getCount("cve_detail", "*")
	cveDetails := make(map[string]CveDetail, cnt)
	cveNames := make(map[int]string, cnt)
	var cveID int
	var cveName string
	for rows.Next() {
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
	c.CveDetail = cveDetails
	c.CveNames = cveNames
}

func loadPkgErratumModule(c *Cache) {
	defer utils.TimeTrack(time.Now(), "PkgErratum2Module")

	cols := "pkg_id,errata_id,module_stream_id"
	table := "errata_modulepkg"

	type PkgErratum2ModuleSelect struct {
		PkgID     PkgID
		ErratumID ErratumID
		ModuleID  int
	}

	r := PkgErratum2ModuleSelect{}
	cnt := getCount("(select count(*) from errata_modulepkg group by pkg_id, errata_id)", "*")
	rows := getAllRows(table, cols)
	m := make(map[PkgErratum][]int, cnt)

	for rows.Next() {
		if err := rows.Scan(&r.PkgID, &r.ErratumID, &r.ModuleID); err != nil {
			panic(err)
		}
		pkgErratum := PkgErratum{r.PkgID, r.ErratumID}
		if _, ok := m[pkgErratum]; !ok {
			m[pkgErratum] = []int{}
		}
		m[pkgErratum] = append(m[pkgErratum], r.ModuleID)
	}

	c.PkgErratum2Module = m
}

func loadModule2IDs(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ModuleName2IDs")

	cols := "module,stream,stream_id"
	table := "module_stream"

	type ModuleStreamIDs struct {
		Module string
		Stream string
		ID     int
	}

	r := ModuleStreamIDs{}
	cnt := getCount("(select count(*) from module_stream group by module, stream)", "*")
	rows := getAllRows(table, cols)

	m := make(map[ModuleStream][]int, cnt)

	for rows.Next() {
		if err := rows.Scan(&r.Module, &r.Stream, &r.ID); err != nil {
			panic(err)
		}
		ms := ModuleStream{r.Module, r.Stream}
		if _, ok := m[ms]; !ok {
			m[ms] = []int{}
		}
		m[ms] = append(m[ms], r.ID)
	}

	c.Module2IDs = m
}

func loadModuleRequires(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ModuleRequire")

	table := "module_stream_require"
	moduleRequires := loadInt2Ints(table, "stream_id,require_id", "module2requires")
	c.ModuleRequires = moduleRequires
}

func loadString(c *Cache) {
	defer utils.TimeTrack(time.Now(), "String")

	cnt := getCount("string", "*")
	rows := getAllRows("string", "*")
	m := make(map[int]string, cnt)
	var id int
	var str *string
	for rows.Next() {
		err := rows.Scan(&id, &str)
		if err != nil {
			panic(err)
		}
		if str != nil {
			m[id] = *str
		}
	}
	c.String = m
}

func loadDBChanges(c *Cache) {
	defer utils.TimeTrack(time.Now(), "DBChange")

	rows := getAllRows("dbchange", "*")
	arr := []DBChange{}
	var item DBChange
	for rows.Next() {
		err := rows.Scan(&item.ErrataChanges, &item.CveChanges, &item.RepoChanges,
			&item.LastChange, &item.Exported)
		if err != nil {
			panic(err)
		}
		arr = append(arr, item)
	}
	c.DBChange = arr[0]
}

func loadInt2Ints(table, cols, info string) map[int][]int {
	defer utils.TimeTrack(time.Now(), info)

	splitted := strings.Split(cols, ",")
	cnt := getCount(table, fmt.Sprintf("distinct %s", splitted[0]))
	rows := getAllRows(table, cols)
	int2ints := make(map[int][]int, cnt)
	var key int
	var val int
	for rows.Next() {
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

	splitted := strings.Split(cols, ",")
	cnt := getCount(table, fmt.Sprintf("distinct %s", splitted[0]))
	rows := getAllRows(table, cols)
	int2strs := make(map[int][]string, cnt)
	var key int
	var val string
	for rows.Next() {
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

	splitted := strings.Split(cols, ",")
	cnt := getCount(table, fmt.Sprintf("distinct %s", splitted[0]))
	rows := getAllRows(table, cols)
	int2strs := make(map[string][]int, cnt)
	var key string
	var val int
	for rows.Next() {
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

	rows := getAllRows("errata_module", "*")
	cnt := getCount("errata_module", "errata_id")
	erID2modules := make(map[int][]Module, cnt)
	var erID int
	var mod Module
	for rows.Next() {
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

func loadOvalDefinitionDetail(c *Cache) {
	defer utils.TimeTrack(time.Now(), "oval_definition_detail")

	row := DefinitionDetail{}
	cnt := getCount("oval_definition_detail", "*")
	defDetail := make(map[DefinitionID]DefinitionDetail, cnt)
	rows := getAllRows("oval_definition_detail", "id,definition_type_id,criteria_id")

	for rows.Next() {
		if err := rows.Scan(&row.ID, &row.DefinitionTypeID, &row.CriteriaID); err != nil {
			panic(err)
		}
		defDetail[row.ID] = row
	}
	c.OvaldefinitionDetail = defDetail
}

func loadOvalDefinitionCves(c *Cache) {
	defer utils.TimeTrack(time.Now(), "oval_definition_cve")

	type OvalDefinitionCve struct {
		DefinitionID DefinitionID
		Cve          string
	}
	r := OvalDefinitionCve{}
	cnt := getCount("oval_definition_cve", "distinct definition_id")
	ret := make(map[DefinitionID][]string, cnt)
	cols := "definition_id,cve"
	rows := getAllRows("oval_definition_cve", cols)

	for rows.Next() {
		if err := rows.Scan(&r.DefinitionID, &r.Cve); err != nil {
			panic(err)
		}
		ret[r.DefinitionID] = append(ret[r.DefinitionID], r.Cve)
	}
	c.OvaldefinitionID2Cves = ret
}

func loadPackagenameID2DefinitionIDs(c *Cache) {
	defer utils.TimeTrack(time.Now(), "PackagenameID2definitionIDs")

	type NameDefinition struct {
		NameID       NameID
		DefinitionID DefinitionID
	}
	r := NameDefinition{}
	cnt := getCount("packagename_oval_definition", "distinct name_id")
	ret := make(map[NameID][]DefinitionID, cnt)
	cols := "name_id,definition_id"
	rows := getAllRows("packagename_oval_definition", cols)

	for rows.Next() {
		if err := rows.Scan(&r.NameID, &r.DefinitionID); err != nil {
			panic(err)
		}
		ret[r.NameID] = append(ret[r.NameID], r.DefinitionID)
	}
	c.PackagenameID2definitionIDs = ret
}

func loadRepoCpes(c *Cache) {
	defer utils.TimeTrack(time.Now(), "RepoID2CpeIDs")

	type CpeRepo struct {
		RepoID RepoID
		CpeID  CpeID
	}
	r := CpeRepo{}
	cnt := getCount("cpe_repo", "distinct repo_id")
	ret := make(map[RepoID][]CpeID, cnt)
	cols := "repo_id,cpe_id"
	rows := getAllRows("cpe_repo", cols)

	for rows.Next() {
		if err := rows.Scan(&r.RepoID, &r.CpeID); err != nil {
			panic(err)
		}
		ret[r.RepoID] = append(ret[r.RepoID], r.CpeID)
	}
	c.RepoID2CpeIDs = ret
}

func loadContentSet2Cpes(c *Cache) {
	defer utils.TimeTrack(time.Now(), "ContentSetID2CpeIDs")

	type CpeCS struct {
		ContentSetID ContentSetID
		CpeID        CpeID
	}
	r := CpeCS{}
	cnt := getCount("cpe_content_set", "distinct content_set_id")
	ret := make(map[ContentSetID][]CpeID, cnt)
	cols := "content_set_id,cpe_id"
	rows := getAllRows("cpe_content_set", cols)

	for rows.Next() {
		if err := rows.Scan(&r.ContentSetID, &r.CpeID); err != nil {
			panic(err)
		}
		ret[r.ContentSetID] = append(ret[r.ContentSetID], r.CpeID)
	}
	c.ContentSetID2CpeIDs = ret
}

func loadCpeID2DefinitionIDs(c *Cache) {
	defer utils.TimeTrack(time.Now(), "CpeID2OvalDefinitionIDs")

	type DefinitionCpe struct {
		CpeID        CpeID
		DefinitionID DefinitionID
	}
	r := DefinitionCpe{}
	cnt := getCount("oval_definition_cpe", "distinct cpe_id")
	ret := make(map[CpeID][]DefinitionID, cnt)
	cols := "cpe_id,definition_id"
	rows := getAllRows("oval_definition_cpe", cols)

	for rows.Next() {
		if err := rows.Scan(&r.CpeID, &r.DefinitionID); err != nil {
			panic(err)
		}
		ret[r.CpeID] = append(ret[r.CpeID], r.DefinitionID)
	}
	c.CpeID2OvalDefinitionIDs = ret
}

func loadOvalCriteriaDependency(c *Cache) {
	defer utils.TimeTrack(
		time.Now(),
		"OvalCriteriaID2DepCriteriaIDs, OvalCriteriaID2DepTestIDs, OvalCriteriaID2DepModuleTestIDs",
	)

	type OvalCriteriaDep struct {
		ParentCriteriaID CriteriaID
		DepCriteriaID    CriteriaID
		DepTestID        TestID
		DepModuleTestID  ModuleTestID
	}

	r := OvalCriteriaDep{}

	cnt := getCount("oval_criteria_dependency", "distinct parent_criteria_id")
	criteriaID2DepCriteriaIDs := make(map[CriteriaID][]CriteriaID, cnt)
	criteriaID2DepTestIDs := make(map[CriteriaID][]TestID, cnt)
	criteriaID2DepModuleTestIDs := make(map[CriteriaID][]ModuleTestID, cnt)

	cols := "parent_criteria_id,COALESCE(dep_criteria_id, 0),COALESCE(dep_test_id, 0),COALESCE(dep_module_test_id, 0)"
	rows := getAllRows("oval_criteria_dependency", cols)

	for rows.Next() {
		if err := rows.Scan(&r.ParentCriteriaID, &r.DepCriteriaID, &r.DepTestID, &r.DepModuleTestID); err != nil {
			panic(err)
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
	c.OvalCriteriaID2DepCriteriaIDs = criteriaID2DepCriteriaIDs
	c.OvalCriteriaID2DepTestIDs = criteriaID2DepTestIDs
	c.OvalCriteriaID2DepModuleTestIDs = criteriaID2DepModuleTestIDs
}

func loadOvalCriteriaID2Type(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalCriteriaID2Type")

	type OvalCriteriaType struct {
		CriteriaID CriteriaID
		TypeID     int
	}

	r := OvalCriteriaType{}
	cnt := getCount("oval_criteria_type", "*")
	criteriaID2Type := make(map[CriteriaID]int, cnt)
	cols := "criteria_id,type_id"
	rows := getAllRows("oval_criteria_type", cols)

	for rows.Next() {
		if err := rows.Scan(&r.CriteriaID, &r.TypeID); err != nil {
			panic(err)
		}
		criteriaID2Type[r.CriteriaID] = r.TypeID
	}
	c.OvalCriteriaID2Type = criteriaID2Type
}

func loadOvalStateID2Arches(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalModuleTestDetail")

	type StateArch struct {
		StateID OvalStateID
		ArchID  ArchID
	}
	r := StateArch{}
	cnt := getCount("oval_state_arch", "distinct state_id")
	ret := make(map[OvalStateID][]ArchID, cnt)
	cols := "state_id,arch_id"
	rows := getAllRows("oval_state_arch", cols)

	for rows.Next() {
		if err := rows.Scan(&r.StateID, &r.ArchID); err != nil {
			panic(err)
		}
		ret[r.StateID] = append(ret[r.StateID], r.ArchID)
	}
	c.OvalStateID2Arches = ret
}

func loadOvalModuleTestDetail(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalModuleTestDetail")

	type ModuleTestDetail struct {
		ID           ModuleTestID
		ModuleStream string
	}

	r := ModuleTestDetail{}
	cnt := getCount("oval_module_test_detail", "*")
	details := make(map[ModuleTestID]OvalModuleTestDetail, cnt)
	cols := "id,module_stream"
	rows := getAllRows("oval_module_test_detail", cols)

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.ModuleStream); err != nil {
			panic(err)
		}
		splitted := strings.Split(r.ModuleStream, ":")
		details[r.ID] = OvalModuleTestDetail{
			ModuleStream: ModuleStream{Module: splitted[0], Stream: splitted[1]},
		}
	}
	c.OvalModuleTestDetail = details
}

func loadOvalTestDetail(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalTestDetail")

	type TestDetail struct {
		ID               TestID
		PackageNameID    NameID
		CheckExistenceID int
	}

	r := TestDetail{}
	cnt := getCount("oval_test_detail", "*")
	testDetail := make(map[TestID]OvalTestDetail, cnt)
	cols := "id,package_name_id,check_existence_id"
	rows := getAllRows("oval_test_detail", cols)

	for rows.Next() {
		if err := rows.Scan(&r.ID, &r.PackageNameID, &r.CheckExistenceID); err != nil {
			panic(err)
		}
		testDetail[r.ID] = OvalTestDetail{PkgNameID: r.PackageNameID, CheckExistence: r.CheckExistenceID}
	}
	c.OvalTestDetail = testDetail
}

func loadOvalTestID2States(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalTestID2States")

	type TestState struct {
		TestID         TestID
		StateID        OvalStateID
		EvrID          EvrID
		EvrOperationID int
	}

	r := TestState{}
	cnt := getCount("oval_test_state", "*")
	test2State := make(map[TestID][]OvalState, cnt)
	cols := "test_id,state_id,evr_id,evr_operation_id"
	rows := getAllRows("oval_test_state", cols)

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
	c.OvalTestID2States = test2State
}

func loadOvalDefinitionErrata(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OvalDefinitionID2ErrataIDs")

	type OvalDefinitionErrataSelect struct {
		DefinitionID DefinitionID
		ErratumID    ErratumID
	}

	cols := "definition_id,errata_id"
	rows := getAllRows("oval_definition_errata", cols)
	cnt := getCount("oval_definition_errata", "distinct definition_id")
	row := OvalDefinitionErrataSelect{}
	// TODO: investigate - it looks like 1 definitionID is always mapped to 1 erratum
	//       and 1 erratum can be associated with multiple definitions
	//       we might not need `map[DefinitionID][]ErratumID` but `map[DefinitionID]ErratumID`
	definitionErrata := make(map[DefinitionID][]ErratumID, cnt)

	for rows.Next() {
		if err := rows.Scan(&row.DefinitionID, &row.ErratumID); err != nil {
			panic(err)
		}
		definitionErrata[row.DefinitionID] = append(definitionErrata[row.DefinitionID], row.ErratumID)
	}
	c.OvalDefinitionID2ErrataIDs = definitionErrata
}

func loadCpeID2Label(c *Cache) {
	defer utils.TimeTrack(time.Now(), "CpeID2Label")

	type CpeID2Label struct {
		CpeID CpeID
		Label string
	}
	r := CpeID2Label{}
	cnt := getCount("cpe", "*")
	rows := getAllRows("cpe", "id,label")
	ret := make(map[CpeID]string, cnt)

	for rows.Next() {
		if err := rows.Scan(&r.CpeID, &r.Label); err != nil {
			panic(err)
		}
		ret[r.CpeID] = r.Label
	}
	c.CpeID2Label = ret
}
