package vmaas

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"

	_ "github.com/mattn/go-sqlite3" // sqlite driver for cache load
)

var (
	lock  sync.Mutex
	sqlDB *sql.DB
)

var loadFuncs = []func(c *Cache){
	loadPkgNames, loadUpdates, loadUpdatesIndex, loadEvrMaps, loadArchs, loadArchCompat, loadRepoDetails,
	loadLabel2ContentSetID, loadPkgRepos, loadErrata, loadPkgErratum, loadErrataRepoIDs, loadCves,
	loadPkgErratumModule, loadModule2IDs, loadModuleRequires, loadDBChanges, loadString, loadOSReleaseDetails,
	// CSAF
	loadRepoCpes, loadContentSet2Cpes, loadCpeID2Label, loadCSAFCVE,
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

func buildIndexes(c *Cache) {
	start := time.Now()

	pkgIDs := make([]PkgID, 0, len(c.PackageDetails))
	for pkgID := range c.PackageDetails {
		pkgIDs = append(pkgIDs, pkgID)
	}

	// nil values will be at the beginning
	slices.SortFunc(pkgIDs, func(aID, bID PkgID) int {
		a := c.PackageDetails[aID].Modified
		b := c.PackageDetails[bID].Modified
		if a == nil || b == nil {
			return utils.Bool2Int(b == nil) - utils.Bool2Int(a == nil)
		}
		return a.Compare(*b)
	})
	c.PackageDetailsModifiedIndex = pkgIDs
	utils.LogInfo("elapsed", fmt.Sprint(time.Since(start)), "Indexes built successfully")
}

// Make sure only one load at a time is performed
func loadCache(path string, opts *options) (*Cache, error) {
	lock.Lock()
	defer lock.Unlock()
	start := time.Now()

	if err := openDB(path); err != nil {
		return nil, err
	}
	defer closeDB()

	c := Cache{}

	loadDumpSchemaVersion(&c)

	var wg sync.WaitGroup
	guard := make(chan struct{}, opts.maxGoroutines)
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

	buildIndexes(&c)
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

func getAllRowsWithOrder(tableName, cols, order string) *sql.Rows {
	rows, err := sqlDB.Query(fmt.Sprintf("SELECT %s FROM %s ORDER BY %s", cols, tableName, order))
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
		"id,label,name,url,COALESCE(basearch,''),COALESCE(releasever,''),product,product_id,COALESCE(revision,''),"+
			"last_change,third_party",
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
	var lastChange string
	for rows.Next() {
		var det RepoDetail
		err := rows.Scan(&repoID, &det.Label, &det.Name, &det.URL, &det.Basearch, &det.Releasever,
			&det.Product, &det.ProductID, &det.Revision, &lastChange, &det.ThirdParty)
		if err != nil {
			panic(err)
		}

		repoIDs = append(repoIDs, repoID)

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

		lastChangeTime, err := time.Parse(time.RFC3339, lastChange)
		if err == nil {
			det.LastChange = &lastChangeTime
		}
		id2repoDetail[repoID] = det
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

	loadPkgDetails(c)
	erID2cves := loadInt2Strings("errata_cve", "errata_id,cve", "erID2cves")
	erID2pkgIDs := loadInt2Ints("pkg_errata", "errata_id,pkg_id", "erID2pkgID")
	erID2bzs := loadInt2Strings("errata_bugzilla", "errata_id,bugzilla", "erID2bzs")
	erID2refs := loadInt2Strings("errata_refs", "errata_id,ref", "erID2refs")
	erID2modules := loadErrataModules(c)

	cols := "ID,name,synopsis,COALESCE(summary, ''),COALESCE(type, ''),severity,COALESCE(description, ''),COALESCE(solution, ''),issued,COALESCE(updated, ''),url,third_party,requires_reboot" //nolint:lll,nolintlint
	rows := getAllRows("errata_detail", cols)
	erratumDetails := map[string]ErratumDetail{}
	erratumID2Name := map[ErratumID]string{}
	var erratumID ErratumID
	var issuedStr, updatedStr string
	var errataName string
	for rows.Next() {
		var det ErratumDetail
		err := rows.Scan(&erratumID, &errataName, &det.Synopsis, &det.Summary, &det.Type, &det.Severity,
			&det.Description, &det.Solution, &issuedStr, &updatedStr, &det.URL, &det.ThirdParty, &det.RequiresReboot)
		if err != nil {
			panic(err)
		}
		erratumID2Name[erratumID] = errataName

		if issued, err := time.Parse(time.RFC3339, issuedStr); err == nil {
			det.Issued = &issued
		}
		if updated, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			det.Updated = &updated
		}

		det.ID = erratumID
		if cves, ok := erID2cves[int(erratumID)]; ok {
			det.CVEs = cves
		}

		if pkgIDs, ok := erID2pkgIDs[int(erratumID)]; ok {
			det.PkgIDs = pkgIDs
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

//nolint:lll
func loadCves(c *Cache) {
	defer utils.TimeTrack(time.Now(), "CveDetail")

	cveID2cwes := loadInt2Strings("cve_cwe", "cve_id,cwe", "cveID2cwes")
	cveID2pkg := loadInt2Ints("cve_pkg", "cve_id,pkg_id", "cveID2pkg")
	cve2eid := loadString2Ints("errata_cve", "cve,errata_id", "cve2eid")

	rows := getAllRows("cve_detail", "id, name, COALESCE(redhat_url, ''), COALESCE(secondary_url, ''), COALESCE(cvss3_score, ''), COALESCE(cvss3_metrics, ''), impact, COALESCE(published_date, ''), COALESCE(modified_date, ''), COALESCE(iava, ''), description, COALESCE(cvss2_score, ''), COALESCE(cvss2_metrics, ''), source")
	cnt := getCount("cve_detail", "*")
	cveDetails := make(map[string]CveDetail, cnt)
	cveNames := make(map[int]string, cnt)
	var cveID int
	var publishedDateStr, modifiedDateStr string
	for rows.Next() {
		var det CveDetail
		err := rows.Scan(&cveID, &det.Name, &det.RedHatURL, &det.SecondaryURL, &det.Cvss3Score, &det.Cvss3Metrics,
			&det.Impact, &publishedDateStr, &modifiedDateStr, &det.Iava, &det.Description, &det.Cvss2Score,
			&det.Cvss2Metrics, &det.Source)
		if err != nil {
			panic(err)
		}

		if publishedDate, err := time.Parse(time.RFC3339, publishedDateStr); err == nil {
			det.PublishedDate = &publishedDate
		}
		if modifiedDate, err := time.Parse(time.RFC3339, modifiedDateStr); err == nil {
			det.ModifiedDate = &modifiedDate
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

		eids, ok := cve2eid[det.Name]
		if ok {
			det.ErrataIDs = eids
		}
		cveDetails[det.Name] = det
		cveNames[cveID] = det.Name
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

func loadEms2PkgIDs() map[ems][]int {
	rows := getAllRows("errata_modulepkg", "pkg_id, errata_id, module_stream_id")
	cnt := getCount("errata_modulepkg", "pkg_id")
	ems2PkgIDs := make(map[ems][]int, cnt)

	var key ems
	var pkgID int
	for rows.Next() {
		err := rows.Scan(&pkgID, &key.ErratumID, &key.ModuleStreamID)
		if err != nil {
			panic(err)
		}

		ems2PkgIDs[key] = append(ems2PkgIDs[key], pkgID)
	}
	return ems2PkgIDs
}

func loadErrataModules(c *Cache) map[int][]Module {
	defer utils.TimeTrack(time.Now(), "errata2module")

	ems2PkgIDs := loadEms2PkgIDs()
	rows := getAllRows("errata_module", "errata_id, module_name, module_stream_id, module_stream, module_version, module_context") //nolint:lll
	cnt := getCount("errata_module", "errata_id")

	ensvc2StreamIDs := make(map[ensvc][]int, cnt)
	var streamID int
	var key ensvc
	for rows.Next() {
		err := rows.Scan(&key.ErratumID, &key.Name, &streamID, &key.Stream, &key.Version, &key.Context)
		if err != nil {
			panic(err)
		}
		ensvc2StreamIDs[key] = append(ensvc2StreamIDs[key], streamID)
	}

	erID2modules := make(map[int][]Module, cnt)
	for ensvc, streamIDs := range ensvc2StreamIDs {
		var pkgIDs []int
		for _, streamID := range streamIDs {
			ems := ems{
				ErratumID:      ensvc.ErratumID,
				ModuleStreamID: streamID,
			}
			pkgIDs = append(pkgIDs, ems2PkgIDs[ems]...)
		}

		binPackages, sourcePackages := c.packageIDs2Nevras(pkgIDs)

		mod := Module{
			Name:              ensvc.Name,
			Stream:            ensvc.Stream,
			Version:           ensvc.Version,
			Context:           ensvc.Context,
			PackageList:       binPackages,
			SourcePackageList: sourcePackages,
		}

		erID2modules[ensvc.ErratumID] = append(erID2modules[ensvc.ErratumID], mod)
	}

	return erID2modules
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
	rows := getAllRowsWithOrder("cpe_repo", cols, cols)

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
	rows := getAllRowsWithOrder("cpe_content_set", cols, cols)

	for rows.Next() {
		if err := rows.Scan(&r.ContentSetID, &r.CpeID); err != nil {
			panic(err)
		}
		ret[r.ContentSetID] = append(ret[r.ContentSetID], r.CpeID)
	}
	c.ContentSetID2CpeIDs = ret
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
	ret := make(map[CpeID]CpeLabel, cnt)

	for rows.Next() {
		if err := rows.Scan(&r.CpeID, &r.Label); err != nil {
			panic(err)
		}
		ret[r.CpeID] = CpeLabel(r.Label)
	}
	c.CpeID2Label = ret
}

func loadCSAFProductStatus(c *Cache) {
	defer utils.TimeTrack(time.Now(), "CSAF product status")

	cnt := getCount("csaf_product_status", "*")
	rows := getAllRows("csaf_product_status", "id,name")

	cache := make(map[int]string, cnt)

	type ProductStatusRow struct {
		ID    int
		label string
	}
	psr := ProductStatusRow{}

	for rows.Next() {
		if err := rows.Scan(&psr.ID, &psr.label); err != nil {
			panic(fmt.Errorf("failed to scan csaf_product_status row: %s", err.Error()))
		}
		cache[psr.ID] = psr.label
	}

	c.CSAFProductStatus = cache
}

type csafCVEProductRow struct {
	ID                  int
	Product             CSAFProduct
	CVEID               CVEID
	CSAFProductStatusID int
	Erratum             string
}

func productsByStatus(
	c *Cache, cpr *csafCVEProductRow, product *CSAFProduct, cn *CpeIDNameID,
	cveCache map[CpeIDNameID]map[CSAFProduct]CSAFCVEs,
) ([]CVEID, []CVEID) {
	switch c.CSAFProductStatus[cpr.CSAFProductStatusID] {
	case "fixed":
		return append(cveCache[*cn][*product].Fixed, cpr.CVEID), cveCache[*cn][*product].Unfixed
	case "known_affected":
		return cveCache[*cn][*product].Fixed, append(cveCache[*cn][*product].Unfixed, cpr.CVEID)
	default:
		panic(fmt.Sprintf("unknown product status: %s", c.CSAFProductStatus[cpr.CSAFProductStatusID]))
	}
}

func loadCSAFCVE(c *Cache) {
	loadCSAFProductStatus(c) // Load statuses before other CSAF load functions

	defer utils.TimeTrack(time.Now(), "CSAF CVEs")

	rows := getAllRows(
		"csaf_product p join csaf_cve_product cp on p.id = cp.csaf_product_id",
		"p.id,p.cpe_id,p.package_name_id,p.package_id,p.module_stream,"+
			"cp.cve_id,cp.csaf_product_status_id,COALESCE(cp.erratum,'')",
	)
	cntProducts := getCount("csaf_product", "*")
	cntCveProducts := getCount("csaf_cve_product", "*")

	product2id := make(map[CSAFProduct]CSAFProductID, cntProducts)
	cveCache := make(map[CpeIDNameID]map[CSAFProduct]CSAFCVEs, cntProducts)
	errataCache := make(map[CSAFCVEProduct]string, cntCveProducts)

	for rows.Next() {
		cpr := csafCVEProductRow{}
		if err := rows.Scan(&cpr.ID,
			&cpr.Product.CpeID,
			&cpr.Product.PackageNameID,
			&cpr.Product.PackageID,
			&cpr.Product.ModuleStream,
			&cpr.CVEID,
			&cpr.CSAFProductStatusID,
			&cpr.Erratum,
		); err != nil {
			panic(fmt.Errorf("failed to scan csaf_product row: %s", err.Error()))
		}

		cveProduct := CSAFCVEProduct{CVEID: cpr.CVEID, CSAFProductID: CSAFProductID(cpr.ID)}
		product := CSAFProduct{
			CpeID:         cpr.Product.CpeID,
			PackageNameID: cpr.Product.PackageNameID,
			PackageID:     cpr.Product.PackageID,
			ModuleStream:  cpr.Product.ModuleStream,
		}

		if len(cpr.Erratum) > 0 {
			errataCache[cveProduct] = cpr.Erratum
		}

		cn := CpeIDNameID{product.CpeID, product.PackageNameID}
		fixed, unfixed := productsByStatus(c, &cpr, &product, &cn, cveCache)
		if _, ok := cveCache[cn]; !ok {
			cveCache[cn] = map[CSAFProduct]CSAFCVEs{}
		}
		cveCache[cn][product] = CSAFCVEs{Fixed: fixed, Unfixed: unfixed}
		product2id[product] = CSAFProductID(cpr.ID)
	}

	c.CSAFCVEs = cveCache
	c.CSAFCVEProduct2Errata = errataCache
	c.CSAFProduct2ID = product2id
}

func loadDumpSchemaVersion(c *Cache) {
	defer utils.TimeTrack(time.Now(), "DumpSchemaVersion")

	// This block might be removed in future
	rows, err := sqlDB.Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'dump_schema'")
	if err != nil {
		panic(err)
	}
	if !rows.Next() {
		utils.LogWarn("dump_schema table doesn't exist yet in dump, dump schema version is 0.")
		return
	}

	rows = getAllRows("dump_schema", "version")
	var version int
	for rows.Next() {
		err := rows.Scan(&version)
		if err != nil {
			panic(err)
		}
	}
	c.DumpSchemaVersion = version
}

func loadOSReleaseDetails(c *Cache) {
	defer utils.TimeTrack(time.Now(), "OSReleaseDetails")
	if c.DumpSchemaVersion < 3 {
		utils.LogWarn("OSReleaseDetails requires dump schema version 3, skipping.")
		return
	}

	rows := getAllRows(
		"operating_system",
		"id,name,major,minor,lifecycle_phase,system_profile",
	)
	cntOSRelease := getCount("operating_system", "*")

	id2OSReleaseDetail := make(map[int]OSReleaseDetail, cntOSRelease)
	var OSReleaseID int
	for rows.Next() {
		var det OSReleaseDetail
		err := rows.Scan(&OSReleaseID, &det.Name, &det.Major, &det.Minor, &det.LifecyclePhase, &det.SystemProfile)
		if err != nil {
			panic(err)
		}
		id2OSReleaseDetail[OSReleaseID] = det
	}
	c.OSReleaseDetails = id2OSReleaseDetail
}
