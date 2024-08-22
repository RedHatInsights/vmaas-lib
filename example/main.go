package main

import (
	"github.com/redhatinsights/vmaas-lib/vmaas"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

func main() {
	api, _ := vmaas.InitFromFile("./example/vmaas.db")
	repo := []string{"rhel-7-server-rpms"}
	request := vmaas.Request{
		Packages: []string{"kernel-0:3.10.0-957.5.1.el7.x86_64"},
		Repos:    &repo,
		UseCsaf:  true,
	}

	vulnerabilities, _ := api.Vulnerabilities(&request)
	utils.LogInfo("cves", vulnerabilities.CVEs, "Vulnerabilities")
	utils.LogInfo("manually fixable cves", vulnerabilities.ManuallyFixableCVEs, "Vulnerabilities")
	utils.LogInfo("unpatched cves", vulnerabilities.UnpatchedCVEs, "Vulnerabilities")
}
