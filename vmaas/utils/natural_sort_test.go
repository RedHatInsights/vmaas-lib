package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNaturalSort(t *testing.T) {
	s := []string{"a", "b", "ab", "a1", "a10", "c1"}
	expected := []string{"a", "a1", "a10", "ab", "b", "c1"}

	s = NaturalSortByField(s, func(x string) string { return x })
	for i := range s {
		assert.Equal(t, expected[i], s[i])
	}
}

func TestNaturalSortCves(t *testing.T) {
	rawCves := []string{
		"CVE-2020-28924", "CVE-2023-3803", "CVE-2023-28412", "CVE-2023-22601", "CVE-2023-0163",
		"CVE-2021-26098", "CVE-2024-40927", "CVE-2023-3754", "CVE-2008-4106", "CVE-2022-48629",
	}
	expected := []string{
		"CVE-2008-4106", "CVE-2020-28924", "CVE-2021-26098", "CVE-2022-48629", "CVE-2023-0163",
		"CVE-2023-3754", "CVE-2023-3803", "CVE-2023-22601", "CVE-2023-28412", "CVE-2024-40927",
	}

	cves := NaturalSort(rawCves)
	for i := range cves {
		assert.Equal(t, expected[i], cves[i])
	}
}

func TestNaturalSortErrata(t *testing.T) {
	rawErrata := []string{
		"RHSA-2019:1619", "RHBA-2019:3648", "RHBA-2019:43251", "RHSA-2018:0414", "RHBA-2018:1061", "RHBA-2019:40367",
		"RHBA-2020:1703", "RHEA-2020:4695", "RHBA-2019:40905", "RHBA-2021:1871", "RHSA-2019:1175", "RHBA-2019:42636",
		"RHSA-2019:42269", "RHSA-2020:2773", "RHSA-2020:0279", "RHEA-2019:3448", "RHEA-2019:43250", "RHBA-2019:3522",
		"RHBA-2017:1912", "RHBA-2019:42172",
	}
	expected := []string{
		"RHBA-2017:1912", "RHBA-2018:1061", "RHBA-2019:3522", "RHBA-2019:3648", "RHBA-2019:40367", "RHBA-2019:40905",
		"RHBA-2019:42172", "RHBA-2019:42636", "RHBA-2019:43251", "RHBA-2020:1703", "RHBA-2021:1871", "RHEA-2019:3448",
		"RHEA-2019:43250", "RHEA-2020:4695", "RHSA-2018:0414", "RHSA-2019:1175", "RHSA-2019:1619", "RHSA-2019:42269",
		"RHSA-2020:0279", "RHSA-2020:2773",
	}

	errata := NaturalSort(rawErrata)
	for i := range errata {
		assert.Equal(t, expected[i], errata[i])
	}
}

func TestNaturalSortNevras(t *testing.T) {
	rawNevras := []string{
		"perl-aliased-0.34-14.el8.noarch", "perl-Number-Bytes-Human-0.11-10.el8.noarch",
		"perl-tests-4:5.26.3-417.el8_3.x86_64", "bash-4.2.45-5.el7.src",
		"perl-Pod-Escapes-1:1.07-396.module+el8.1.0+2926+ce7246ad.src", "389-ds-base-1.3.7.5-18.el7.x86_64",
		"perl-IO-HTML-1.001-11.module+el8.3.0+6498+9eecfe51.noarch",
		"vim-common-2:7.4.160-1.el7_3.1.x86_64", "bash-4.4.19-12.el8.src", "bash-4.4.19-12.el8.x86_64",
		"perl-Pod-Escapes-1:1.07-395.module+el8+2464+d274aed1.src",
	}
	expected := []string{
		"389-ds-base-1.3.7.5-18.el7.x86_64",
		"bash-4.2.45-5.el7.src",
		"bash-4.4.19-12.el8.src",
		"bash-4.4.19-12.el8.x86_64",
		"perl-aliased-0.34-14.el8.noarch",
		"perl-IO-HTML-1.001-11.module+el8.3.0+6498+9eecfe51.noarch",
		"perl-Number-Bytes-Human-0.11-10.el8.noarch",
		"perl-Pod-Escapes-1:1.07-395.module+el8+2464+d274aed1.src",
		"perl-Pod-Escapes-1:1.07-396.module+el8.1.0+2926+ce7246ad.src",
		"perl-tests-4:5.26.3-417.el8_3.x86_64",
		"vim-common-2:7.4.160-1.el7_3.1.x86_64",
	}

	nevras := NaturalSort(rawNevras)
	for i := range nevras {
		assert.Equal(t, expected[i], nevras[i])
	}
}

func TestNaturalSortRepoLabels(t *testing.T) {
	rawLabels := []string{
		"rhel-7-server-rpms", "rhel-7-workstation-rpms", "rhel-8-for-x86_64-baseos-eus-rpms",
		"rhel-8-for-x86_64-baseos-rpms", "rhel-8-for-x86_64-appstream-eus-rpms", "rhel-8-for-x86_64-appstream-rpms",
		"epel-modular", "epel-8",
	}
	expected := []string{
		"epel-8", "epel-modular", "rhel-7-server-rpms", "rhel-7-workstation-rpms",
		"rhel-8-for-x86_64-appstream-eus-rpms", "rhel-8-for-x86_64-appstream-rpms",
		"rhel-8-for-x86_64-baseos-eus-rpms", "rhel-8-for-x86_64-baseos-rpms",
	}

	labels := NaturalSort(rawLabels)
	for i := range labels {
		assert.Equal(t, expected[i], labels[i])
	}
}
