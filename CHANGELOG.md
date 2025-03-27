# Changelog

<!--next-version-placeholder-->

## v1.24.0 (2025-03-27)

### Feature

* Rewrite vmaas package_name/rpms endpoint in go ([`7bc9cd2`](https://github.com/RedHatInsights/vmaas-lib/commit/7bc9cd22d5692db33fc2ce61c04d023a367bf384))
* Add ContentSetID2Label and ContentSetID2PkgNameIDs to cache ([`f6887e2`](https://github.com/RedHatInsights/vmaas-lib/commit/f6887e27e76824c38d7b04a4788fa6bdbe0ea414))
* Add Intersection utility ([`20e4851`](https://github.com/RedHatInsights/vmaas-lib/commit/20e485101684fa60c291842c643f774236704cb8))
* Add ApplyMap utility ([`15d53cb`](https://github.com/RedHatInsights/vmaas-lib/commit/15d53cb8d57921c6da5041afb15386a4f342f932))
* Add generalized K2V and K2Vs loaders ([`6ce7e71`](https://github.com/RedHatInsights/vmaas-lib/commit/6ce7e71422410acb6036be530d3bb3378696f7b1))

## v1.23.0 (2025-03-06)

### Feature

* Rewrite vmaas patches endpoint in go ([`0361331`](https://github.com/RedHatInsights/vmaas-lib/commit/0361331e734964399cee5862c79b25bf285ba499))

## v1.22.0 (2025-03-06)

### Feature

* Add lifecycle_phase ([`8fbb5b6`](https://github.com/RedHatInsights/vmaas-lib/commit/8fbb5b6ef245e6bb20068604fb8810ac68873bfa))

## v1.21.2 (2025-03-05)

### Fix

* Add missing ReposRequest has_packages ([`c886e24`](https://github.com/RedHatInsights/vmaas-lib/commit/c886e243ef5843033803cf9496bc38c258c454f0))
* Add missing sort before repo pagination ([`298b54e`](https://github.com/RedHatInsights/vmaas-lib/commit/298b54ed5d82dba7bfdb6763195b78aa79348fa6))
* Show last_change for a single repo ([`9907f6c`](https://github.com/RedHatInsights/vmaas-lib/commit/9907f6c730d3c66019341f3c9136771e9b2ff24c))
* Ensure updated_package_names shows as expected ([`4f25b07`](https://github.com/RedHatInsights/vmaas-lib/commit/4f25b07ab0cc4fd4d239a314ecd1f1ae062bbf20))

## v1.21.1 (2025-02-27)

### Fix

* Remove natural sort ([`88ca886`](https://github.com/RedHatInsights/vmaas-lib/commit/88ca886a76b7acd7c8deed13bf91034d868372f1))

## v1.21.0 (2025-02-26)

### Feature

* Rewrite vmaas pkgtree endpoint in go ([`9da4367`](https://github.com/RedHatInsights/vmaas-lib/commit/9da4367fae0b923815d647ec8e54b7f971dc43ce))
* Add natural sort ([`c20c1fb`](https://github.com/RedHatInsights/vmaas-lib/commit/c20c1fb84fd0fae159df7582c0042ecc07aefe86))

## v1.20.0 (2025-02-24)

### Feature

* **csaf:** Newer release cves not fixed in current release ([`37afae4`](https://github.com/RedHatInsights/vmaas-lib/commit/37afae492f361126bf1a64b7d24656dcf0cce980))

### Fix

* **cpe:** Sort matched cpes to give consistent cve results ([`e49ec4d`](https://github.com/RedHatInsights/vmaas-lib/commit/e49ec4dabcfdd763dc8025e991c602b592982f28))
* **repositories:** Newer release cves not fixed in current release ([`f8a011a`](https://github.com/RedHatInsights/vmaas-lib/commit/f8a011a3071d5a7cb8194722d066e8d579e3979e))

## v1.19.0 (2025-02-18)

### Feature

* Implement pkglist endpoint in go ([`04eb606`](https://github.com/RedHatInsights/vmaas-lib/commit/04eb606611f3af9fb82d3de07e5fdb9080073cdf))
* Add package details modified index ([`5c2a02a`](https://github.com/RedHatInsights/vmaas-lib/commit/5c2a02a5c0964b23f0b67bee91b94469ec41d074))
* Add go pkglist endpoint shell ([`395648c`](https://github.com/RedHatInsights/vmaas-lib/commit/395648c13bc069df01451219f5008f7354b3efd6))

## v1.18.0 (2025-02-12)

### Feature

* Rewrite packages endpoint in go ([`8e722b9`](https://github.com/RedHatInsights/vmaas-lib/commit/8e722b900214a1f9aae090e51a71882b09e67377))

## v1.17.0 (2025-01-30)

### Feature

* Rewrite repos endpoint in go ([`e2cef54`](https://github.com/RedHatInsights/vmaas-lib/commit/e2cef54bf07cfabc7b2f1760d42fe73b3f34e53c))

## v1.16.0 (2025-01-29)

### Feature

* OS Release Vulnerability Report API ([`5325249`](https://github.com/RedHatInsights/vmaas-lib/commit/532524969888ce00359bd6e9ce6f673cbab4e1f3))

## v1.15.0 (2025-01-23)

### Feature

* Introduce simple dump versioning ([`b462637`](https://github.com/RedHatInsights/vmaas-lib/commit/b4626376debe1c197a4fa4bcbfccc1aeb0b95c4e))

## v1.14.7 (2025-01-20)

### Fix

* Improve missing errata_list error message ([`531737e`](https://github.com/RedHatInsights/vmaas-lib/commit/531737ee635c1ba013a12e918bd4e616669c1ed9))
* Fix errata endpoint severity ([`ff26c59`](https://github.com/RedHatInsights/vmaas-lib/commit/ff26c59392ed3fca74e29dbca198c582073f83a3))
* Fix pagination pages calculation ([`37ed4e1`](https://github.com/RedHatInsights/vmaas-lib/commit/37ed4e17ed2b965535088e39899d2a653931aab9))
* Fix errata endpoint types ([`792c2f5`](https://github.com/RedHatInsights/vmaas-lib/commit/792c2f52b6644e215d35a4901064a61953c5c9bc))
* Fix errata endpoint non-nullable arrays ([`ce57b34`](https://github.com/RedHatInsights/vmaas-lib/commit/ce57b34006fa01d13c332ff6569251f19286ebf0))
* Fix errata endpoint bad request error code ([`b973591`](https://github.com/RedHatInsights/vmaas-lib/commit/b973591d53533e57cdca834f6ce5876fd63a80ed))

## v1.14.6 (2024-12-12)

### Fix

* Improve cves req missing property err message ([`b8b3513`](https://github.com/RedHatInsights/vmaas-lib/commit/b8b3513824517be7f990bda59dc126858d5fbf12))

## v1.14.5 (2024-12-04)

### Fix

* Condition for skipping seen package names ([`b5da97d`](https://github.com/RedHatInsights/vmaas-lib/commit/b5da97d7d2f14eb385498bf9b94141aae68f075e))

## v1.14.4 (2024-12-04)

### Fix

* Remove unused nameID2SrcNameIDs map ([`7404e32`](https://github.com/RedHatInsights/vmaas-lib/commit/7404e32fd4c5476b4b2485907239f22c924f0bca))
* Don't process same name ids multiple times ([`d7f45c0`](https://github.com/RedHatInsights/vmaas-lib/commit/d7f45c006da606330648f06e60d328d44adcfb30))
* Get source pkg from installed nevra for unfixed cves ([`4863dfa`](https://github.com/RedHatInsights/vmaas-lib/commit/4863dfa67bbab245b98402b8e43b9e9a5fa463e0))

## v1.14.3 (2024-12-02)

### Fix

* Implement various cves endpoint fixes ([`197a925`](https://github.com/RedHatInsights/vmaas-lib/commit/197a925eac8679522916e492ee0406abb7077e5b))

## v1.14.2 (2024-11-28)

### Fix

* Ignore updates from rhel-alt el7a release ([`a20c900`](https://github.com/RedHatInsights/vmaas-lib/commit/a20c90020f6605186355549533f6029dabcf3ec4))

## v1.14.1 (2024-11-14)

### Fix

* Revert "fix: upgrade go version" ([`1d7b125`](https://github.com/RedHatInsights/vmaas-lib/commit/1d7b125026d7a4dd9d40d094101c1edff8876a70))

## v1.14.0 (2024-11-13)

### Feature

* Rewrite errata endpoint in go ([`89e593f`](https://github.com/RedHatInsights/vmaas-lib/commit/89e593fece2a1566b8235d855ffe7763796139fa))

## v1.13.1 (2024-11-12)

### Fix

* Upgrade go version ([`89020ab`](https://github.com/RedHatInsights/vmaas-lib/commit/89020ab63c5f38b7c704dbf743f1d1f236b4cbd8))

## v1.13.0 (2024-10-31)

### Feature

* Implement cves pagination ([`482d3ab`](https://github.com/RedHatInsights/vmaas-lib/commit/482d3abca0d9b8c87483a52cddf9b472a96ef172))
* Implement expanding cves by regex ([`ecb2e42`](https://github.com/RedHatInsights/vmaas-lib/commit/ecb2e42eb75ea0fc0813c50c973f5314d2149340))
* Rewrite basic cves endpoint in go ([`ad285fb`](https://github.com/RedHatInsights/vmaas-lib/commit/ad285fb461fc5cf165f1918861872f0e3beef906))

### Fix

* Move cache utils and their tests ([`9ebc21e`](https://github.com/RedHatInsights/vmaas-lib/commit/9ebc21e00899ab48458fa58a97253920ff565c5d))

## v1.12.0 (2024-10-15)

### Feature

* Remove use_csaf from request struct ([`41aeae1`](https://github.com/RedHatInsights/vmaas-lib/commit/41aeae109fc82659b3f8c6449489c68cd29d0396))

## v1.11.3 (2024-10-15)

### Fix

* Options to disable newerReleasever from repos and csaf ([`f737060`](https://github.com/RedHatInsights/vmaas-lib/commit/f73706094a0b3337e296265293e5772f4adc848e))

## v1.11.2 (2024-10-15)

### Fix

* Reuse product struct for products with unfixed cves ([`986885f`](https://github.com/RedHatInsights/vmaas-lib/commit/986885f95162ecd8277b24f7b4dddf14aa37b922))

## v1.11.1 (2024-10-01)

### Fix

* Revert appendUniq due to performance hit ([`cda7483`](https://github.com/RedHatInsights/vmaas-lib/commit/cda7483d6c53b2919b57741b77efe0ecb850e132))

## v1.11.0 (2024-10-01)

### Feature

* Remove oval evaluation ([`1ec86dc`](https://github.com/RedHatInsights/vmaas-lib/commit/1ec86dca7374f465fe1be24f1805eb0a52030255))

## v1.10.3 (2024-09-30)

### Fix

* Skip processing of duplicate products ([`2cc6f3c`](https://github.com/RedHatInsights/vmaas-lib/commit/2cc6f3c94a248ae1f803bb9039d51a285bd4ba61))

## v1.10.2 (2024-09-27)

### Fix

* Iterate over all fixable and manually fixable errata ([`5767402`](https://github.com/RedHatInsights/vmaas-lib/commit/5767402f254e004402e468c94a552527995478a2))

## v1.10.1 (2024-09-25)

### Fix

* **udpates:** Slice allocation ([`214fb7a`](https://github.com/RedHatInsights/vmaas-lib/commit/214fb7a812f7b5ef6666018b4f86050966487e63))

## v1.10.0 (2024-09-25)

### Feature

* Return manually fixable cves from repositories in vulnerabilities receiver ([`986be63`](https://github.com/RedHatInsights/vmaas-lib/commit/986be63d5b097820a3a96bb0d4eff40edcd86017))
* Return only fixable updates from updates receiver ([`357badd`](https://github.com/RedHatInsights/vmaas-lib/commit/357badd9b64603b0e2f9b5bbda7696fb9ac69fa1))
* Find updates in repos with newer releasever ([`cb5df58`](https://github.com/RedHatInsights/vmaas-lib/commit/cb5df58478354f9c7a6a35fbd88380d935deda81))

### Fix

* **csaf:** Use cpes from newer release ver for eus updates ([`f6f726e`](https://github.com/RedHatInsights/vmaas-lib/commit/f6f726e92a92469086db605a28b05829ac33321e))

## v1.9.2 (2024-09-24)

### Fix

* Skip cves missing in mapping ([`bfc8561`](https://github.com/RedHatInsights/vmaas-lib/commit/bfc8561e8d14b5a3c261cc2a3a751fe7613cf8b8))

## v1.9.1 (2024-08-27)

### Fix

* **csaf:** Duplicate cpes while processing ([`f4fde94`](https://github.com/RedHatInsights/vmaas-lib/commit/f4fde94b05e10875836dc41c13fa0e8932dcc9f0))

## v1.9.0 (2024-08-22)

### Feature

* **opts:** Add option to exclude package names from csaf ([`f297f3d`](https://github.com/RedHatInsights/vmaas-lib/commit/f297f3d470d893d449497234ce5d4eb5140da03f))

### Fix

* **csaf:** Make sure cpes are unique ([`74d142f`](https://github.com/RedHatInsights/vmaas-lib/commit/74d142fe84e1c83aa662c91ae273bcde6b4ea3a0))
* **csaf:** Exclude packages names in csaf eval ([`1d47bfb`](https://github.com/RedHatInsights/vmaas-lib/commit/1d47bfba02dede246cec36fb7ed9d956bf0ab1a7))

## v1.8.0 (2024-08-19)

### Feature

* Remove oval evaluation ([`a018f4b`](https://github.com/RedHatInsights/vmaas-lib/commit/a018f4b3a16bbff065928ece97dbe754bbb39c19))

## v1.7.2 (2024-08-09)

### Fix

* **fixed_cves:** Use modules of fixed products in evaluation ([`4af5b69`](https://github.com/RedHatInsights/vmaas-lib/commit/4af5b69439bde2943d98bfe03d038340bceff6fe))

## v1.7.1 (2024-07-04)

### Fix

* Detect all affected packages for unfixed vulns in CSAF ([`20214f7`](https://github.com/RedHatInsights/vmaas-lib/commit/20214f79c2fb7f888fdbe1e99fc0f985ac2d76d0))
* Detect all affected packages for unfixed vulns in OVAL ([`d4139cc`](https://github.com/RedHatInsights/vmaas-lib/commit/d4139cc3836b8fc4cd94f6483cc2cac5b857d3ef))

## v1.7.0 (2024-07-02)

### Feature

* Report affected module for unfixed CVEs in CSAF ([`126ee49`](https://github.com/RedHatInsights/vmaas-lib/commit/126ee4996e4d11d056b0cecca4981afabaa5add6))
* Report affected module for unfixed CVEs in OVAL ([`1bbfbbc`](https://github.com/RedHatInsights/vmaas-lib/commit/1bbfbbc41707b994e753d76eedf688d3ca599887))

## v1.6.1 (2024-06-27)

### Fix

* Match cpe pattern substrings ([`c64a4d1`](https://github.com/RedHatInsights/vmaas-lib/commit/c64a4d11b4508a0f764da72e66056c282185c774))

## v1.6.0 (2024-06-19)

### Feature

* **csaf:** Manually fixable cves from csaf ([`ec9262b`](https://github.com/RedHatInsights/vmaas-lib/commit/ec9262b89c874d8eec7cb4d3863fceea791c0e47))
* **load:** Load csaf errata ([`c1c7905`](https://github.com/RedHatInsights/vmaas-lib/commit/c1c7905aa17f315b7ee55124dad3f1107f738ba2))

### Fix

* **csaf:** Show only first package with unpatched cve ([`aa8d0f0`](https://github.com/RedHatInsights/vmaas-lib/commit/aa8d0f0f440ba6456d121cb7ae8ef20e73965ebb))

## v1.5.1 (2024-06-17)

### Fix

* Evaluate module tests for unfixed CVEs ([`9d93a0f`](https://github.com/RedHatInsights/vmaas-lib/commit/9d93a0fa1f5a8cfc4baceb05c3623b3fe9b0241c))

## v1.5.0 (2024-05-28)

### Feature

* Update go version ([`a93743a`](https://github.com/RedHatInsights/vmaas-lib/commit/a93743a7dfe88aabc11f0cacaade6edfd463a8c2))

## v1.4.2 (2024-05-28)

### Fix

* **csaf:** Products for package names built from the same source ([`bb89ec7`](https://github.com/RedHatInsights/vmaas-lib/commit/bb89ec7517622f9abf3163c6877ddd5242b3cb18))

## v1.4.1 (2024-04-30)

### Fix

* **concurrency:** Goroutines per package instead of package-update ([`1e1a033`](https://github.com/RedHatInsights/vmaas-lib/commit/1e1a0339ecad09812ab87ae7068fa3c3188c9cc2))
* Check to verify that update exists in repo ([`1cfa9ee`](https://github.com/RedHatInsights/vmaas-lib/commit/1cfa9eedbe1e955bb75ffc17ac41652cb347e0ad))

## v1.4.0 (2024-04-25)

### Feature

* **csaf:** Evaluate unfixed cves from csaf ([`d6692e9`](https://github.com/RedHatInsights/vmaas-lib/commit/d6692e9fc9a6348df8327364f0522395acb71007))

### Fix

* **csaf_load:** Load null values to CSAFCVEs cache ([`5b17153`](https://github.com/RedHatInsights/vmaas-lib/commit/5b17153f549de89c940767ee724d6f538feaaa51))
* **csaf:** Cpe comparison ([`621855b`](https://github.com/RedHatInsights/vmaas-lib/commit/621855b55ea8f722df409b68f9782e9b17524b38))

## v1.3.0 (2024-04-04)

### Feature

* Add Csaf load and cache ([`efc388e`](https://github.com/RedHatInsights/vmaas-lib/commit/efc388ee2e830dab7d6bae39a17a3b942ff9c8f9))

## v1.2.0 (2024-02-22)

### Feature

* Consider evaluating definitions from newer eus/aus/e4s streams ([`16acc19`](https://github.com/RedHatInsights/vmaas-lib/commit/16acc1946b205ebc55fca8481c3da2bc8b3360d6))

### Fix

* Map definition to first matched CPE ([`8d694aa`](https://github.com/RedHatInsights/vmaas-lib/commit/8d694aa0a64104b2a4207098ce75b83551cbe0ca))

## v1.1.2 (2023-11-24)

### Fix

* Don't evaluate module tests for unfixed CVE definitions, we're not looking for package updates anyway ([`a01b3c1`](https://github.com/RedHatInsights/vmaas-lib/commit/a01b3c1fd7c58728eedeab10f178065324226436))

## v1.1.1 (2023-11-22)

### Fix

* Update go to 1.20 and update dependencies ([`7b4efce`](https://github.com/RedHatInsights/vmaas-lib/commit/7b4efcef9d7f87d7e6f0826e8bbd20f3c65b467d))

## v1.1.0 (2023-10-17)

### Feature

* Load last_change column from cache ([`ed9ec90`](https://github.com/RedHatInsights/vmaas-lib/commit/ed9ec9004e4248db4b210fc8ae91159a366c71a1))

## v1.0.7 (2023-08-31)

### Fix

* Sort updates also by other fields ([`5631339`](https://github.com/RedHatInsights/vmaas-lib/commit/5631339889294372678de9333baab24d9397deb3))

## v1.0.6 (2023-08-24)

### Fix

* Display all affected_packages and errata for cves evaluated by repositories ([`91f9e53`](https://github.com/RedHatInsights/vmaas-lib/commit/91f9e530aec7d10928629dcf1f237301e4137838))

## v1.0.5 (2023-08-14)

### Fix

* **updates:** Sort availableUpdates ([`af06bec`](https://github.com/RedHatInsights/vmaas-lib/commit/af06becbee8387b31e105df1357b4b90198105fa))

## v1.0.4 (2023-07-18)

### Fix

* **semantic-release:** Use older python-semantic-release ([`5ebef9e`](https://github.com/RedHatInsights/vmaas-lib/commit/5ebef9e1f8c73924f78eb6b865311e8bd40d90d0))
* Make sure definition list is in fixed order ([`eff45d5`](https://github.com/RedHatInsights/vmaas-lib/commit/eff45d58891b743f6cb99b349fe70167e38bda94))
* Make sure CPE list is in fixed order ([`a57484d`](https://github.com/RedHatInsights/vmaas-lib/commit/a57484d26bf4cd382ed76f1e40c2534cc2460846))
* Make sure input package list is in fixed order ([`6a3b4ad`](https://github.com/RedHatInsights/vmaas-lib/commit/6a3b4adbfaa3ba3782459786c426411d031f1c9f))

## v1.0.3 (2023-07-04)

### Fix

* Check whether pkg update exists in enabled repo ([`ba3b4cc`](https://github.com/RedHatInsights/vmaas-lib/commit/ba3b4cc0f4639c93e98ed324a1458f05b004c755))

## v1.0.2 (2023-06-28)

### Fix

* Bump version to release code to pkg.go.dev ([`59585f6`](https://github.com/RedHatInsights/vmaas-lib/commit/59585f648841838d712c69d74b58a92cd901c0a3))

## v1.0.1 (2023-06-28)

### Fix

* Nil pointer dereference ([`215d328`](https://github.com/RedHatInsights/vmaas-lib/commit/215d3283f0bcafd4adc4e2e914a6ba391bd02683))

## v1.0.0 (2023-06-27)

### Feature

* Add functional options ([`0e751b9`](https://github.com/RedHatInsights/vmaas-lib/commit/0e751b9a7ef98e29ce4533b4e7ee5ec03e212554))
* Return package name and evra in updates ([`d7b62c8`](https://github.com/RedHatInsights/vmaas-lib/commit/d7b62c89f8a7e0e025e6df5a822fd538362a888f))

### Fix

* Improve cases when cache should be reloaded ([`f93129a`](https://github.com/RedHatInsights/vmaas-lib/commit/f93129aa12fca4c666885d536d90808372a21293))
* Remove unnecessary pointer to a mutex ([`f2c9493`](https://github.com/RedHatInsights/vmaas-lib/commit/f2c94937771add67b0d0ff563794421706fbc90b))
* Custom error when processing of input fails ([`96850f0`](https://github.com/RedHatInsights/vmaas-lib/commit/96850f0be36475f0044da84618642152c47b9b35))

### Breaking

* methods cannot be exported since `options` is unexported ([`25bf738`](https://github.com/RedHatInsights/vmaas-lib/commit/25bf7380980288e206d1c1f9d10af810ba263ff0))

## v0.9.0 (2023-05-31)
### Feature

* **config:** Api config instead of using env vars ([`b57e28b`](https://github.com/RedHatInsights/vmaas-lib/commit/b57e28b1372dbd961c6e0dc6f5bee6e06b688df9))

## v0.8.1 (2023-05-26)
### Fix
* Update to go1.19 ([`0d7d810`](https://github.com/RedHatInsights/vmaas-lib/commit/0d7d8105906683df0bfd8f4f13663e70a66b1c5a))

## v0.8.0 (2023-05-16)
### Feature
* Add epoch_required request option ([`a091b25`](https://github.com/RedHatInsights/vmaas-lib/commit/a091b25541b8209d2987c35e8f610fb1672ee413))

## v0.7.1 (2023-05-15)
### Fix
* **modules:** Package from module with disabled repo ([`b6e7155`](https://github.com/RedHatInsights/vmaas-lib/commit/b6e7155b6d3dae886ba900fb000ca9b2f2d7d3f7))

## v0.7.0 (2023-05-10)
### Feature
* **oval:** Show package name, evra, cpe for unpatched cves ([`9cfe7d8`](https://github.com/RedHatInsights/vmaas-lib/commit/9cfe7d8d97b825a60681ca17fab93a47e10fdebb))

## v0.6.0 (2023-05-09)
### Feature
* **oval:** Unpatched cves take precedence over fixable and manually fixable ([`d01c877`](https://github.com/RedHatInsights/vmaas-lib/commit/d01c87705a368025c95abb16855f30f2912dbaf4))

### Fix
* **load:** Load oval definition id ([`04e746b`](https://github.com/RedHatInsights/vmaas-lib/commit/04e746b8e1a5f5d927676a66fc376d96d0948bb0))

## v0.5.1 (2023-05-03)
### Fix
* **oval:** Check module stream in evaluateModuleTest ([`20be8ac`](https://github.com/RedHatInsights/vmaas-lib/commit/20be8ac36741fd6bb462a3089107cba4250458c3))
* **oval:** Remove duplicates from UnpatchedCves list ([`9c48307`](https://github.com/RedHatInsights/vmaas-lib/commit/9c48307753f149815ff5c16975f89ba0a3db4003))
* **modules:** Find updates in modular errata for package from module when module is enabled ([`cd99eef`](https://github.com/RedHatInsights/vmaas-lib/commit/cd99eef927a5d1457921169c66b46f75de557a0c))

## v0.5.0 (2023-04-18)
### Feature
* Remove releasever check when finding updates ([`009fc1b`](https://github.com/RedHatInsights/vmaas-lib/commit/009fc1b2992312ea3795faccfe7ea117c9604f9f))
* Always use optimistic updates ([`a892a8b`](https://github.com/RedHatInsights/vmaas-lib/commit/a892a8b2bbbfd63afa99279f5726dfe034d6b724))

## v0.4.3 (2023-04-03)
### Fix
* Allow empty string for modules only in request ([`427829d`](https://github.com/RedHatInsights/vmaas-lib/commit/427829dc423a353c066e7e54009faa32155d42af))

## v0.4.2 (2023-04-03)
### Fix
* Use *string for module name and stream to allow empty strings ([`ca5be5f`](https://github.com/RedHatInsights/vmaas-lib/commit/ca5be5fc9619544a6088b54b84b655e64ec7a83b))

## v0.4.1 (2023-03-30)
### Fix
* Make sure lock is unlocked in case of error ([`a3af86a`](https://github.com/RedHatInsights/vmaas-lib/commit/a3af86a15766a6c71bc6cf698f3fb2e5b6b3d2c4))

## v0.4.0 (2023-03-27)
### Feature
* Return multiple erratas for manually fixable cve ([`14b59ed`](https://github.com/RedHatInsights/vmaas-lib/commit/14b59ed3de5b9ab2d8adc63650db2e10e4b5fb6b))
* Update vmaas.db with oval_definition_errata feed ([`8588b31`](https://github.com/RedHatInsights/vmaas-lib/commit/8588b31c6f4ee5022aeacf69e94c65372bfb72b2))
* Return errata for manually fixable cves ([`972a273`](https://github.com/RedHatInsights/vmaas-lib/commit/972a273b36ee12bb02fcfe81a34fba56290eba62))

## v0.3.5 (2023-03-20)
### Fix
* Re-use logging logic from patchman ([`e5af24b`](https://github.com/RedHatInsights/vmaas-lib/commit/e5af24b2ec71e6aa86c97a7f60620d58155aa37f))

## v0.3.4 (2023-03-20)
### Fix
* Stream downloaded dump to a file ([`0f49948`](https://github.com/RedHatInsights/vmaas-lib/commit/0f4994885461be647548c0cd137132cd88540803))

## v0.3.3 (2023-02-07)
### Fix
* Third_party json field ([`c991822`](https://github.com/RedHatInsights/vmaas-lib/commit/c991822e1aba9a6be8a4f290e089b8d07fdd76ba))

## v0.3.2 (2023-02-06)
### Fix
* Return errata: [] instead of null ([`9549f8a`](https://github.com/RedHatInsights/vmaas-lib/commit/9549f8a5d1ef160e942d6557b79ede50ac6d4c95))

## v0.3.1 (2023-01-19)
### Fix
* Allow nil repolist ([`96f4b79`](https://github.com/RedHatInsights/vmaas-lib/commit/96f4b79c8efff5095fb0059d8fa2423d9d5377c8))

## v0.3.0 (2023-01-11)
### Feature
* Add goroutines ([`7eb7548`](https://github.com/RedHatInsights/vmaas-lib/commit/7eb754806bc4885df09b49d4d1b5563822d1d065))

## v0.2.6 (2023-01-05)
### Fix
* Detail load, unnecessary cve iteration ([`a83a6e6`](https://github.com/RedHatInsights/vmaas-lib/commit/a83a6e6895e3a21666c9169e29bf8c369baacc08))

## v0.2.5 (2023-01-04)
### Fix
* Cache reload ([`9a8a676`](https://github.com/RedHatInsights/vmaas-lib/commit/9a8a676485444ce77c3e4d9c2bdae62f343f88c0))

## v0.2.4 (2022-12-16)
### Fix
* Pre-alloc maps in cache ([`8f4eba6`](https://github.com/RedHatInsights/vmaas-lib/commit/8f4eba6dc2b45fea0b09b07c3f9a9d4f5a196cb7))

## v0.2.3 (2022-12-14)
### Fix
* Use nevra pointer for receiver ([`e0d8a9f`](https://github.com/RedHatInsights/vmaas-lib/commit/e0d8a9f00970cf12720f3eb1d979a3d09bdada55))
* Close db after cache read ([`a9486e3`](https://github.com/RedHatInsights/vmaas-lib/commit/a9486e36ff8a31d5810c68511fb6b4453053e376))
* Optimize oval load ([`b6d7e01`](https://github.com/RedHatInsights/vmaas-lib/commit/b6d7e01ddc98e4d346ed4f8c58941252a8a25738))
* Reduce number of allocations ([`38d1be5`](https://github.com/RedHatInsights/vmaas-lib/commit/38d1be54de528b014ce8a9c1c3f30a8a8f5a3258))

## v0.2.2 (2022-12-09)
### Fix
* Updates when releasever in repo is empty ([`3ec8712`](https://github.com/RedHatInsights/vmaas-lib/commit/3ec8712cdaa5638902ee1d2b6aecf31b3c3de0a8))

## v0.2.1 (2022-12-08)
### Fix
* Arch compatibility ([`b18e816`](https://github.com/RedHatInsights/vmaas-lib/commit/b18e816f253edd3dcd580aaf5854024c7b9b3e7d))

## v0.2.0 (2022-12-08)
### Feature
* **rhui:** Look up updates by repository path ([`044abab`](https://github.com/RedHatInsights/vmaas-lib/commit/044abab43674b1836874cd172ce3187293b57b80))

## v0.1.4 (2022-12-01)
### Fix
* Minor fixes ([`9c06686`](https://github.com/RedHatInsights/vmaas-lib/commit/9c06686039c1386efd8948a1cef91da4e7267766))

## v0.1.3 (2022-11-30)
### Fix
* Issues found with unit tests ([`43beb51`](https://github.com/RedHatInsights/vmaas-lib/commit/43beb5188c98c0d0edbdf6816fe358d516c6cdbb))

## v0.1.2 (2022-11-28)
### Fix
* Don't iter UpdatesIndex in processInputPackages ([`8f2fc92`](https://github.com/RedHatInsights/vmaas-lib/commit/8f2fc92a1d39ea8ffcd59e9b77038fa1afbd571e))

## v0.1.1 (2022-11-28)
### Fix
* RepoID slice, simplify intersection, gorpm build ([`1611883`](https://github.com/RedHatInsights/vmaas-lib/commit/1611883bebc2856c232b8385200990d21d1b83c3))

## v0.1.0 (2022-11-28)
### Feature
* **test:** Introduce unit tests ([`27584fb`](https://github.com/RedHatInsights/vmaas-lib/commit/27584fba178ccf2c3bc34b6ceb7708dd74859e49))
* Setup semantic release from vuln4shift ([`01ccb51`](https://github.com/RedHatInsights/vmaas-lib/commit/01ccb51313e4a520f3a8bb9d4e06955ec1e95fe0))
