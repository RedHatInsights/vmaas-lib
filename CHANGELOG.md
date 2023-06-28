# Changelog

<!--next-version-placeholder-->

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
