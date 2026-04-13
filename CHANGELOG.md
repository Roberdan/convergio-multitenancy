# Changelog

## [0.4.3](https://github.com/Roberdan/convergio-multitenancy/compare/v0.4.2...v0.4.3) (2026-04-13)


### Bug Fixes

* add crates.io publishing metadata (description, repository) ([85987b5](https://github.com/Roberdan/convergio-multitenancy/commit/85987b53989dd57b5245dc2fe0e135370843fa6f))

## [0.4.2](https://github.com/Roberdan/convergio-multitenancy/compare/v0.4.1...v0.4.2) (2026-04-13)


### Bug Fixes

* apply cargo fmt ([9ed417c](https://github.com/Roberdan/convergio-multitenancy/commit/9ed417c28a253906d27d7c84e3a34a730f215602))
* raise default max_concurrent_agents from 20 to 100 ([691ea04](https://github.com/Roberdan/convergio-multitenancy/commit/691ea04cbfa07de930df5299966cc15e5c8ad873))
* raise default max_concurrent_agents to 100 ([68b1d20](https://github.com/Roberdan/convergio-multitenancy/commit/68b1d207a65d3fe4290082aa061a64af1d20c2cc))

## [0.4.1](https://github.com/Roberdan/convergio-multitenancy/compare/v0.4.0...v0.4.1) (2026-04-13)


### Bug Fixes

* sha2 0.11 compatibility — replace LowerHex with manual hex encoding ([0680541](https://github.com/Roberdan/convergio-multitenancy/commit/0680541ac584be274c7c4032058c20fd63a21898))

## [0.4.0](https://github.com/Roberdan/convergio-multitenancy/compare/v0.3.0...v0.4.0) (2026-04-13)


### ⚠ BREAKING CHANGES

* **security:** TenancyError has new variants (InvalidOrgId, Unauthorized)

### Features

* initial convergio-multitenancy from template ([7b74984](https://github.com/Roberdan/convergio-multitenancy/commit/7b749840691be88b06545b6e83b1a6ba0c4dc83d))


### Bug Fixes

* **release:** use vX.Y.Z tag format (remove component) ([a7d131f](https://github.com/Roberdan/convergio-multitenancy/commit/a7d131fed0f108b3dbf0561cfd726288c124f2a7))
* **security:** harden tenant isolation and input validation ([#2](https://github.com/Roberdan/convergio-multitenancy/issues/2)) ([d95c27c](https://github.com/Roberdan/convergio-multitenancy/commit/d95c27c65de26bc9ae78b9ed0a46ead245b12458))

## [0.3.0](https://github.com/Roberdan/convergio-multitenancy/compare/convergio-multitenancy-v0.2.0...convergio-multitenancy-v0.3.0) (2026-04-12)


### ⚠ BREAKING CHANGES

* **security:** TenancyError has new variants (InvalidOrgId, Unauthorized)

### Features

* initial convergio-multitenancy from template ([7b74984](https://github.com/Roberdan/convergio-multitenancy/commit/7b749840691be88b06545b6e83b1a6ba0c4dc83d))


### Bug Fixes

* **security:** harden tenant isolation and input validation ([#2](https://github.com/Roberdan/convergio-multitenancy/issues/2)) ([d95c27c](https://github.com/Roberdan/convergio-multitenancy/commit/d95c27c65de26bc9ae78b9ed0a46ead245b12458))

## 0.1.0 (Initial Release)

### Features

- Initial extraction from convergio monorepo
