# Conformance repository consolidation

The conformance suite is maintained in `trace-spec/conformance/`. It remains a separate Apache-2.0 Python distribution named `agentrust-trace-tests`, with the `trace_tests` import and `trace-tests` CLI. The normative specification's licensing and the root `agentrust-trace` package remain as described in their existing files.

## Imported source

Imported from [trace-tests](https://github.com/agentrust-io/trace-tests) at `482eb5e61eb1f42629b00ffe4ebb9f35d321c7d9`. All 144 non-`.github/` files are included. `conformance/import-manifest.json` records each original Git blob. Package URLs, checkout instructions, documentation edit links and fuzz build paths are adjusted for the new location.

Fixtures, schemas, generators, checker sources, report identifiers, licenses and historical measurement reports retain their imported bytes. Obligation accounting continues to cite its original repository and pinned specification revisions. Those historical locators must remain resolvable; repository consolidation does not change their meaning or establish additional conformance.

The root house-style checker permits an imported file only while its Git blob still matches this fixed import manifest. An edit removes that exception. This preserves Unicode vectors and historical artifacts without exempting future conformance code or prose.

## Validation and maintenance

- `conformance-ci.yml` runs the existing level, unit and full suites on Python 3.11, 3.12 and 3.13 from `conformance/`.
- `conformance-package.yml` builds wheel and source distributions and exercises each installed artifact outside the checkout. It uploads distributions; it does not publish.
- `conformance-docs.yml` builds and uploads the existing documentation site. It does not deploy.
- Root ClusterFuzzLite builds both packages' targets. Root CodeQL scans both trees.
- Dependabot monitors the nested Python project. Conformance paths retain their original maintainer ownership.

Run the suite from its project directory:
```bash
cd conformance
pip install --require-hashes -r requirements/test.txt
pip install --no-deps -e .
python -m pytest -v --tb=short
```

## Cutover after merge

1. Recheck trace-tests main and open work immediately before cutover. [PR #137](https://github.com/agentrust-io/trace-tests/pull/137), portable anchor inclusion vectors, was open at import time; merge and import it or preserve its review in the new location before archiving.
2. Update consuming CI, source checkout URLs, the organization profile, and the website to this directory.
3. Configure a trusted PyPI publisher for the existing package from trace-spec with a separate workflow and release policy. Root library tags must not release the conformance package accidentally. Verify a release from the new publisher before retiring the original release workflow.
4. Move the tests.agentrust-io.com deployment to a host supporting a second site from this repository, or a dedicated deployment repository. A second gh-deploy in trace-spec would overwrite the specification site, so this PR only builds the tests documentation. Keep the existing source deployment active until the replacement is verified.
5. Add a moved notice to the original README and archive trace-tests only after the consumer, release and site cutovers. Retain its Git history, releases and issues; never delete the repository.
