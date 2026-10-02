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

## Prepared publisher handover

`conformance-publish.yml` reuses the installed-artifact package build. Its manual default only builds. Root library release tags are ignored; conformance releases use `conformance-v<package-version>` and must match `conformance/pyproject.toml`. Publication is disabled unless its explicit repository variable is `true`.

Before enabling either publisher:

1. Configure the existing `agentrust-trace-tests` project with repository `agentrust-io/trace-spec`, workflow `conformance-publish.yml`, and the matching environment: `conformance-testpypi` or `conformance-pypi`.
2. Configure independent environment approval and verify two available package owners/release operators. Louie and Rajnish are the proposed operators; their package access is not yet verified.
3. Set `CONFORMANCE_TESTPYPI_ENABLED=true` only after its TestPyPI binding and approvals are ready. Run the manual TestPyPI target and verify the installed artifact.
4. Enable `CONFORMANCE_PYPI_ENABLED=true` only after the production binding and approval requirements are verified. Publish an approved, previously unpublished conformance version; do not republish an existing version or bump versions solely for migration.
5. Link the successful production run and installed-package verification before retiring the old publisher.

The workflow is prepared, not evidence that a trusted publisher or environment has been configured. Keep the original release path active until verification.

For documentation, use a host supporting a separate project/site from the same repository, with `conformance/` as its project root. Existing `conformance-docs.yml` builds the site artifact. Verify the separate deployment and custom domain before changing DNS or retiring the original site. Do not deploy that artifact to the specification's GitHub Pages site.
