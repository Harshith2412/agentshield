# Release checklist

- [x] Confirm version and changelog
- [x] PyPI distribution name verified: `agentshield-provenance`
- [x] Run complete tests and documentation examples
- [x] Run Ruff, Bandit, and secret/path scans
- [x] Run `pip-audit` for base and selected optional environments
- [x] Run all benchmarks and baseline verification
- [x] Generate and inspect CycloneDX SBOM
- [x] Build wheel and sdist; run `twine check dist/*`
- [x] Audit archive contents and metadata
- [x] Install wheel in a clean environment; run help and demo
- [x] Validate base optional-dependency isolation and framework extras
- [x] Validate README links and `CITATION.cff`
- [x] Review security policy and responsible-use guidance
- [ ] Obtain human release approval before tag or publication
- [ ] Upload distribution to PyPI
- [ ] Create GitHub Release
