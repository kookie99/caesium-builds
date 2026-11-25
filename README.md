# Caesium Windows builds

On-demand Windows x64 installers of [Caesium Image Compressor v3](https://github.com/Lymphatus/caesium-v3), built from official upstream source. These are **unofficial, unsigned development builds**, not releases endorsed by the upstream developer. The upstream MIT license is included with each installer.

## Run a build

Open [Build Caesium Windows x64](https://github.com/kookie99/caesium-builds/actions/workflows/build-windows.yml) and select **Run workflow** on `main`.

| Input | Default | Options / purpose |
| --- | --- | --- |
| source_ref | `main` | Official main, a full commit reachable from main, or an official version tag |
| build_mode | `upstream` | Choose `security-patched` for reviewed Rust lockfile patches and compatible npm security remediation |
| node_version | `26.13.1` | Tested exact version; select `26.x` or a newer exact version if necessary |
| rust_version | `1.100.0` | Tested exact version; `stable` selects newest stable |
| rust_audit_policy | `block` | `report` permits builds with disclosed RustSec findings for investigation only |

For personal use, select `security-patched` and keep the default RustSec policy `block`. For workflow validation against a known vulnerable upstream revision, explicitly choose `report`. Report mode is useful for investigating advisories, including crates for platforms other than Windows; do not treat a report-mode success with findings as security approval. Review all audit reports before installation.

The default exact toolchain versions match the successful November 25, 2026 build, not a claim that they are always the latest. MSVC, NASM and runner images can still change. New upstream requirements may require adjusting the toolchain inputs.

## What the workflow verifies

- Restricts source refs to official main history or version tags; records the actual commit, workflow commit, runner image and toolchain.
- Uses SHA-pinned official GitHub Actions and read-only build permissions; checkout credentials are not persisted.
- Audits the upstream npm lockfile and installed tree, both full and production-only.
- In patched mode, runs `npm audit fix --package-lock-only --ignore-scripts --no-force`, preserves upstream dependency manifests, records the effective npm lockfile and patch, and blocks the installer if any npm findings remain. Upstream mode preserves the original lockfile and reports findings.
- Audits the entire Cargo.lock using the official precompiled Windows x64 cargo-audit 0.23.0 release, with a pinned archive SHA-256 and version check. Fetches the current RustSec database; records its revision and rejects unexpected advisory exclusions. In upstream mode the original Rust lockfile is preserved. In security-patched mode, the reviewed exact versions cookie 0.18.2 → 0.18.3 (RUSTSEC-2026-0594) and url 2.5.8 → 2.5.9 (RUSTSEC-2026-0592) are applied using Cargo's targeted resolver. Any unrelated package, checksum, dependency edge or manifest change blocks the build. Already fixed or newer versions are not downgraded. The reviewed advisories must be absent from the final audit even in report mode. New vulnerabilities require separate review. An invalid or unavailable audit fails either mode; known vulnerabilities block when the Rust policy is `block`. Informational warnings are recorded.
- Generates an npm CycloneDX inventory and Windows-filtered Cargo metadata. These are dependency inventories, not a complete SBOM of the final executable.
- Runs TypeScript checks, an optimized Windows x64 Tauri/NSIS build and upstream Rust library regression tests. The tests include file collision and atomic output behavior in the current upstream revision.
- Checks dependency hashes again after compilation and tests, rejects unexpected tracked source changes, and confirms the standalone executable did not change during regression testing.
- Extracts the NSIS installer without executing it, checks the AMD64 PE header, and verifies the embedded executable against the compiled binary. Tauri temporarily replaces its first `__TAURI_BUNDLE_TYPE_VAR_UNK` marker with `__TAURI_BUNDLE_TYPE_VAR_NSS` during NSIS bundling and restores the standalone binary afterward. Only an exact match or the exact documented marker substitution is accepted; any other change blocks publication. The installed-executable hash is calculated from the embedded payload.
- Publishes a versioned structured manifest, installer SHA-256, actual embedded-executable SHA-256, and checksums for every accompanying report and supporting file.
- Downloads the exact installer artifact in an independent Linux job, checks installer and supporting file hashes, source/build identity, audit policies, and report consistency, and creates GitHub artifact attestations for the installer and manifest. The attestation job has scoped OIDC/attestation permissions, does not check out upstream code, and never executes the installer.

The build is not an official release or Authenticode-signed installer. GitHub attestations establish provenance for this repository's build, not approval by the upstream author. A clean audit is not proof of absence of vulnerabilities. Native libraries, npm lifecycle scripts, runtime behavior and all bundled code are not exhaustively security-tested. TypeScript and Rust checks do not substitute for testing the GUI or representative image compression.

## Artifacts

Only use an installer from a run whose **entire workflow** succeeded, including the independent attestation job. A build artifact may exist even if that final job fails. Successful build artifacts are labeled with source version, commit, mode, run ID and attempt. Diagnostics are uploaded even when earlier steps fail where possible.

Installer archive:
- NSIS installer
- `SHA256SUMS.txt`
- `INSTALLED-EXE-SHA256.txt`
- `build-manifest.json`
- Final npm audits, RustSec audit and status, Rust remediation report, original/effective Rust lockfiles, payload verification report, dependency hashes, source record and upstream license

Diagnostics archive:
- Original/effective npm and Rust lockfiles, dependency patches and targeted Cargo update logs
- All npm and RustSec reports, scanner download verification, advisory database revision, audit status, dependency inventories
- Runner/toolchain information and source identity
- Compiler, regression test and installer extraction logs, plus payload comparison details and both executable hashes

Artifacts expire after 90 days. Keep important installers and manifests locally. No automatic release publishing or installation occurs.

## Verify and install on Windows

Extract the downloaded installer artifact ZIP. Open PowerShell in the extracted folder:

```powershell
$M = Get-Content .\build-manifest.json -Raw | ConvertFrom-Json; $I = Join-Path (Get-Location) $M.installer.name; if ((Get-FileHash -LiteralPath $I -Algorithm SHA256).Hash -ne $M.installer.sha256) { throw 'Installer hash mismatch' }; Write-Host 'Installer hash verified'
```

Optional stronger provenance verification, if GitHub CLI is installed:

```powershell
gh attestation verify "$I" --repo kookie99/caesium-builds --signer-workflow kookie99/caesium-builds/.github/workflows/build-windows.yml --deny-self-hosted-runners; if ($LASTEXITCODE -ne 0) { throw 'Installer attestation verification failed' }; gh attestation verify .\build-manifest.json --repo kookie99/caesium-builds --signer-workflow kookie99/caesium-builds/.github/workflows/build-windows.yml --deny-self-hosted-runners; if ($LASTEXITCODE -ne 0) { throw 'Manifest attestation verification failed' }
```

Close Caesium, back up the active settings.json privately, and install over the existing version when appropriate. Then compare the installed executable to the manifest (default per-user install directory):

```powershell
$Exe = Join-Path $env:LOCALAPPDATA ('Caesium Image Compressor\' + $M.executable.name); if ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash -ne $M.executable.sha256) { throw 'Installed executable differs from build manifest' }; Write-Host 'Installed executable verified'
```

Confirm settings remain intact and test a few disposable copies of JPEG, PNG, WebP and any other important formats. Never upload personal settings or images to this public repository.

## Maintenance

- [Workflow validation](https://github.com/kookie99/caesium-builds/actions/workflows/validate-workflows.yml) runs actionlint, payload unit tests on Windows and Linux, manifest acceptance/tamper tests against the exact production verification code, the targeted Rust remediation tests, and the shared RustSec scanner before and after real Cargo resolution on a pinned upstream revision. When the prior known-good build artifact is still retained, trusted main-branch pushes also exercise actual NSIS extraction and marker verification on it. The historical fixture is skipped after artifact expiration. These checks do not replace a full build and attestation run.
- Dependabot checks action pins weekly and proposes pull requests; review changes before merging. It does not automatically update the upstream application's dependencies.
- The main build remains manually triggered. No recurring builds are scheduled.
- The exact source commit, manifests, dependency lockfiles and toolchain records improve traceability; bit-for-bit reproducibility is not guaranteed because runner images, registry state, build tools and advisories can change.

## License

Original application: [Lymphatus/caesium-v3](https://github.com/Lymphatus/caesium-v3). The build override disables signed updater-artifact generation, not the upstream updater itself. The optional npm and reviewed Rust remediation change only the runner checkout, not the upstream repository.
