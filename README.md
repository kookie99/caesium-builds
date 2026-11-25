# caesium-builds

Automated Windows x64 builds of Caesium Image Compressor v3 from the [official upstream repository](https://github.com/Lymphatus/caesium-v3).

These are **unofficial, unsigned development builds**, not releases endorsed by the upstream developer. Upstream source is MIT-licensed; its license accompanies the installer artifact.

## Build a Windows installer

1. Open [Build Caesium Windows x64](https://github.com/kookie99/caesium-builds/actions/workflows/build-windows.yml).
2. Select **Run workflow** on the **main** branch.
3. Enter an upstream source ref (default: `main`). A full commit SHA is recommended when reproducing a particular build.
4. Select a build mode (see below).
5. Start the workflow and open the run when it completes.
6. Review the job summary and the `build-diagnostics-*` artifact. Download the installer only after reviewing the reports.

## Build modes

| Mode | Dependency behavior | npm audit policy |
| --- | --- | --- |
| `upstream` (default) | Preserves upstream package.json, package-lock.json and Cargo.lock | Reports known findings; valid audits required, findings alone do not block build |
| `security-patched` | Opt-in compatible npm audit fixes to the lockfile only; no forced upgrades | Requires zero reported findings in both full and production audits of the patched lockfile and installed tree; otherwise no installer is uploaded |

Both modes audit the original lockfile and the installed dependency tree, with separate full and production-only JSON reports. The patched mode also audits the remediated lockfile before installing dependencies. The remediation command is `npm audit fix --package-lock-only --ignore-scripts --no-force`; package.json and Cargo.lock must remain unchanged. If fixes require changing declared dependency ranges or leave findings, the patched build fails rather than forcing an upgrade. Failed runs retain available diagnostics.

The build uses a standard GitHub-hosted Windows x64 runner, Node.js 26, stable Rust/MSVC, NASM, npm ci, locked Rust dependencies, TypeScript checks and Tauri's NSIS bundler. The source SHA, toolchain versions, original and effective npm lockfiles, effective dependency file hashes, lockfile patch (patched mode), upstream license, compiler logs and installer SHA-256 are recorded. Installer artifacts identify the build mode in their names. Dependency file hashes are rechecked after compilation.

An npm production-only audit is a dependency classification, not proof that the affected code ships in the final Tauri binary. Zero reported npm findings does not establish that a build is secure; Rust vulnerabilities, native libraries, supply chain attacks and runtime behavior are not comprehensively audited by this workflow. Builds are unsigned. Toolchains and registry advisories can change over time; recorded inputs improve traceability but do not guarantee bit-for-bit reproducibility.

Artifacts expire after 90 days. No automated installation, source synchronization, release publishing or repository write token is required by the workflow.

## Verify and install

Extract the artifact ZIP. In PowerShell, run `Get-FileHash -Algorithm SHA256 -LiteralPath '.\<installer filename>.exe'` (replace the placeholder with the actual filename) and compare with SHA256SUMS.txt. A matching hash verifies the downloaded bytes against the build record, not an upstream digital signature.

Back up your existing Caesium settings before installing a new build. Close the application, verify the installer and source identity, and test representative copies of images after installation. Do not publish personal configuration files or image data in this repository.

## Source and license

Original application: [Lymphatus/caesium-v3](https://github.com/Lymphatus/caesium-v3). Each run records the actual checked-out commit and copies the upstream license. Updater-artifact generation is disabled through a local Tauri configuration override. The optional security-patched mode also modifies the npm dependency lockfile in the disposable runner checkout; changes are not pushed to upstream.
