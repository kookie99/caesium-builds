# caesium-builds

Automated Windows x64 builds of Caesium Image Compressor v3 from the [official upstream repository](https://github.com/Lymphatus/caesium-v3).

These are **unofficial, unsigned development builds**, not releases endorsed by the upstream developer. Upstream source is MIT-licensed; its license accompanies the installer artifact.

## Build a Windows installer

1. Open [Build Caesium Windows x64](https://github.com/kookie99/caesium-builds/actions/workflows/build-windows.yml).
2. Select **Run workflow** on the **main** branch.
3. Enter an upstream source ref (default: `main`). A full commit SHA is recommended when reproducing a particular build.
4. Start the workflow and open the run when it completes.
5. Review the `build-diagnostics-*` artifact, especially the npm audit report. Download the installer artifact only after reviewing the results.

The build uses a standard GitHub-hosted Windows x64 runner, Node.js 26, stable Rust/MSVC, NASM, locked dependencies, TypeScript checks and Tauri's NSIS bundler. The source SHA, toolchain versions, lockfile hashes, upstream license, compiler logs and installer SHA-256 are recorded. No private upstream signing key is needed. npm audit findings are reported rather than automatically fixing dependencies; a successful build does not imply a clean security audit or runtime validation.

Artifacts expire after 90 days. No automated installation, source synchronization, release publishing or repository write token is required by the workflow.

## Verify and install

Extract the artifact ZIP. In PowerShell, run `Get-FileHash -Algorithm SHA256 -LiteralPath '.\<installer filename>.exe'` (replace the placeholder with the actual filename) and compare with SHA256SUMS.txt. A matching hash verifies the downloaded bytes against the build record, not an upstream digital signature.

Back up your existing Caesium settings before installing a new build. Close the application, verify the installer and source identity, and test representative copies of images after installation. Do not publish personal configuration files or image data in this repository.

## Source and license

Original application: [Lymphatus/caesium-v3](https://github.com/Lymphatus/caesium-v3). Each run records the actual checked-out commit and copies the upstream license. Only updater-artifact generation is disabled through a local Tauri configuration override.
