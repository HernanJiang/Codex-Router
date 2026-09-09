# Third-Party Notices

Codex-Router combines original project material with independent third-party software. Codex-Router is licensed under AGPL-3.0; this does not replace, narrow, or claim ownership of third-party rights.

## CLIProxyAPI

- Project: CLIProxyAPI
- Upstream: https://github.com/router-for-me/CLIProxyAPI
- Bundled release: v7.2.135
- Upstream source commit: https://github.com/router-for-me/CLIProxyAPI/commit/856ddd8df746a38a6033dbbf6c140974bf5aea0f
- License: MIT
- License text: `licenses/CLIProxyAPI-LICENSE.txt`
- Bundled Windows amd64 asset SHA-256: `80eef3e63e229405362c0f302abba50909cd53f10f6036c438d3f4f765144d34`
- Bundled executable SHA-256: `0a8ffc52dfb2a466baa1b006341b350bdb1f76fc70b6cc80375bb99afdff697b`
- macOS arm64 asset (`CLIProxyAPI_7.2.135_darwin_aarch64.tar.gz`) SHA-256: `c5f6e785cf7568c177d5c31aa75c389c4bb1b1dee9e0133887b9bce3200475dd` (matches upstream `checksums.txt`)
- macOS arm64 executable (`cli-proxy-api`, Mach-O arm64, no plugin bundled) SHA-256: `5f24ebf3ed2caeee6ff63b5eaba7ccdb66f3ccb7af273ba1f70d68dc2f3531fb`

The bundled `app/cli-proxy-api.exe` is the audited `v7.2.135` Windows amd64 build. The 2.0.0 release builder verifies the executable and the archive hashes above before staging and fails closed on any mismatch. Recipients may exercise the rights granted by CLIProxyAPI's upstream MIT license with respect to CLIProxyAPI itself. Restrictions in Codex-Router's license apply to original Codex-Router material and the Codex-Router combination/distribution, not to independently obtained upstream CLIProxyAPI code.

## Gemini CLI plugin

- Project: Gemini CLI plugin (CLIProxyAPI plugin ABI)
- Upstream: https://github.com/router-for-me/cpa-plugin-gemini-cli
- Version: 1.0.5
- Role: provides the Gemini CLI OAuth login entry (Google One Free and Code Assist project/tier) used by the Router's Gemini OAuth flow
- License: MIT (distributed under the CLIProxyAPI plugin SDK terms)
- Bundled file (Windows): `app/plugins/windows/amd64/gemini-cli-v1.0.5.dll`
- Bundled file (Windows) SHA-256: `c1d849f13270329bff9f4d8ab8ef7507eba57642402beb19c60e66ecc2e40cee`
- Bundled file (macOS arm64): `app/plugins/darwin/arm64/gemini-cli.dylib`
- Bundled file (macOS arm64) SHA-256: `4fbac8a964467c477db9975f9ec38e35254ea60fb950b67418a063b2cde20f1b`
- macOS arm64 asset (`gemini-cli_1.0.5_darwin_arm64.zip`) SHA-256: `3c771ff57e607b40bf95753e0ad2fb01127a296fe4cbff79b49116cd2327b5bb` (matches upstream `checksums.txt`)

The plugin is loaded by the bundled CLIProxyAPI through its plugin ABI. The release builder verifies the pinned hash before staging.

## SQLite

- The 2.0.0 Router keeps its local state in an embedded SQLite database through the `rusqlite` crate, which bundles the SQLite amalgamation.
- SQLite is in the public domain and does not require a license: https://www.sqlite.org/copyright.html
- Notice text: `licenses/SQLite-NOTICE.txt`

## Microsoft Visual C++ Runtime

- Components: `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, and `MSVCP140.dll`
- Architecture: x64
- Build source: the official Microsoft Visual Studio `VC/Redist/MSVC/<version>/x64/Microsoft.VC*.CRT` payload, or an explicitly supplied `VC_REDIST_CRT_DIR` copy of that official payload
- Deployment: one app-local copy beside `Codex-Router.exe`
- Notice and license references: `licenses/Microsoft-Visual-Cpp-Runtime-NOTICE.txt`

The release builder rejects Windows `System32` and `SysWOW64` as runtime sources and verifies each bundled DLL's x64 PE architecture, Microsoft Authenticode signature, version, and hash. The exact runtime version and per-file hashes are recorded in `dependency-manifest.json` and `release-manifest.json`.

## Rust crates

- Locked dependency graph: `codex-router-gui-rust/Cargo.lock` in the source distribution
- Target used for the portable GUI: `x86_64-pc-windows-msvc`
- Exact crate inventory, crate-supplied notices, and bundled SQLite notice: `licenses/Rust-Crates-LICENSES.txt`
- Canonical SPDX license texts: `licenses/Rust-SPDX-LICENSE-TEXTS.txt`

The Rust crate notice bundle is generated from `cargo metadata --locked` during release construction so its versions remain tied to the executable build rather than a hand-maintained dependency list.
