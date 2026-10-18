# Building and testing

BFME Beacon is a Cargo workspace. The player side (`Beacon.exe`, `wsock32.dll`) is
built on Windows with the LLVM-based MinGW targets (`*-pc-windows-gnullvm`); the
server also builds as a static Linux binary. CI does the same on GitHub Actions
(see [CI and releases](#ci-and-releases)).

| Crate | Target | Output |
|---|---|---|
| `beacon-proto` | all | library (wire formats, crypto) |
| `beacon-server` | host, `x86_64-unknown-linux-musl` | `beacon-server` |
| `beacon-launcher` | `x86_64-pc-windows-gnullvm` | `Beacon.exe` |
| `beacon-hook` | `i686-pc-windows-gnullvm` | `wsock32.dll` (32-bit, for `lotrbfme.exe`) |
| `beacon-hook-harness` | `i686-pc-windows-gnullvm` | 32-bit test program for the hook |

## Toolchains

* **Rust stable** via rustup. The dev PC uses the `x86_64-pc-windows-gnullvm` host
  toolchain plus the targets `i686-pc-windows-gnullvm` and
  `x86_64-unknown-linux-musl`:
  ```sh
  rustup toolchain install stable-x86_64-pc-windows-gnullvm --component clippy \
      --target i686-pc-windows-gnullvm --target x86_64-unknown-linux-musl
  rustup default stable-x86_64-pc-windows-gnullvm
  ```
* **llvm-mingw** (msvcrt variant, x86_64 host) from
  <https://github.com/mstorsjo/llvm-mingw/releases>, unpacked anywhere. It provides
  the clang/lld linker drivers and the import libraries for both Windows targets.
  CI pins the release and its SHA-256 in
  [`.github/scripts/setup-llvm-mingw.ps1`](../../.github/scripts/setup-llvm-mingw.ps1).
* **Python 3** with `pefile` for the hook's export tools
  (`python -m pip install pefile`).

### Linker configuration

The linker paths are machine-specific and live outside the repository, in
`$CARGO_HOME/config.toml` (example with llvm-mingw in `C:/llvm-mingw`):

```toml
[target.x86_64-pc-windows-gnullvm]
linker = "C:/llvm-mingw/bin/x86_64-w64-mingw32-clang.exe"
rustflags = ["-C", "target-feature=+crt-static"]
[target.i686-pc-windows-gnullvm]
linker = "C:/llvm-mingw/bin/i686-w64-mingw32-clang.exe"
rustflags = ["-C", "target-feature=+crt-static"]
[target.x86_64-unknown-linux-musl]
linker = "rust-lld"
[env]
CC_x86_64_pc_windows_gnullvm = "C:/llvm-mingw/bin/x86_64-w64-mingw32-clang.exe"
CC_i686_pc_windows_gnullvm = "C:/llvm-mingw/bin/i686-w64-mingw32-clang.exe"
AR_x86_64_pc_windows_gnullvm = "C:/llvm-mingw/bin/llvm-ar.exe"
AR_i686_pc_windows_gnullvm = "C:/llvm-mingw/bin/llvm-ar.exe"
```

`+crt-static` matters: without it the binaries import `libunwind.dll` from
llvm-mingw, which players do not have. CI sets the same values through
`CARGO_TARGET_<TRIPLE>_LINKER` / `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` environment
variables. On a Linux host the musl target needs no configuration.

## Cargo aliases

Defined in [`.cargo/config.toml`](../../.cargo/config.toml):

| Alias | Runs | Output |
|---|---|---|
| `cargo hook` | `build --profile release-hook -p beacon-hook --target i686-pc-windows-gnullvm` | `target/i686-pc-windows-gnullvm/release-hook/wsock32.dll` |
| `cargo hook-harness` | `run -p beacon-hook-harness --target i686-pc-windows-gnullvm --` | runs the harness scenarios against the `cargo hook` output |
| `cargo server-linux` | `build --release -p beacon-server --target x86_64-unknown-linux-musl` | `target/x86_64-unknown-linux-musl/release/beacon-server` |

## Release files

```sh
cargo build --release -p beacon-launcher       # target/release/Beacon.exe
cargo hook                                     # wsock32.dll
python crates/beacon-hook/tools/check_exports.py \
    target/i686-pc-windows-gnullvm/release-hook/wsock32.dll
cargo server-linux                             # static Linux server
```

`Beacon.exe` and `wsock32.dll` ship together in one folder. The Docker image is
built from [`deploy/Dockerfile`](../../deploy/Dockerfile) around the static server
binary.

## Tests

```sh
cargo test -p beacon-proto -p beacon-server -p beacon-launcher -p beacon-hook
cargo test -p beacon-proto --no-default-features
cargo test -p beacon-hook --target i686-pc-windows-gnullvm
cargo hook && cargo hook-harness
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p beacon-hook -p beacon-hook-harness --target i686-pc-windows-gnullvm \
    --all-targets -- -D warnings
```

* On Linux only `beacon-proto` and `beacon-server` are built and tested.
* No test starts the game. One hook test reads `C:\BFME1\lotrbfme.exe` and
  `worldbuilder.exe` if they exist and is skipped otherwise.
* `check_exports.py` and the harness compare the hook with the system's
  `C:\Windows\SysWOW64\wsock32.dll`.
* `beacon-server` tests: `BEACON_TEST_LOG=1` prints the server logs.

## Smart App Control on the dev PC

With Windows Smart App Control on, every freshly built, unsigned binary (build
scripts, test executables, `Beacon.exe`, the harness) is checked and is
occasionally blocked: `os error 4551` ("An Application Control policy has blocked
this file").

* Retry the command; if `rustc` or a build script itself is blocked, wait a while
  and retry.
* Build scripts compiled with debug info were blocked on the dev PC; setting
  `CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG=false` in the environment helped. It is
  not part of the workspace profile because verdicts differ per binary and target
  folder.
* A separate `CARGO_TARGET_DIR` per line of work avoids rebuilding binaries that
  were already allowed.
* Keep the dependency graph small. The build scripts of `ahash` and `num-traits`
  (pulled in by `eframe`) were blocked, which is why the UI is a local web page.
* Never weaken security settings to get a build through.

The release binaries are unsigned, so players with Smart App Control may be
blocked as well. Authenticode signing through SignPath is prepared as a commented
step in `release.yml`.

## CI and releases

* [`ci.yml`](../../.github/workflows/ci.yml) runs on every branch push and pull
  request (and is called by the release workflow):
  * **windows-latest:** gnullvm toolchain, pinned llvm-mingw, `cargo hook` and
    `check_exports.py`, tests (x86_64 and the hook on i686), the hook harness,
    clippy for both targets.
  * **ubuntu-latest:** `beacon-proto` and `beacon-server` tests and clippy, the
    static musl build of `beacon-server`.
* [`release.yml`](../../.github/workflows/release.yml) runs on tags `v*`: CI, then
  `Beacon-<version>-windows.zip` (`Beacon\Beacon.exe`, `wsock32.dll`,
  `LIESMICH.txt`, `LICENSE.txt`), `beacon-server-<version>-linux-x86_64`, the image
  `ghcr.io/floderso/bfme-beacon-server:<version>` (and `:latest` for
  non-prereleases), `SHA256SUMS`, and the GitHub release with the notes from
  `CHANGELOG.md`.

To release:

1. Set `version` in `[workspace.package]` of `Cargo.toml` and run `cargo check` so
   `Cargo.lock` follows.
2. Add a `## [x.y.z] - YYYY-MM-DD` section to `CHANGELOG.md`.
3. Commit, tag `vx.y.z`, push the tag. The workflow refuses a tag that does not
   match the workspace version or has no changelog section. A version with a
   suffix (`0.2.0-rc.1`) becomes a prerelease without `:latest`.

To update llvm-mingw, change the release and its SHA-256 in
`.github/scripts/setup-llvm-mingw.ps1` (GitHub shows each asset's digest on the
release page).
