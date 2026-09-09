# CodexRouter macOS 适配 —— 会话交接文档

> 分支：`adapt/mac`（基于 main 3.2.9，commit `30dcdba`）
> 更新时间：2026-09-09
> 目标：让 Windows-only 的 CodexRouter 适配 macOS，最终发布 Mac release 包。

---

## 本轮完成（2026-09-09，核心链路代码 ✅）

- 共享平台抽象：`backend/config_compiler.rs` 新增 `executable_file_name` / `gui/host/cli_executable_file_name` / `gemini_plugin_relative_path`（Mac 为 None）/ `required_runtime_relative_paths`，Windows 返回值与旧硬编码逐字节一致。
- 哈希按平台区分：`CLI_PROXY_SHA256_MACOS=5f24eb…3531fb`、`CLI_PROXY_PACKAGE_SHA256_MACOS=c5f6e7…0475dd`（包哈希与上游 `checksums.txt` 对上；二进制为 Mach-O arm64 真机 `--help` 跑通 `7.2.135/commit 856ddd8d`）。`THIRD_PARTY_NOTICES.md` 已同步。
- `start_cli`（`router_host.rs`）：Mac 跳过 gemini `.dll` 校验；`default_runtime_config` 在 Mac 置 `plugins.enabled=false`；`validate()` 的 gemini 锁仅 Windows 强制（lib Default 不变，旧测试全过）。
- 路径：`is_router_root` / `host_executable` / `cli_executable` / `ensure_required_layout` / 向导页校验全部走抽象；`pids\*.pid` 反斜杠 join 改 `join("pids").join(..)`（Mac 下旧写法会写出带 `\` 的单文件）。
- updater：helper 名、VC runtime 拷贝、`verify_release_root`、`launch_updated_app` 跨平台（Windows 行为不变）。
- **额外发现并修复**：① `logic.rs` 的 `read/write/delete_router_credential` 在 Mac 是静默 no-op，导致“加 API key”整条写坏——已桥接到 `crate::credentials`（Keychain），8 个相关测试转绿；② Mac `LifecycleLock` drop 不删文件，第二次起服务必 BUSY——已加带 PID 归属检查的 `Drop`；③ `cargo test --bin codex-router` 在 Mac 根本编不过（5 处 Windows-only 测试代码缺 cfg 门）——已补 `all(test, windows)` / `#[cfg(windows)]` 门，Windows 语义不变。
- 验证：`cargo test --locked` 全绿（lib 201 + GUI bin 500 + host bin 8，3 ignored 均为预先 ignore）；`cargo clippy --all-targets` 0 unused；`cargo check` 仅剩 HANDOFF 记录过的 dead_code 类 warning。Windows-only 打包流测试（updater manifest/powershell/DPAPI/TCP 表）已门住，Windows CI 仍会跑。
- 第三方包位置：`/tmp/cr-mac/cli135-darwin-aarch64.tar.gz`（解包 `/tmp/cr-mac/ex/cli-proxy-api`），`/tmp` 重启会丢，重装包按 THIRD_PARTY_NOTICES 哈希重下即可。
- 测试包位置：`Release-mac-test/CodexRouter/`（`Codex-Router` + `app/codex-router-host` + `app/cli-proxy-api`，debug 构建，每次改完需重拷）。

---

## 本轮完成（2026-09-09 第二轮，用户真机报错驱动）

- 用户报错“安全登录环境准备失败：本地 Router 未能稳定启动”，根因是 Mac 进程管理四个 no-op：`process_exists` 恒 false → `wait_host_ready` 永不可能成功；`listener_process_id`/`loopback_listener_pid` 恒 None → 残留进程不可见；`terminate_*` 空实现 → 重试直接 EADDRINUSE（`router-host-stderr.log: Address already in use`）。
- 修复（`lifecycle.rs`，新增 `libc` 依赖）：`process_exists` 用 `kill(pid,0)`（EPERM 视为存在）；`process_path` 用 `ps -o command=` 取 argv[0]；`terminate` 用 SIGTERM→等10s→SIGKILL（`waitpid(WNOHANG)` 处理僵尸子进程）；`listener/loopback_listener_pid` 用 `lsof -iTCP -sTCP:LISTEN -Fn` 解析（缺 lsof 则退化回 None）。Windows 行为零改动。
- 新增 3 个 Mac 单测（exists/reap、terminate sleep、listener 自举），GUI bin 全量 503 pass 连绿 3 次；`cargo test` 全绿（lib 202 + bin 503 + host 8）。
- 黑盒复验：host 直拉真 darwin CLI，`/health` 200、`/v1/models` 带 key 200/不带 401、`plugins.enabled=false` 落盘生效。
- **端到端打通（2026-09-09 真机）**：用户经 GUI 向导配好 mimo-v2.5 并一键部署后，`GET /v1/models` 返回 `mimo-v2.5`，`POST /v1/chat/completions` 透过本机 18080 → host → darwin CLIProxy → 上游拿到真实回复（MiMo-v2.5 自我介绍）。Mac 核心链路闭环。

---

## 本轮完成（2026-09-09 第三轮，辅助功能打通）

- `autostart.rs` 393 行 diff 已 review：纯搬运进 `mod win` + Mac no-op，机械 diff 只有 fmt/空行，Windows 语义一致 ✅。
- 单实例：`flock` 文件锁（`~/Library/Application Support/Codex-Router/gui-single-instance.lock`），`main()` 全平台启用，重复启动弹 rfd 提示后退出；单测覆盖 等待锁释放语义。
- 自启动：launchd plist（`com.github.hernanjiang.codexrouter`，`--background` + RunAtLoad）+ bootstrap/bootout；`plutil` OK + dummy 程序上下线真机验证 ✅。
- 系统代理：`scutil --proxy` 解析填共享 `internet` 槽，来源标 `macos`；本机 Clash（127.0.0.1:7897）真实识别 ✅。
- 重启 Codex 桌面：`pgrep -x ChatGPT` → SIGTERM(5s) → SIGKILL → `open -a` bundle（从被杀进程 argv[0] 反推）；`/Applications/ChatGPT.app` 存在 ✅；**杀进程本体未真机实测**（当时用户在用）。
- 孤儿清理：host 支持 SIGTERM 优雅停机（顺手杀 CLI），真机验证双亡+端口释放 ✅。
- Gemini 缺口收敛：两处 OAuth picker + `start_provider_oauth` 在 Mac 对 gemini 置灰/拒绝（API Key 渠道不受影响）。
- 验证：`cargo test` 全绿（lib 202 + bin 512 + host 8），clippy 0 unused，全量 2 次确认；改动未提交。
- 待用户真机确认：托盘图标出现与否、GUI 重启后 flock 生效（旧 GUI 进程无锁）、设置页自启动开关、ChatGPT 重启按钮。

---

## 本轮完成（2026-09-09 第四轮，存盘加密）

- Mac OAuth 快照文件保护：Windows DPAPI 的等价实现——AES-256-GCM（新增 `aes-gcm` 依赖），DEK（32 字节随机）存钥匙串 `FileProtectionKey`，blob 格式 `CR1` 魔数 + 12 字节随机 nonce + 密文tag；无魔数的旧明文文件透传兼容。
- 单测：roundtrip、nonce 随机性、密文无明文残留、篡改必报认证错、截断报错；DEK 落钥匙串真机确认 ✅。
- `cargo test` 全绿（lib 202 + bin 513 + host 8），clippy 0 unused；测试包二进制已更新；改动未提交。

---

## 本轮完成（2026-09-09 第五轮，Gemini 插件反转 + 系统层 junk 修复）

- 用户质疑“geminicli 有 Mac 版”是对的，我之前结论下早了。重验：独立仓库 `router-for-me/cpa-plugin-gemini-cli` v1.0.5 **有官方 `darwin_arm64` 构建**（`gemini-cli.dylib` 9.4MB，包哈希与上游 checksums.txt 对上）。
- 真机 live 证据：`pluginhost: plugin loaded/registered`，`/v0/management/plugins` 报 `registered/effective_enabled/supports_oauth=true`，`gemini-cli-auth-url` 200（无插件时 404；其余 5 家 OAuth 路由 darwin 原生 200，不需插件）。
- 落地：`GEMINI_PLUGIN_SHA256_MACOS` + 包哈希进常量与 NOTICES；`gemini_plugin_relative_path`/`required_runtime_relative_paths`/`validate`/`apply_platform_runtime_policy`/`start_cli` 全部按 `windows|macos vs 其他` 重切；三处 UI 置灰已撤销；测试包已含 `app/plugins/darwin/arm64/gemini-cli.dylib`。
- 附带修复：部署时往 `app/` 下写出 `C:\ProgramData/...` 字面目录（`codex_system_config_path` 回退路径在 Unix 是相对路径）。Mac 无系统层概念：public 写/删/probe/退出 persist 全部 no-op（`_to/_from` 保留给单测），回归单测 + 3 个 Windows-only 语义测试已门住；测试包内 junk 已删。
- 教训：外部事实必须黑盒验到终态（这次是“路由真返回 200”），不能靠“包里没看到”下结论。
- 教训：凡是“看起来 Ok 但实际没干活”的降级（no-op 返回 Ok/None）都是定时炸弹，Mac 适配里一律按“未实现”处理，要么真实现，要么 loud bail。

---

## 当前状态（已完成 ✅）

### 1. 依赖迁移 + cfg 门（编译通过）
- `cargo build` 在 macOS (aarch64-apple-darwin) 下 **0 错误通过**，产出两个 Mach-O arm64 二进制：`codex-router` + `codex-router-host`。
- 根因：`Cargo.toml` 里 20 个跨平台依赖（anyhow/serde/chrono/eframe/egui/tray-icon 等）被误锁进 `[target.'cfg(windows)'.dependencies]`，迁移到 `[dependencies]` 后 345 个报错 → 剩 2 个。
- 已适配的文件（Windows API 加 `#[cfg]` 门 + Mac 等价/no-op）：
  - `credentials.rs` → macOS Keychain（`security` CLI，真机核对可用）
  - `proxy.rs` → 无系统代理（环境变量代理保留）
  - `platform.rs` → `open` 命令开 URL 真实实现；进程控制 no-op
  - `autostart.rs` / `logic.rs` / `lifecycle.rs` / `router_host.rs` → cfg 门 + 安全 no-op/等价

### 2. GUI 启动 + 中文显示（真机验证）
- ✅ GUI 窗口真机渲染成功（eframe 事件循环，不再是 `main.rs` 的 exit(2) 占位符）。
- ✅ 中文显示正常（**已修复**）：根因是 `windows_main.rs::install_app_fonts` 硬编码从 `C:\Windows\Fonts` 读微软雅黑。已新增 `platform_font_sources()` 按平台分流，Mac 读 `/System/Library/Fonts` 的 `Hiragino Sans GB.ttc` + STHeiti。

---

## 下一步（进行中 🔄 / 待做 ⬜）

### 🔄 核心链路打通（当前正在做，方案 A）
目标：让「GUI 引导 → 识别项目目录 → 启动 Router Host → 启动 CLIProxy → 加 API key → 转发」这条链路在本机跑通。

**已做完：** 下载了 CLIProxy `v7.2.135` darwin aarch64 包（`/tmp/cli_135_darwin.tar.gz`），解出 `cli-proxy-api`（Mach-O arm64，19MB）。
> 关键结论：**`v7.2.135` 上游就有 darwin 包**，不必升到 v7.2.154，版本保持 135 与项目现状对齐。

**待改（关键，伐正在做 — 2026-09-09 已按上述方案落地，未提交）：**

| 位置 | 现状 | 要改成 |
|---|---|---|
| `config.rs:582-585` `is_router_root` | ~~硬编码 `app/codex-router-host.exe` + `app/cli-proxy-api.exe`~~ ✅ 已走 `cli_compiler::{host,cli}_executable_file_name` | ✅ 完成 |
| `lifecycle.rs:679-685` `host_executable`/`cli_executable` | ~~`r"app\codex-router-host.exe"`~~ ✅ 已走抽象 + pid join 修复 + `LifecycleLock` Drop 修复 | ✅ 完成 |
| `lifecycle.rs:871-882` `ensure_required_layout` | ~~硬编码 3 个 Windows 文件~~ ✅ 已走 `required_runtime_relative_paths` | ✅ 完成 |
| `router_host.rs:208-231` `start_cli` | ~~`.exe` 路径 + SHA256 校验 + gemini `.dll`~~ ✅ Mac 无后缀 + Mac 哈希 + 跳过 `.dll` | ✅ 完成 |
| `updater.rs` 多处 `Codex-Router.exe` | ~~硬编码~~ ✅ 已走 `gui_executable_file_name` | ✅ 完成 |

**⚠️ 关键坑（哈希校验）：** `backend/config_compiler.rs:7-15` 里有 `CLI_PROXY_SHA256` / `GEMINI_PLUGIN_SHA256` / `CLI_PROXY_PACKAGE_SHA256` 三个写死的哈希。**Mac 版 CLIProxy 二进制跟 Windows 版不同，哈希必然不一样**，`router_host.rs::start_cli` 的 `sha256_file` 校验会让 Mac 版直接 bail（`CR-CLI-0001: hash mismatch`）。需要：
1. 算出 darwin `cli-proxy-api` 的真实 SHA256；
2. 把哈希常量按平台区分（Windows 用 `0a8ffc...`，Mac 用新算的哈希）。

**设计建议（伐已定的方向 — 2026-09-09 落地时微调）：**
- 共享辅助函数放在 `backend/config_compiler.rs`（lib，GUI 和 host 两个二进制都能用），而不是 GUI 的 `config.rs`（host 二进制引用不到）。`config.rs::is_router_root` 只是调用方。
- Mac 运行时目录结构对齐 Windows 便携包：`CodexRouter/`（GUI）+ `app/cli-proxy-api` + `app/codex-router-host`。
- gemini 插件（`gemini-cli-v1.0.5.dll`）Mac 版**不存在**，`start_cli` 里加载 `.dll` 的逻辑已 `#[cfg(windows)]` 门住，Mac 跳过（代价：Gemini OAuth 登录入口 Mac 暂缺）。
- **新增**：`logic.rs` 凭证读写必须走 `crate::credentials`（Keychain），不得再各自 no-op——Mac 下“看起来 Ok 但实际没存”是灾难性静默失败，本轮已踩过一次。
- **新增**：Windows-only 的测试（powershell/DPAPI/TCP 表/便携包 manifest）一律 `#[cfg(windows)]` 门住再提交，保证 `cargo test` 在 Mac 常绿，Windows CI 照跑。

### ⬜ 桌面集成功能从 no-op 升级（详见 `docs/mac-adaptation-TODO.md`）
| 功能 | 现状 | 后续 |
|---|---|---|
| 系统代理 | 无系统代理 | SystemConfiguration |
| 自启动 | no-op | launchd plist |
| 单实例锁 | 待实现 | 文件锁/flock |
| 重启 Codex 桌面 | no-op | `open -a`（Codex 是否有 Mac 版 UNVERIFIED） |
| Gemini OAuth 登录 | 缺插件 | 上游 darwin 插件缺失 |

### ⬜ release 发布准备
- Mac 打包脚本（现有 `.ps1` 是 PowerShell，需 `.app` bundle + `dmg` 的 shell 脚本）。
- `.app` bundle（Info.plist + 图标 + 可执行）。
- CI `theoretical-unix.yml` 升级（现在还在断言「二进制 exit 2」，要改成「真 GUI 起来 + Mac 包产出」）。
- README/CHANGELOG 同源更新（徽章已谎称支持 macOS，真支持后要更新，按 CLAUDE.md §7）。

---

## 环境关键事实

- **机器**：Apple Silicon Mac（`uname -m` = arm64），macOS Darwin 24.6.0。
- **Rust 工具链**：本次用 `brew install rustup` 装的，rustc 1.98.1。**rustup 是 keg-only，PATH 需 `/opt/homebrew/opt/rustup/bin`**（已写入 `~/.zshrc`）。构建前 `export PATH="/opt/homebrew/opt/rustup/bin:$PATH"`。
- **构建命令**（记得用绝对路径，cwd 会漂）：
  ```bash
  export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
  cargo build --manifest-path /Users/wylam/Documents/workspace/CodexRouter/codex-router-gui-rust/Cargo.toml
  ```
- **项目路径**：`/Users/wylam/Documents/workspace/CodexRouter`（不要用相对路径，shell cwd 每次重置）。
- **GitHub Actions**：已有 `theoretical-unix.yml` 在 macos-latest（arm64+x64）+ ubuntu 跑 build，但之前验证的是 exit(2) 占位符，现已替换为真入口。

---

## 第三方二进制事实（已真机核对）

- **CLIProxyAPI** 上游 `router-for-me/CLIProxyAPI`，每个 release 都有 `darwin_aarch64` + `darwin_amd64` 官方二进制。`v7.2.135` 也有（下载 URL 已验证）。
- CLIProxy darwin 包内容：`cli-proxy-api`（单 Mach-O）+ LICENSE + README + config.example.yaml，**不含 Gemini 插件**。
- gemini 插件是 Windows 专用的 `.dll`，Mac 版缺失。

---

## 遗留 / 需注意

- **`autostart.rs` 的 diff 有 393 行**（subagent 可能做了额外重构），建议后续 code review 时重点看一遍是否引入了不必要的改动。
- 4 个 `dead_code` warning（`ServiceKind::name`、`router_credential_target`、`router_legacy_credential_target`、`CodexRestartOutcome::Restarted/RelaunchSkipped`）是 Mac 分支预期的无害结果。
- 未提交任何 commit（所有改动在工作树，`git status` 有 10 个 modified + 1 个 untracked `docs/mac-adaptation-TODO.md`）。用户未授权 commit/push。

---

## 关联文档

- `docs/mac-adaptation-TODO.md` —— 桌面集成功能降级清单（逐项标注 Windows 现状 → Mac 降级 → 升级路径）。
- `THIRD_PARTY_NOTICES.md` —— CLIProxy/gemini 插件版本与哈希的权威来源。
