# macOS 适配 —— 未实现 / 降级功能清单

> 分支：`adapt/mac`。此文件记录 Mac 第一版中**尚未真实实现**（先 no-op 或占位）的桌面集成功能。
> 原则：核心路由链路真实实现；桌面集成类（进程控制/代理/自启动/更新器）第一版先降级为安全 no-op，后续逐项升级。
> 每项标注：Windows 现状 → Mac 第一版降级方式 → 后续升级路径。
> 2026-09-09 更新：1/3/4/6 已真实实现；8 部分（host 支持 SIGTERM 优雅停机）；2（Gemini OAuth）在 Mac 明确不可用（UI 已置灰）；托盘/更新器见下。

---

## 编译与启动状态（2026-09-08）

- ✅ **`cargo build` 在 macOS (aarch64-apple-darwin) 下 0 错误通过**，产出 `codex-router` + `codex-router-host` 两个 Mach-O arm64 二进制。
- ✅ **GUI 二进制启动后进入 eframe 事件循环持续存活**（不再是 `main.rs` 里 exit(2) 占位符）。
- ⚠️ **窗口「肉眼可见渲染」尚未验证** —— 当前在 headless 会话内跑，需你在真 Mac 桌面双击运行确认。
- 剩余 4 个 `dead_code` warning（`ServiceKind::name`、`router_credential_target`、`router_legacy_credential_target`、`CodexRestartOutcome::Restarted/RelaunchSkipped`）均为 Mac 分支未引用的预期结果，无害。

---

## 已真实实现（可放心）

| 功能 | 说明 |
|---|---|
| 凭证存储 | `credentials.rs`：Windows 走 Credential Manager；Mac 走 `security` CLI 的 Keychain（read/write/delete 三原语已实现） |
| GUI 框架 | eframe/egui/tray-icon/image 等依赖已从 `cfg(windows)` 迁出，可跨平台编译 |
| 打开外部 URL | `platform.rs::open_external_https_url`：Mac 用系统 `open` 命令真实实现 |
| 环境变量代理 | `proxy.rs`：跨平台的 HTTP(S)_PROXY/NO_PROXY 环境变量走代理保留 |

---

## 未实现 / 降级（需后续升级）

> 状态符号：⬜ 未开始　🟡 已 no-op 占位（编译通过但功能未实现）　✅ 已真实实现

### ✅ 1. 重启 Codex 桌面客户端 `platform.rs::restart_codex_desktop`
- **Windows 现状**：`Toolhelp32Snapshot` 枚举进程 → `TerminateProcess` 杀 → `ShellExecuteW`/`explorer shell:AppsFolder` 重启（`ChatGPT.exe`）。
- **Mac 实现**：`pgrep -x ChatGPT` 定位 → SIGTERM（5s）→ SIGKILL 兜底 → `open -a <bundle>` 重启（bundle 路径从被杀进程的 argv[0] 反推，缺省 `ChatGPT`），10s 内回查。
- **真机核对**：`/Applications/ChatGPT.app` 存在 ✅；`pgrep`/`ps` 输出格式已核对；**重启本体的真机实测未做**（当时 ChatGPT 正在运行，不便杀），用户可从 GUI 点“重启”验证。

### ✅ 2. 打开外部 URL `platform.rs::open_external_https_url`
- **Windows 现状**：`ShellExecuteW(..., "open", url)`。
- **Mac 实现**：`std::process::Command::new("open").arg(url)` 真实实现 ✅（前轮已做，此处补记）。

### ✅ 3. 系统代理发现 `proxy.rs::resolve_current`
- **Windows 现状**：WinHTTP (`WinHttpGetIEProxyConfigForCurrentUser`) + 注册表读代理 + `WinHttp` 直连探测。
- **Mac 实现**：`scutil --proxy` 解析（HTTP/HTTPS/SOCKS 开关+端口+例外表）填入共享的 `internet` 槽，来源标 `macos`；环境变量、显式配置、直连探测逻辑全部复用。
- **真机核对**：本机 Clash（127.0.0.1:7897）被正确识别为 `macos` 来源 ✅。

### ✅ 4. 自启动 `autostart.rs::set_enabled/is_registered`
- **Windows 现状**：注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 写 `Codex-Router.exe --background`；清理旧快捷方式/schtasks。
- **Mac 实现**：写 `~/Library/LaunchAgents/com.github.hernanjiang.codexrouter.plist`（`Codex-Router --background` + `RunAtLoad`）+ `launchctl bootstrap/bootout`；禁用即删 plist。
- **真机核对**：`plutil -lint` OK，dummy 程序 bootstrap→运行→bootout→消失全链路 ✅。Windows 旧逻辑原样搬进 `mod win`（已做机械等价 diff，可放心）。

### 🟡 5. 更新器的 ShellLink（开始菜单快捷方式）`updater.rs`
- **Windows 现状**：`IShellLinkW`+`IPersistFile` 创建 `.lnk` 快捷方式（`#[cfg(windows)]` 已局部隔离）。
- **Mac 第一版**：对应 Mac 分支 no-op（不创建快捷方式）。
- **后续路径**：Mac 用 `.app` bundle + `dmg` 分发，无需 `.lnk`；更新器本身（`check_for_updates`/`download_and_stage_update`）跨平台可复用。

### ✅ 6. 单实例锁
- **Windows 现状**：`acquire_single_instance()`（Windows mutex/命名互斥体）。
- **Mac 实现**：`~/Library/Application Support/Codex-Router/gui-single-instance.lock` 的 `flock(LOCK_EX|LOCK_NB)`，内核在进程死亡时自动释放，无 stale 锁；`main()` 已全平台启用，重复启动弹 rfd 提示框后退出。

### 🟡 7. 进程孤儿清理（Job Object）
- **Windows 现状**：`router_host.rs::assign_kill_on_close_job` 把 CLI 子进程绑到 Job Object，宿主退出时连带杀子进程。
- **Mac 进展**：host 现已处理 SIGTERM（优雅停机顺手杀 CLI 子进程），真机验证 SIGTERM 后 host+cli 双亡、端口释放 ✅；加上 lifecycle 的 lsof 兜底清扫，同镜像残留会被下次启动清掉。
- **后续路径**：Mac 用进程组（`setpgid`/`posix_spawn` flag）或子进程 watchdog（目前够用，暂不做）。

### 🟡 8. 托盘后端确认
- **Windows 现状**：`tray-icon` crate 的 Windows 后端。
- **Mac 现状**：`tray-icon` 本身已支持 macOS（依赖里有 `muda`+`objc2-app-kit`），创建代码纯跨平台、失败只降级（无崩溃路径）；但**真机托盘图标显示/交互尚未肉眼验证**（headless 会话看不见）。
- **后续路径**：用户在桌面确认菜单栏图标出现 + 右键菜单可用。

---

## 待真机核对的 UNVERIFIED 外部事实

| 事实 | 状态 | 影响 |
|---|---|---|
| Codex Desktop 是否有 macOS 版 (`ChatGPT.app`/`Codex.app`) | 已确认：`/Applications/ChatGPT.app` 存在 | 「重启 Codex 桌面」已真实实现 |
| CLIProxyAPI darwin 包是否内置 Gemini CLI 插件 | darwin 主包不带，但独立仓库 `cpa-plugin-gemini-cli` v1.0.5 有官方 `darwin_arm64` 构建 | **已接入**：`app/plugins/darwin/arm64/gemini-cli.dylib`（哈希 pin + 真机注册成功 + 路由 200），UI 置灰已撤销 |
| OAuth 快照文件保护（DPAPI） | Windows 用 DPAPI；Mac 已实现等价：AES-256-GCM + 钥匙串 DEK（`CR1` 魔数头，旧明文自动兼容） | 单测覆盖 roundtrip/篡改/透传；DEK 已落钥匙串 ✅ |
| `security` CLI 在真机读写 Keychain | 已确认可用（`find-generic-password` 存在） | 凭证功能可真实实现 |
| eframe 0.35 在 Mac 真机窗口显示 | 编译通过，未肉眼验证 | GUI 里程碑 |
