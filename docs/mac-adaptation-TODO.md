# macOS 适配 —— 未实现 / 降级功能清单

> 分支：`adapt/mac`。此文件记录 Mac 第一版中**尚未真实实现**（先 no-op 或占位）的桌面集成功能。
> 原则：核心路由链路真实实现；桌面集成类（进程控制/代理/自启动/更新器）第一版先降级为安全 no-op，后续逐项升级。
> 每项标注：Windows 现状 → Mac 第一版降级方式 → 后续升级路径。

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

### 🟡 1. 重启 Codex 桌面客户端 `platform.rs::restart_codex_desktop`
- **Windows 现状**：`Toolhelp32Snapshot` 枚举进程 → `TerminateProcess` 杀 → `ShellExecuteW`/`explorer shell:AppsFolder` 重启（`ChatGPT.exe`）。
- **Mac 第一版**：no-op（返回错误/未运行），不动 Codex 进程。
- **依赖前提**：Codex Desktop 是否有 macOS 版（`ChatGPT.app` / `Codex.app`）需真机核对 —— 若没有 Mac 版桌面客户端，该功能在 Mac 上本就不适用，可考虑直接去掉或指向 `codex` CLI。
- **后续路径**：`NSRunningApplication` / `osascript` / `open -a` 控制进程；重启逻辑对应用户装的 Codex/Claude Code 客户端。

### 🟡 2. 打开外部 URL `platform.rs::open_external_https_url`
- **Windows 现状**：`ShellExecuteW(..., "open", url)`。
- **Mac 第一版**：待实现（用 `open` 命令或 `fd` `NSWorkspace` 等价物，简单，可快速真实实现）。
- **后续路径**：`std::process::Command::new("open").arg(url)` 即可，一行。

### 🟡 3. 系统代理发现 `proxy.rs::resolve_current`
- **Windows 现状**：WinHTTP (`WinHttpGetIEProxyConfigForCurrentUser`) + 注册表读代理 + `WinHttp` 直连探测。
- **Mac 第一版**：no-op（返回「无代理/直连」）。
- **后续路径**：SystemConfiguration framework（`SCDynamicStoreCopyProxies`）读系统代理；直连探测逻辑本身就是跨平台 Rust，可复用 `direct_target_reachable`。
- **影响**：Mac 上「跟随系统代理」失效，但 API 直连、显式配置的 relay 不受影响。

### 🟡 4. 自启动 `autostart.rs::set_enabled/is_registered`
- **Windows 现状**：注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 写 `Codex-Router.exe --background`；清理旧快捷方式/schtasks。
- **Mac 第一版**：no-op（`set_enabled` 直接返回 Ok，`is_registered` 返回 false）。
- **后续路径**：写 `~/Library/LaunchAgents/com.github.hernanjiang.codexrouter.plist` + `launchctl load/bootstrap` 控制。

### 🟡 5. 更新器的 ShellLink（开始菜单快捷方式）`updater.rs`
- **Windows 现状**：`IShellLinkW`+`IPersistFile` 创建 `.lnk` 快捷方式（`#[cfg(windows)]` 已局部隔离）。
- **Mac 第一版**：对应 Mac 分支 no-op（不创建快捷方式）。
- **后续路径**：Mac 用 `.app` bundle + `dmg` 分发，无需 `.lnk`；更新器本身（`check_for_updates`/`download_and_stage_update`）跨平台可复用。

### 🟡 6. 单实例锁
- **Windows 现状**：`acquire_single_instance()`（Windows mutex/命名互斥体）。
- **Mac 第一版**：待实现 —— 用文件锁（`pidfile` + `flock`）或 bundle id 检测。`platform.rs` 里 `acquire_single_instance` 在 `main()` 里 `#[cfg(windows)]` 已门住，Mac 分支当前为空。
- **后续路径**：`fs2`/`flock` 文件锁，或 `NSRunningApplication` 按进程名判断。

### 🟡 7. 进程孤儿清理（Job Object）
- **Windows 现状**：`router_host.rs::assign_kill_on_close_job` 把 CLI 子进程绑到 Job Object，宿主退出时连带杀子进程。
- **Mac 第一版**：no-op（已实现 `#[cfg(not(windows))]` 空实现），依赖 GUI 生命周期的端口清理兜底。
- **后续路径**：Mac 用进程组（`setpgid`/`posix_spawn` flag）或子进程 watchdog。

### ⬜ 8. 托盘后端确认
- **Windows 现状**：`tray-icon` crate 的 Windows 后端。
- **Mac 第一版**：`tray-icon` 本身已支持 macOS（依赖里有 `muda`+`objc2-app-kit`），编译层面已就绪；但**真机托盘图标显示/交互尚未肉眼验证**。
- **后续路径**：GUI 起来后真机验证托盘。

---

## 待真机核对的 UNVERIFIED 外部事实

| 事实 | 状态 | 影响 |
|---|---|---|
| Codex Desktop 是否有 macOS 版 (`ChatGPT.app`/`Codex.app`) | UNVERIFIED | 决定「重启 Codex 桌面」在 Mac 是否有意义 |
| CLIProxyAPI darwin 包是否内置 Gemini CLI 插件 | 已确认**不带**插件 | Gemini OAuth 登录入口 Mac 上暂缺 |
| `security` CLI 在真机读写 Keychain | 已确认可用（`find-generic-password` 存在） | 凭证功能可真实实现 |
| eframe 0.35 在 Mac 真机窗口显示 | 编译通过，未肉眼验证 | GUI 里程碑 |
