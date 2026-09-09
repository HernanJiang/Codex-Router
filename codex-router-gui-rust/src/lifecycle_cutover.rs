//! Journaled shadow cutover orchestration for a legacy Router stack.

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandSpec {
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSpec {
    pub source: PathBuf,
    pub backup_name: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CutoverManifest {
    #[serde(default)]
    pub snapshots: Vec<SnapshotSpec>,
    pub shadow_start: CommandSpec,
    pub shadow_health: CommandSpec,
    pub pre_cutover_smoke: CommandSpec,
    pub old_stop: CommandSpec,
    pub new_start: CommandSpec,
    pub post_cutover_smoke: CommandSpec,
    pub new_stop: CommandSpec,
    pub old_start: CommandSpec,
    pub rollback_health: CommandSpec,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverStage {
    SnapshotComplete,
    ShadowReady,
    PreCutoverSmokePassed,
    CutoverBegin,
    PostCutoverSmokePassed,
    RollbackBegin,
    RollbackHealthy,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CutoverJournal {
    pub stage: CutoverStage,
    pub updated_at: String,
    pub attempts: u32,
    #[serde(default)]
    pub failure_code: Option<String>,
}

fn migration_root(router_root: &Path) -> PathBuf {
    router_root.join("data").join("migration")
}

fn journal_path(router_root: &Path) -> PathBuf {
    migration_root(router_root).join("cutover-journal.json")
}

fn snapshot_root(router_root: &Path) -> PathBuf {
    migration_root(router_root).join("cutover-snapshot")
}

fn save_journal(router_root: &Path, journal: &CutoverJournal) -> anyhow::Result<()> {
    crate::config::atomic_write(
        &journal_path(router_root),
        serde_json::to_vec_pretty(journal)?.as_slice(),
    )
}

fn load_journal(router_root: &Path) -> anyhow::Result<Option<CutoverJournal>> {
    let path = journal_path(router_root);
    match std::fs::read(path) {
        Ok(content) => Ok(Some(serde_json::from_slice(&content)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn set_stage(
    router_root: &Path,
    journal: &mut CutoverJournal,
    stage: CutoverStage,
    failure_code: Option<&str>,
) -> anyhow::Result<()> {
    journal.stage = stage;
    journal.updated_at = chrono::Utc::now().to_rfc3339();
    journal.failure_code = failure_code.map(str::to_owned);
    save_journal(router_root, journal)
}

fn safe_backup_name(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn copy_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    if source.is_dir() {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

fn create_snapshot(router_root: &Path, manifest: &CutoverManifest) -> anyhow::Result<()> {
    let root = snapshot_root(router_root);
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    for snapshot in &manifest.snapshots {
        if !safe_backup_name(&snapshot.backup_name) {
            bail!("CR-MIG-0002: snapshot backup name must be a relative safe path");
        }
        if !snapshot.source.exists() {
            bail!("CR-MIG-0002: snapshot source does not exist");
        }
        copy_tree(&snapshot.source, &root.join(&snapshot.backup_name))?;
    }
    Ok(())
}

fn restore_snapshot(router_root: &Path, manifest: &CutoverManifest) -> anyhow::Result<()> {
    let root = snapshot_root(router_root);
    for snapshot in &manifest.snapshots {
        let backup = root.join(&snapshot.backup_name);
        if !backup.exists() {
            bail!("CR-MIG-0008: cutover snapshot is incomplete");
        }
        if snapshot.source.is_dir() {
            std::fs::remove_dir_all(&snapshot.source)?;
        } else if snapshot.source.exists() {
            std::fs::remove_file(&snapshot.source)?;
        }
        copy_tree(&backup, &snapshot.source)?;
    }
    Ok(())
}

fn run_command(name: &str, spec: &CommandSpec) -> anyhow::Result<()> {
    if !spec.executable.is_file() {
        bail!("{name} executable is missing");
    }
    let mut command = Command::new(&spec.executable);
    command.args(&spec.args);
    if let Some(directory) = &spec.working_directory {
        command.current_dir(directory);
    }
    let status = command.status().with_context(|| format!("run {name}"))?;
    if !status.success() {
        bail!("{name} failed with exit code {:?}", status.code());
    }
    Ok(())
}

fn rollback(
    router_root: &Path,
    manifest: &CutoverManifest,
    journal: &mut CutoverJournal,
    failure_code: &str,
) -> anyhow::Result<()> {
    set_stage(
        router_root,
        journal,
        CutoverStage::RollbackBegin,
        Some(failure_code),
    )?;
    run_command("new_stop", &manifest.new_stop).context("CR-MIG-0007")?;
    restore_snapshot(router_root, manifest).context("CR-MIG-0008")?;
    run_command("old_start", &manifest.old_start).context("CR-MIG-0008")?;
    run_command("rollback_health", &manifest.rollback_health).context("CR-MIG-0008")?;
    set_stage(
        router_root,
        journal,
        CutoverStage::RollbackHealthy,
        Some(failure_code),
    )
}

fn requires_recovery(stage: CutoverStage) -> bool {
    matches!(
        stage,
        CutoverStage::SnapshotComplete
            | CutoverStage::ShadowReady
            | CutoverStage::PreCutoverSmokePassed
            | CutoverStage::CutoverBegin
            | CutoverStage::PostCutoverSmokePassed
            | CutoverStage::RollbackBegin
    )
}

pub fn run_shadow_cutover(
    router_root: &Path,
    manifest_path: &Path,
) -> anyhow::Result<CutoverJournal> {
    let manifest: CutoverManifest = serde_json::from_slice(
        &std::fs::read(manifest_path).context("CR-MIG-0002: read cutover manifest")?,
    )
    .context("CR-MIG-0002: parse cutover manifest")?;
    let existing_journal = load_journal(router_root)?;
    let must_recover = existing_journal
        .as_ref()
        .is_some_and(|journal| requires_recovery(journal.stage));
    let mut journal = existing_journal.unwrap_or(CutoverJournal {
        stage: CutoverStage::SnapshotComplete,
        updated_at: chrono::Utc::now().to_rfc3339(),
        attempts: 0,
        failure_code: None,
    });
    if journal.stage == CutoverStage::Committed {
        return Ok(journal);
    }
    if must_recover {
        rollback(router_root, &manifest, &mut journal, "CR-MIG-0007")?;
    }

    journal.attempts = journal.attempts.saturating_add(1);
    create_snapshot(router_root, &manifest).context("CR-MIG-0002: create cutover snapshot")?;
    set_stage(
        router_root,
        &mut journal,
        CutoverStage::SnapshotComplete,
        None,
    )?;
    if run_command("shadow_start", &manifest.shadow_start).is_err()
        || run_command("shadow_health", &manifest.shadow_health).is_err()
    {
        rollback(router_root, &manifest, &mut journal, "CR-MIG-0006")?;
        bail!("CR-MIG-0006: shadow stack failed readiness checks");
    }
    set_stage(router_root, &mut journal, CutoverStage::ShadowReady, None)?;
    if run_command("pre_cutover_smoke", &manifest.pre_cutover_smoke).is_err() {
        rollback(router_root, &manifest, &mut journal, "CR-MIG-0006")?;
        bail!("CR-MIG-0006: pre-cutover smoke failed");
    }
    set_stage(
        router_root,
        &mut journal,
        CutoverStage::PreCutoverSmokePassed,
        None,
    )?;
    set_stage(
        router_root,
        &mut journal,
        CutoverStage::CutoverBegin,
        None,
    )?;
    if run_command("old_stop", &manifest.old_stop).is_err()
        || run_command("new_start", &manifest.new_start).is_err()
        || run_command("post_cutover_smoke", &manifest.post_cutover_smoke).is_err()
    {
        rollback(router_root, &manifest, &mut journal, "CR-MIG-0007")?;
        bail!("CR-MIG-0007: post-cutover smoke failed and the old stack was restored");
    }
    set_stage(
        router_root,
        &mut journal,
        CutoverStage::PostCutoverSmokePassed,
        None,
    )?;
    set_stage(router_root, &mut journal, CutoverStage::Committed, None)?;
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(script: &Path, marker: &Path, action: &str) -> CommandSpec {
        CommandSpec {
            executable: PathBuf::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            args: vec![
                "-NoProfile".to_owned(),
                "-File".to_owned(),
                script.display().to_string(),
                marker.display().to_string(),
                action.to_owned(),
            ],
            working_directory: None,
        }
    }

    fn fixture(fail_action: &str) -> (PathBuf, CutoverManifest, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("router-cutover-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let script = root.join("step.ps1");
        std::fs::write(
            &script,
            format!(
                "param($Marker,$Action)\nAdd-Content -LiteralPath $Marker -Value $Action\nif ($Action -eq '{}') {{ exit 9 }}\n",
                fail_action
            ),
        )
        .unwrap();
        let marker = root.join("steps.txt");
        let state = root.join("legacy-state.txt");
        std::fs::write(&state, "legacy").unwrap();
        let command = |action| command(&script, &marker, action);
        let manifest = CutoverManifest {
            snapshots: vec![SnapshotSpec {
                source: state.clone(),
                backup_name: PathBuf::from("legacy-state.txt"),
            }],
            shadow_start: command("shadow_start"),
            shadow_health: command("shadow_health"),
            pre_cutover_smoke: command("pre_smoke"),
            old_stop: command("old_stop"),
            new_start: command("new_start"),
            post_cutover_smoke: command("post_smoke"),
            new_stop: command("new_stop"),
            old_start: command("old_start"),
            rollback_health: command("rollback_health"),
        };
        (root, manifest, marker, state)
    }

    fn save_manifest(root: &Path, manifest: &CutoverManifest) -> PathBuf {
        let path = root.join("manifest.json");
        // Tests serialize through Value because production manifests are only input.
        let value = serde_json::json!({
            "snapshots":manifest.snapshots.iter().map(|item| serde_json::json!({
                "source":item.source,"backupName":item.backup_name
            })).collect::<Vec<_>>(),
            "shadowStart":spec_value(&manifest.shadow_start),
            "shadowHealth":spec_value(&manifest.shadow_health),
            "preCutoverSmoke":spec_value(&manifest.pre_cutover_smoke),
            "oldStop":spec_value(&manifest.old_stop),
            "newStart":spec_value(&manifest.new_start),
            "postCutoverSmoke":spec_value(&manifest.post_cutover_smoke),
            "newStop":spec_value(&manifest.new_stop),
            "oldStart":spec_value(&manifest.old_start),
            "rollbackHealth":spec_value(&manifest.rollback_health),
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        path
    }

    fn spec_value(spec: &CommandSpec) -> Value {
        serde_json::json!({"executable":spec.executable,"args":spec.args})
    }

    use serde_json::Value;

    #[cfg(windows)]
    #[test]
    fn successful_cutover_commits_and_is_idempotent() {
        let (root, manifest, marker, _) = fixture("never");
        let path = save_manifest(&root, &manifest);
        let first = run_shadow_cutover(&root, &path).unwrap();
        assert_eq!(first.stage, CutoverStage::Committed);
        let before = std::fs::read_to_string(&marker).unwrap();
        let second = run_shadow_cutover(&root, &path).unwrap();
        assert_eq!(second.stage, CutoverStage::Committed);
        assert_eq!(std::fs::read_to_string(marker).unwrap(), before);
    }

    #[cfg(windows)]
    #[test]
    fn post_cutover_failure_restores_snapshot_and_old_health() {
        let (root, manifest, marker, state) = fixture("post_smoke");
        let path = save_manifest(&root, &manifest);
        std::fs::write(&state, "legacy").unwrap();
        let error = run_shadow_cutover(&root, &path).unwrap_err().to_string();
        assert!(error.contains("CR-MIG-0007"));
        assert_eq!(std::fs::read_to_string(state).unwrap(), "legacy");
        let steps = std::fs::read_to_string(marker).unwrap();
        assert!(steps.contains("new_stop"));
        assert!(steps.contains("old_start"));
        assert!(steps.contains("rollback_health"));
        assert_eq!(load_journal(&root).unwrap().unwrap().stage, CutoverStage::RollbackHealthy);
    }

    #[cfg(windows)]
    #[test]
    fn interrupted_dangerous_stage_rolls_back_before_retry() {
        let (root, manifest, marker, _) = fixture("pre_smoke");
        let path = save_manifest(&root, &manifest);
        create_snapshot(&root, &manifest).unwrap();
        save_journal(
            &root,
            &CutoverJournal {
                stage: CutoverStage::ShadowReady,
                updated_at: chrono::Utc::now().to_rfc3339(),
                attempts: 1,
                failure_code: None,
            },
        )
        .unwrap();
        let _ = run_shadow_cutover(&root, &path);
        let steps = std::fs::read_to_string(marker).unwrap();
        let rollback = steps.find("rollback_health").unwrap();
        let shadow = steps.find("shadow_start").unwrap();
        assert!(rollback < shadow);
    }
}
