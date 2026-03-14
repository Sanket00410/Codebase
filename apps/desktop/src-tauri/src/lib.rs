use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use serde::Serialize;
use tauri::menu::{MenuBuilder, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, State};

const BACKEND_HOST: &str = "127.0.0.1";
const BACKEND_PORT: &str = "8686";
const BACKEND_STARTUP_TIMEOUT_SECS: u64 = 20;
const BACKEND_EXISTING_WAIT_SECS: u64 = 4;

#[derive(Default)]
struct BackendState {
    child: Mutex<Option<Child>>,
}

#[derive(Serialize)]
struct BackendStatus {
    running: bool,
    port: u16,
}

#[derive(Serialize, Clone)]
struct DesktopCommandEvent {
    id: String,
}

#[derive(Serialize)]
struct SourceWindowPayload {
    path: String,
    start_line: usize,
    end_line: usize,
    snippet: String,
    error: Option<String>,
}

#[derive(Serialize)]
struct FilePreviewPayload {
    path: String,
    content: String,
    truncated: bool,
    error: Option<String>,
}

#[tauri::command]
fn start_backend(app: AppHandle, state: State<BackendState>) -> Result<BackendStatus, String> {
    let data_dir = runtime_data_dir(&app)?;
    let pid_path = data_dir.join("backend.pid");

    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                wait_for_backend_ready(Duration::from_secs(BACKEND_STARTUP_TIMEOUT_SECS))?;
                let _ = persist_backend_pid(&pid_path);
                return Ok(BackendStatus {
                    running: true,
                    port: BACKEND_PORT.parse().unwrap_or(8686),
                });
            }
            Ok(Some(_)) => {
                *guard = None;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    if backend_healthy() {
        let _ = persist_backend_pid(&pid_path);
        return Ok(BackendStatus {
            running: true,
            port: BACKEND_PORT.parse().unwrap_or(8686),
        });
    }

    if pid_path.exists() {
        if wait_for_backend_ready(Duration::from_secs(BACKEND_EXISTING_WAIT_SECS)).is_ok() {
            let _ = persist_backend_pid(&pid_path);
            return Ok(BackendStatus {
                running: true,
                port: BACKEND_PORT.parse().unwrap_or(8686),
            });
        }
        let _ = fs::remove_file(&pid_path);
    }

    let (binary, args, cwd) = backend_command(&app)?;
    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("backend.stdout.log"))
        .map_err(|error| format!("Unable to open backend stdout log: {error}"))?;
    let stderr_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("backend.stderr.log"))
        .map_err(|error| format!("Unable to open backend stderr log: {error}"))?;
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(cwd)
        .env("SCANNER_PLATFORM_HOST", BACKEND_HOST)
        .env("SCANNER_PLATFORM_PORT", BACKEND_PORT)
        .env("SCANNER_PLATFORM_DATA_DIR", &data_dir)
        .env("SCANNER_PLATFORM_PID_FILE", pid_path.as_os_str())
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000);

    let _ = fs::remove_file(&pid_path);
    let child = command.spawn().map_err(|error| format!("Unable to launch backend: {error}"))?;
    *guard = Some(child);

    if let Err(error) = wait_for_backend_ready(Duration::from_secs(BACKEND_STARTUP_TIMEOUT_SECS)) {
        if let Some(child) = guard.as_mut() {
            let _ = child.kill();
        }
        *guard = None;
        let _ = fs::remove_file(&pid_path);
        return Err(format!(
            "Backend failed to become ready: {error}. Check {}",
            data_dir.join("backend.stderr.log").display()
        ));
    }
    let _ = persist_backend_pid(&pid_path);

    Ok(BackendStatus {
        running: true,
        port: BACKEND_PORT.parse().unwrap_or(8686),
    })
}

#[tauri::command]
fn stop_backend(app: AppHandle, state: State<BackendState>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    stop_backend_child(&app, &mut guard)
}

#[tauri::command]
fn backend_status(state: State<BackendState>) -> Result<BackendStatus, String> {
    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        if child.try_wait().map_err(|error| error.to_string())?.is_some() {
            *guard = None;
        }
    } else {
        *guard = None;
    }
    let running = backend_healthy();
    Ok(BackendStatus {
        running,
        port: BACKEND_PORT.parse().unwrap_or(8686),
    })
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("explorer");
        command.arg(&path);
        command.creation_flags(0x08000000);
        command.spawn().map_err(|error| error.to_string())?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&path)
            .spawn()
            .map_err(|error| error.to_string())?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(&path)
            .spawn()
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
}

#[tauri::command]
fn read_source_window(
    path: String,
    line: Option<usize>,
    before: Option<usize>,
    after: Option<usize>,
) -> SourceWindowPayload {
    let path_buf = PathBuf::from(&path);
    let resolved_path = path_buf
        .canonicalize()
        .unwrap_or(path_buf.clone())
        .to_string_lossy()
        .to_string();

    let bytes = match fs::read(&path_buf) {
        Ok(contents) => contents,
        Err(error) => {
            return SourceWindowPayload {
                path: resolved_path,
                start_line: 0,
                end_line: 0,
                snippet: String::new(),
                error: Some(format!("Unable to read source file: {error}")),
            };
        }
    };

    let content = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return SourceWindowPayload {
            path: resolved_path,
            start_line: 0,
            end_line: 0,
            snippet: String::new(),
            error: Some("Source file is empty.".to_string()),
        };
    }

    let requested_line = line.unwrap_or(1).max(1).min(lines.len());
    let before_window = before.unwrap_or(8).min(80);
    let after_window = after.unwrap_or(12).min(120);
    let start_line = requested_line.saturating_sub(before_window).max(1);
    let end_line = (requested_line + after_window).min(lines.len());
    let snippet = lines[(start_line - 1)..end_line]
        .iter()
        .enumerate()
        .map(|(index, source_line)| format!("{:>5} | {}", start_line + index, source_line))
        .collect::<Vec<_>>()
        .join("\n");

    SourceWindowPayload {
        path: resolved_path,
        start_line,
        end_line,
        snippet,
        error: None,
    }
}

#[tauri::command]
fn read_text_file_preview(path: String, max_bytes: Option<usize>, max_lines: Option<usize>) -> FilePreviewPayload {
    let path_buf = PathBuf::from(&path);
    let resolved_path = path_buf
        .canonicalize()
        .unwrap_or(path_buf.clone())
        .to_string_lossy()
        .to_string();

    let bytes = match fs::read(&path_buf) {
        Ok(contents) => contents,
        Err(error) => {
            return FilePreviewPayload {
                path: resolved_path,
                content: String::new(),
                truncated: false,
                error: Some(format!("Unable to read artifact preview: {error}")),
            };
        }
    };

    let byte_limit = max_bytes.unwrap_or(96_000).clamp(1_024, 1_000_000);
    let line_limit = max_lines.unwrap_or(240).clamp(20, 2_000);
    let truncated_by_size = bytes.len() > byte_limit;
    let preview_bytes = if truncated_by_size { &bytes[..byte_limit] } else { &bytes[..] };
    let preview_string = String::from_utf8_lossy(preview_bytes).replace('\0', "");
    let mut lines: Vec<&str> = preview_string.lines().collect();
    let truncated_by_lines = lines.len() > line_limit;
    if truncated_by_lines {
        lines.truncate(line_limit);
    }

    let mut content = lines.join("\n");
    let truncated = truncated_by_size || truncated_by_lines;
    if truncated {
        content.push_str("\n\n... preview truncated ...");
    }

    FilePreviewPayload {
        path: resolved_path,
        content,
        truncated,
        error: None,
    }
}

fn configure_native_menu(app: &AppHandle) -> Result<(), String> {
    let file_menu = SubmenuBuilder::new(app, "File")
        .text("menu.open-repository", "Open Repository...")
        .text("menu.file.open-selected-artifact", "Open Active Report")
        .build()
        .map_err(|error| error.to_string())?;
    let scan_menu = SubmenuBuilder::new(app, "Scan")
        .text("menu.start-scan", "Start Scan")
        .text("menu.refresh-runtime", "Refresh Runtime State")
        .build()
        .map_err(|error| error.to_string())?;
    let view_menu = SubmenuBuilder::new(app, "View")
        .text("menu.toggle-tree-dock", "Toggle Session Tree")
        .text("menu.toggle-inspector-dock", "Toggle Inspector")
        .text("menu.toggle-console-dock", "Toggle Event Console")
        .build()
        .map_err(|error| error.to_string())?;
    let reports_menu = SubmenuBuilder::new(app, "Reports")
        .text("menu.switch-reports", "Open Report Explorer")
        .text("menu.reports.open-selected-artifact", "Open Active Report")
        .build()
        .map_err(|error| error.to_string())?;

    let menu = MenuBuilder::new(app)
        .items(&[&file_menu, &scan_menu, &view_menu, &reports_menu])
        .build()
        .map_err(|error| error.to_string())?;
    app.set_menu(menu).map_err(|error| error.to_string())?;
    Ok(())
}

fn runtime_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?
        .join("runtime");
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    Ok(data_dir)
}

fn wait_for_backend_ready(timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if backend_healthy() {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "backend did not respond on http://{BACKEND_HOST}:{BACKEND_PORT}/health within {} seconds",
                timeout.as_secs()
            ));
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn stop_backend_child(app: &AppHandle, guard: &mut Option<Child>) -> Result<(), String> {
    if let Ok(data_dir) = runtime_data_dir(app) {
        let pid_path = data_dir.join("backend.pid");
        if let Some(pid) = read_backend_pid(&pid_path).or_else(backend_listening_pid) {
            let _ = kill_backend_pid(pid);
        }
        let _ = fs::remove_file(pid_path);
    }

    if let Some(mut child) = guard.take() {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                child.kill().map_err(|error| error.to_string())?;
                let _ = child.wait();
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn kill_backend_pid(pid: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("taskkill");
        command
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000);
        let status = command.status().map_err(|error| error.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("taskkill exited with status {status}"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("kill exited with status {status}"));
    }
}

fn persist_backend_pid(pid_path: &PathBuf) -> Result<(), String> {
    if pid_path.exists() {
        return Ok(());
    }
    let Some(pid) = backend_listening_pid() else {
        return Ok(());
    };
    fs::write(pid_path, pid.to_string()).map_err(|error| error.to_string())
}

fn read_backend_pid(pid_path: &PathBuf) -> Option<u32> {
    let contents = fs::read_to_string(pid_path).ok()?;
    contents.trim().parse::<u32>().ok()
}

fn backend_listening_pid() -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.contains("LISTENING") || !trimmed.contains(&format!(":{BACKEND_PORT}")) {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            if let Ok(pid) = parts[4].parse::<u32>() {
                return Some(pid);
            }
        }
        return None;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("lsof")
            .args(["-ti", &format!("tcp:{BACKEND_PORT}"), "-sTCP:LISTEN"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.lines().find_map(|line| line.trim().parse::<u32>().ok());
    }
}

fn backend_command(app: &AppHandle) -> Result<(String, Vec<String>, PathBuf), String> {
    if let Ok(explicit_backend) = std::env::var("SCANNER_PLATFORM_BACKEND") {
        let path = PathBuf::from(explicit_backend);
        let cwd = path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        return Ok((path.to_string_lossy().to_string(), backend_binary_args(), cwd));
    }

    let backend_name = if cfg!(target_os = "windows") {
        "security-platform-backend.exe"
    } else {
        "security-platform-backend"
    };

    let mut candidate_roots: Vec<PathBuf> = Vec::new();
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidate_roots.push(exe_dir.to_path_buf());
        }
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidate_roots.push(resource_dir);
    }
    candidate_roots.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));

    for root in candidate_roots {
        let candidate = root.join("backend").join(backend_name);
        if candidate.exists() {
            let cwd = candidate.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
            return Ok((candidate.to_string_lossy().to_string(), backend_binary_args(), cwd));
        }
    }

    let source_backend = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("services")
        .join("scanner-core");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let venv_python = if cfg!(target_os = "windows") {
        repo_root.join(".venv").join("Scripts").join("python.exe")
    } else {
        repo_root.join(".venv").join("bin").join("python")
    };
    let python_binary = if venv_python.exists() {
        venv_python.to_string_lossy().to_string()
    } else if cfg!(target_os = "windows") {
        "py".to_string()
    } else {
        "python3".to_string()
    };
    let python_args = if !venv_python.exists() && cfg!(target_os = "windows") {
        vec!["-3.12".to_string()]
    } else {
        Vec::new()
    };
    Ok((
        python_binary,
        [
            python_args,
            vec![
            "-m".to_string(),
            "security_platform.cli".to_string(),
            "serve".to_string(),
            "--host".to_string(),
            BACKEND_HOST.to_string(),
            "--port".to_string(),
            BACKEND_PORT.to_string(),
            ],
        ]
        .concat(),
        source_backend,
    ))
}

fn backend_binary_args() -> Vec<String> {
    vec![
        "serve".to_string(),
        "--host".to_string(),
        BACKEND_HOST.to_string(),
        "--port".to_string(),
        BACKEND_PORT.to_string(),
    ]
}

fn backend_healthy() -> bool {
    let Ok(mut stream) = TcpStream::connect((BACKEND_HOST, BACKEND_PORT.parse().unwrap_or(8686))) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
    if stream
        .write_all(
            format!(
                "GET /health HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
                host = BACKEND_HOST,
                port = BACKEND_PORT
            )
            .as_bytes(),
        )
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }
    response.contains("200 OK") && response.contains("\"status\":\"ok\"")
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(BackendState::default())
        .setup(|app| {
            if let Err(error) = configure_native_menu(&app.handle()) {
                eprintln!("failed to configure native menu: {error}");
            }
            Ok(())
        })
        .on_menu_event(|app, event| {
            let id = event.id().as_ref();
            if id.starts_with("menu.") {
                let _ = app.emit(
                    "desktop-command",
                    DesktopCommandEvent {
                        id: id.to_string(),
                    },
                );
            }
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::Destroyed) {
                let state = window.state::<BackendState>();
                let _ = stop_backend(window.app_handle().clone(), state);
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_backend,
            stop_backend,
            backend_status,
            open_path,
            read_source_window,
            read_text_file_preview
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
