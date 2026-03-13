use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

const BACKEND_HOST: &str = "127.0.0.1";
const BACKEND_PORT: &str = "8686";

#[derive(Default)]
struct BackendState {
    child: Mutex<Option<Child>>,
}

#[derive(Serialize)]
struct BackendStatus {
    running: bool,
    port: u16,
}

#[tauri::command]
fn start_backend(app: AppHandle, state: State<BackendState>) -> Result<BackendStatus, String> {
    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                return Ok(BackendStatus {
                    running: true,
                    port: BACKEND_PORT.parse().unwrap_or(8686),
                })
            }
            Ok(Some(_)) => {
                *guard = None;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    if backend_healthy() {
        return Ok(BackendStatus {
            running: true,
            port: BACKEND_PORT.parse().unwrap_or(8686),
        });
    }

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?
        .join("runtime");
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;

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
        .env("SCANNER_PLATFORM_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000);

    let child = command.spawn().map_err(|error| format!("Unable to launch backend: {error}"))?;
    *guard = Some(child);

    Ok(BackendStatus {
        running: true,
        port: BACKEND_PORT.parse().unwrap_or(8686),
    })
}

#[tauri::command]
fn stop_backend(state: State<BackendState>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    if let Some(mut child) = guard.take() {
        child.kill().map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn backend_status(state: State<BackendState>) -> Result<BackendStatus, String> {
    let mut guard = state.child.lock().map_err(|_| "Backend state lock poisoned".to_string())?;
    let running = if let Some(child) = guard.as_mut() {
        child.try_wait().map_err(|error| error.to_string())?.is_none()
    } else {
        false
    };
    if !running {
        *guard = None;
    }
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
        .invoke_handler(tauri::generate_handler![start_backend, stop_backend, backend_status, open_path])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
