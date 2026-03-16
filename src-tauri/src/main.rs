#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct ServerState {
    child: Option<Child>,
    room_code: Option<String>,
    port: u16,
    event_id: String,
    /// Monotonically increasing counter bumped each time a new server
    /// process is spawned.  The stderr reader thread captures the
    /// generation at spawn time and compares it later to detect whether
    /// the process it was monitoring is still the "current" one.
    generation: u64,
}

// ---------------------------------------------------------------------------
// Server binary resolution
// ---------------------------------------------------------------------------

enum ServerBinary {
    /// A compiled native eventbox-server binary
    Native(PathBuf),
    /// Bundled sidecar Deno binary (ships with the app)
    SidecarDeno(PathBuf, PathBuf), // (deno_path, server_ts_path)
    /// System-installed Deno
    SystemDeno(PathBuf), // server_ts_path
}

/// Resolves the best available server binary in priority order:
///
/// 1. Compiled eventbox-server binary next to app executable
/// 2. Compiled eventbox-server binary in Tauri resources
/// 3. Bundled sidecar Deno + resources/server.ts
/// 4. System Deno (`deno` on PATH) + resources/server.ts
fn resolve_server_binary(app: &tauri::AppHandle) -> Result<ServerBinary, String> {
    let bin_name = if cfg!(target_os = "windows") {
        "eventbox-server.exe"
    } else {
        "eventbox-server"
    };

    // 1. Compiled binary next to app executable
    if let Ok(exe_dir) = std::env::current_exe().map(|p| p.parent().unwrap_or(&p).to_path_buf()) {
        let candidate = exe_dir.join(bin_name);
        if candidate.exists() {
            ensure_executable(&candidate);
            return Ok(ServerBinary::Native(candidate));
        }
    }

    // 2. Compiled binary in Tauri resources
    //    tauri.conf.json bundles "resources/eventbox-server*", which preserves
    //    the resources/ prefix. Try the prefixed path first, then the bare name
    //    for dev builds or alternative bundle layouts.
    for resource_path in [format!("resources/{}", bin_name), bin_name.to_string()] {
        if let Some(candidate) = app.path_resolver().resolve_resource(&resource_path) {
            if candidate.exists() {
                ensure_executable(&candidate);
                return Ok(ServerBinary::Native(candidate));
            }
        }
    }

    // Resolve server.ts once for Deno-based paths
    let server_ts = app
        .path_resolver()
        .resolve_resource("resources/server.ts")
        .filter(|p| p.exists());

    // 3. Bundled sidecar Deno
    let sidecar_deno = resolve_sidecar_deno_path(app);
    if let (Some(deno_path), Some(ts_path)) = (&sidecar_deno, &server_ts) {
        ensure_executable(deno_path);
        return Ok(ServerBinary::SidecarDeno(deno_path.clone(), ts_path.clone()));
    }

    // 4. System Deno on PATH
    if let Some(ts_path) = &server_ts {
        if which_deno().is_some() {
            return Ok(ServerBinary::SystemDeno(ts_path.clone()));
        }
    }

    Err(
        "Could not find eventbox-server binary or Deno runtime.\n\
         The bundled Deno sidecar may be missing. Reinstall EventBox or \
         install Deno manually: https://deno.land/#installation"
            .into(),
    )
}

/// Find the sidecar Deno binary that Tauri bundles via `externalBin`.
/// Tauri renames sidecars to `{name}-{target_triple}[.exe]` at build time.
fn resolve_sidecar_deno_path(_app: &tauri::AppHandle) -> Option<PathBuf> {
    // The sidecar lives next to the app executable after bundling
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))?;

    let target_triple = tauri_target_triple();

    let candidates = if cfg!(target_os = "windows") {
        vec![
            exe_dir.join(format!("deno-{}.exe", target_triple)),
            exe_dir.join("deno.exe"),
        ]
    } else {
        vec![
            exe_dir.join(format!("deno-{}", target_triple)),
            exe_dir.join("deno"),
        ]
    };

    candidates.into_iter().find(|p| p.exists())
}

/// Ensure a binary has the executable permission on Unix.
/// Tauri bundles resources as data files; the execute bit may be stripped
/// during packaging (especially on .deb and AppImage targets).
#[cfg(unix)]
fn ensure_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        let mode = perms.mode();
        if mode & 0o111 == 0 {
            perms.set_mode(mode | 0o755);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

#[cfg(not(unix))]
fn ensure_executable(_path: &std::path::Path) {}

/// Check if `deno` is available on the system PATH.
fn which_deno() -> Option<PathBuf> {
    let name = if cfg!(target_os = "windows") { "deno.exe" } else { "deno" };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.exists())
    })
}

/// Return the Rust target triple at compile time for sidecar name matching.
fn tauri_target_triple() -> &'static str {
    option_env!("TAURI_TARGET_TRIPLE").unwrap_or("unknown-unknown-unknown")
}

// ---------------------------------------------------------------------------
// Deno check (IPC command)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DenoStatus {
    available: bool,
    source: String,       // "sidecar", "system", "none"
    version: String,      // e.g. "deno 1.42.0" or ""
    install_url: String,
}

fn get_deno_version(deno_path: &std::path::Path) -> String {
    Command::new(deno_path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_default()
}

#[tauri::command]
fn check_deno(app_handle: tauri::AppHandle) -> DenoStatus {
    let install_url = "https://deno.land/#installation".to_string();

    // Check sidecar first
    if let Some(sidecar) = resolve_sidecar_deno_path(&app_handle) {
        ensure_executable(&sidecar);
        let version = get_deno_version(&sidecar);
        if !version.is_empty() {
            return DenoStatus {
                available: true,
                source: "sidecar".into(),
                version,
                install_url,
            };
        }
    }

    // Check system Deno
    if let Some(system_deno) = which_deno() {
        let version = get_deno_version(&system_deno);
        if !version.is_empty() {
            return DenoStatus {
                available: true,
                source: "system".into(),
                version,
                install_url,
            };
        }
    }

    DenoStatus {
        available: false,
        source: "none".into(),
        version: String::new(),
        install_url,
    }
}

// ---------------------------------------------------------------------------
// System tray
// ---------------------------------------------------------------------------

fn build_tray() -> SystemTray {
    let menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("status", "EventBox — Stopped").disabled())
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("start", "Start Server"))
        .add_item(CustomMenuItem::new("stop", "Stop Server").disabled())
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "Quit"));

    SystemTray::new().with_menu(menu)
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

fn start_server(state: &Mutex<ServerState>, app: &tauri::AppHandle) -> Result<(), String> {
    let mut s = state.lock().unwrap();
    if s.child.is_some() {
        return Ok(()); // already running
    }

    let port = s.port;
    let event_id = s.event_id.clone();

    let server_binary = resolve_server_binary(app)?;

    let deno_args = |ts_path: &std::path::Path| -> Vec<String> {
        vec![
            "run".into(),
            "--allow-net".into(),
            "--allow-read".into(),
            "--allow-write".into(),
            "--allow-env".into(),
            "--allow-ffi".into(),
            "--unstable-ffi".into(),
            ts_path.to_string_lossy().into(),
        ]
    };

    let (mut cmd, binary_label) = match &server_binary {
        ServerBinary::Native(path) => {
            let mut c = Command::new(path);
            c.env("EVENTBOX_PORT", port.to_string())
                .env("EVENTBOX_EVENT_ID", &event_id)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (c, "bundled server")
        }
        ServerBinary::SidecarDeno(deno_path, ts_path) => {
            let mut c = Command::new(deno_path);
            c.args(deno_args(ts_path))
                .env("EVENTBOX_PORT", port.to_string())
                .env("EVENTBOX_EVENT_ID", &event_id)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (c, "bundled Deno")
        }
        ServerBinary::SystemDeno(ts_path) => {
            let mut c = Command::new("deno");
            c.args(deno_args(ts_path))
                .env("EVENTBOX_PORT", port.to_string())
                .env("EVENTBOX_EVENT_ID", &event_id)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (c, "system Deno")
        }
    };

    match cmd.spawn() {
        Ok(mut child) => {
            // Read stdout in background to capture room code
            if let Some(stdout) = child.stdout.take() {
                let app_handle = app.clone();
                std::thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().map_while(Result::ok) {
                        println!("[EventBox] {}", line);
                        if line.contains("Room code:") {
                            if let Some(code) = line.split("Room code:").nth(1) {
                                let code = code.trim().to_string();
                                {
                                    let state_ref = app_handle.state::<Mutex<ServerState>>();
                                    let mut s = state_ref.lock().unwrap();
                                    s.room_code = Some(code.clone());
                                }
                                let _ = app_handle.emit_all(
                                    "server-status",
                                    serde_json::json!({
                                        "running": true,
                                        "room_code": code,
                                    }),
                                );
                            }
                        }
                    }
                });
            }

            // Read stderr for error reporting.
            // Bump the generation counter and capture it so the
            // thread can later tell whether this specific process
            // instance is still the "current" one (guards against
            // restart races where stop→start stores a new child
            // before the old stderr thread runs its check).
            s.generation += 1;
            let spawn_generation = s.generation;
            if let Some(stderr) = child.stderr.take() {
                let app_handle2 = app.clone();
                std::thread::spawn(move || {
                    let reader = BufReader::new(stderr);
                    let mut error_buf = String::new();
                    for line in reader.lines().map_while(Result::ok) {
                        eprintln!("[EventBox stderr] {}", line);
                        error_buf.push_str(&line);
                        error_buf.push('\n');
                    }
                    // Decide whether this exit was intentional / stale:
                    //  - stop_server() calls child.take() → child is None.
                    //  - A restart bumps the generation counter, so
                    //    spawn_generation != current generation.
                    // In either case we should NOT emit an error.
                    let suppress = {
                        let state_ref = app_handle2.state::<Mutex<ServerState>>();
                        let s = state_ref.lock().unwrap();
                        s.child.is_none() || s.generation != spawn_generation
                    };

                    if !suppress {
                        // Unexpected exit — always emit an error so the
                        // frontend is never left in a "Starting..." limbo.
                        let error_msg = if error_buf.trim().is_empty() {
                            "Server process exited unexpectedly with no output.\n\
                             The bundled server binary may be missing or incompatible with your system."
                                .to_string()
                        } else {
                            error_buf.trim().to_string()
                        };
                        let _ = app_handle2.emit_all(
                            "server-status",
                            serde_json::json!({
                                "running": false,
                                "error": error_msg,
                            }),
                        );
                    }
                });
            }

            s.child = Some(child);
            update_tray(app, true);

            let _ = app.emit_all(
                "server-status",
                serde_json::json!({
                    "running": true,
                    "port": port,
                    "event_id": event_id,
                }),
            );

            Ok(())
        }
        Err(e) => {
            let error_msg = format!(
                "Failed to start {} server: {}\n\n\
                 If this persists, reinstall EventBox or install Deno manually:\n\
                 https://deno.land/#installation",
                binary_label, e
            );
            eprintln!("Failed to start server: {}", e);
            let _ = app.emit_all(
                "server-status",
                serde_json::json!({
                    "running": false,
                    "error": &error_msg,
                }),
            );
            Err(error_msg)
        }
    }
}

fn stop_server(state: &Mutex<ServerState>, app: &tauri::AppHandle) {
    let mut s = state.lock().unwrap();
    if let Some(mut child) = s.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    s.room_code = None;
    update_tray(app, false);
    let _ = app.emit_all("server-status", serde_json::json!({ "running": false }));
}

fn update_tray(app: &tauri::AppHandle, running: bool) {
    if let Some(tray) = app.tray_handle().try_get_item("status") {
        let _ = tray.set_title(if running {
            "EventBox — Running"
        } else {
            "EventBox — Stopped"
        });
    }
    if let Some(item) = app.tray_handle().try_get_item("start") {
        let _ = item.set_enabled(!running);
    }
    if let Some(item) = app.tray_handle().try_get_item("stop") {
        let _ = item.set_enabled(running);
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(ip) = local_ip_address::local_ip() {
        ips.push(ip.to_string());
    }
    if let Ok(networks) = local_ip_address::list_afinet_netifas() {
        for (_, ip) in networks {
            let s = ip.to_string();
            if !s.starts_with("127.") && !s.contains("::1") && !ips.contains(&s) {
                ips.push(s);
            }
        }
    }
    ips
}

// ---------------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn set_event_id_and_start(
    state: tauri::State<'_, Mutex<ServerState>>,
    app_handle: tauri::AppHandle,
    event_id: String,
    port: Option<u16>,
) -> Result<(), String> {
    if event_id.trim().is_empty() {
        return Err("Event ID cannot be empty".into());
    }
    stop_server(&state, &app_handle);
    {
        let mut s = state.lock().unwrap();
        s.event_id = event_id.trim().to_string();
        if let Some(p) = port {
            s.port = p;
        }
    }
    start_server(&state, &app_handle)?;
    Ok(())
}

#[tauri::command]
fn stop_server_cmd(
    state: tauri::State<'_, Mutex<ServerState>>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    stop_server(&state, &app_handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut event_id = std::env::var("EVENTBOX_EVENT_ID").unwrap_or_default();
    let mut port: u16 = std::env::var("EVENTBOX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--event-id" if i + 1 < args.len() => {
                event_id = args[i + 1].clone();
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(8787);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let server_state = Mutex::new(ServerState {
        child: None,
        room_code: None,
        port,
        event_id: event_id.clone(),
        generation: 0,
    });

    tauri::Builder::default()
        .manage(server_state)
        .invoke_handler(tauri::generate_handler![
            set_event_id_and_start,
            stop_server_cmd,
            check_deno
        ])
        .system_tray(build_tray())
        .on_system_tray_event(|app, event| {
            if let SystemTrayEvent::MenuItemClick { id, .. } = event {
                let state = app.state::<Mutex<ServerState>>();
                match id.as_str() {
                    "start" => {
                        let _ = start_server(&state, app);
                    }
                    "stop" => stop_server(&state, app),
                    "quit" => {
                        stop_server(&state, app);
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        })
        .setup(|app| {
            let state = app.state::<Mutex<ServerState>>();
            let handle = app.handle();
            let ips = get_local_ips();
            let _ = handle.emit_all("local-ips", serde_json::json!({ "ips": ips }));
            {
                let s = state.lock().unwrap();
                if !s.event_id.is_empty() {
                    drop(s);
                    let _ = start_server(&state, &handle);
                }
            }
            Ok(())
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                event.window().hide().unwrap();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("Error running EventBox");
}
