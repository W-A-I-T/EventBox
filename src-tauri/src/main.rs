#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem,
};

struct ServerState {
    child: Option<Child>,
    room_code: Option<String>,
    port: u16,
    event_id: String,
}

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

fn start_server(state: &Arc<Mutex<ServerState>>, app: &tauri::AppHandle) {
    let mut s = state.lock().unwrap();
    if s.child.is_some() {
        return; // already running
    }

    // Resolve bundled server.ts
    let resource_path = app
        .path_resolver()
        .resolve_resource("resources/server.ts")
        .expect("Failed to resolve server.ts resource");

    let port = s.port;
    let event_id = s.event_id.clone();

    let mut cmd = Command::new("deno");
    cmd.args([
        "run",
        "--allow-net",
        "--allow-read",
        "--allow-write",
        "--allow-env",
        "--allow-ffi",
        "--unstable-ffi",
        resource_path.to_str().unwrap(),
    ])
    .env("EVENTBOX_PORT", port.to_string())
    .env("EVENTBOX_EVENT_ID", &event_id)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            // Read stdout in background to capture room code
            if let Some(stdout) = child.stdout.take() {
                let app_handle = app.clone();
                let state_clone = Arc::clone(state);
                std::thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().map_while(Result::ok) {
                        println!("[EventBox] {}", line);
                        // Parse room code from output
                        if line.contains("Room code:") {
                            if let Some(code) = line.split("Room code:").nth(1) {
                                let code = code.trim().to_string();
                                {
                                    let mut s = state_clone.lock().unwrap();
                                    s.room_code = Some(code.clone());
                                }
                                // Notify frontend
                                let _ = app_handle.emit_all("server-status", serde_json::json!({
                                    "running": true,
                                    "room_code": code,
                                }));
                            }
                        }
                    }
                });
            }

            s.child = Some(child);

            // Update tray
            if let Some(tray) = app.tray_handle().try_get_item("status") {
                let _ = tray.set_title("EventBox — Running");
            }
            if let Some(item) = app.tray_handle().try_get_item("start") {
                let _ = item.set_enabled(false);
            }
            if let Some(item) = app.tray_handle().try_get_item("stop") {
                let _ = item.set_enabled(true);
            }

            let _ = app.emit_all("server-status", serde_json::json!({
                "running": true,
                "port": port,
                "event_id": event_id,
            }));
        }
        Err(e) => {
            eprintln!("Failed to start Deno server: {}", e);
            let _ = app.emit_all("server-status", serde_json::json!({
                "running": false,
                "error": format!("Failed to start: {}. Is Deno installed?", e),
            }));
        }
    }
}

fn stop_server(state: &Arc<Mutex<ServerState>>, app: &tauri::AppHandle) {
    let mut s = state.lock().unwrap();
    if let Some(mut child) = s.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    s.room_code = None;

    if let Some(tray) = app.tray_handle().try_get_item("status") {
        let _ = tray.set_title("EventBox — Stopped");
    }
    if let Some(item) = app.tray_handle().try_get_item("start") {
        let _ = item.set_enabled(true);
    }
    if let Some(item) = app.tray_handle().try_get_item("stop") {
        let _ = item.set_enabled(false);
    }

    let _ = app.emit_all("server-status", serde_json::json!({
        "running": false,
    }));
}

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

fn main() {
    // Parse CLI args for event-id
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

    let server_state = Arc::new(Mutex::new(ServerState {
        child: None,
        room_code: None,
        port,
        event_id: event_id.clone(),
    }));

    let state_for_tray = Arc::clone(&server_state);
    let state_for_setup = Arc::clone(&server_state);

    tauri::Builder::default()
        .manage(server_state)
        .system_tray(build_tray())
        .on_system_tray_event(move |app, event| {
            if let SystemTrayEvent::MenuItemClick { id, .. } = event {
                match id.as_str() {
                    "start" => start_server(&state_for_tray, app),
                    "stop" => stop_server(&state_for_tray, app),
                    "quit" => {
                        stop_server(&state_for_tray, app);
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
        })
        .setup(move |app| {
            let handle = app.handle();

            // Emit local IPs to frontend
            let ips = get_local_ips();
            let _ = handle.emit_all("local-ips", serde_json::json!({ "ips": ips }));

            // Auto-start if event_id is configured
            {
                let s = state_for_setup.lock().unwrap();
                if !s.event_id.is_empty() {
                    drop(s);
                    start_server(&state_for_setup, &handle);
                }
            }

            Ok(())
        })
        .on_window_event(|event| {
            // Keep running in tray when window closes
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                event.window().hide().unwrap();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("Error running EventBox");
}
