// SPDX-License-Identifier: GPL-3.0-only

//! Launch native COSMIC input methods configured in cosmic-comp's keyboard map.
//!
//! Each IME is spawned through `wp_security_context` so cosmic-comp can
//! identify it by `app_id` and grant access to input-method v3 globals.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, AsRawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use color_eyre::eyre::{ContextCompat, Result, WrapErr};
use cosmic_comp_config::CosmicCompConfig;
use cosmic_config::CosmicConfigEntry;
use rand::distr::{Alphanumeric, SampleString};
use rustix::pipe::pipe;
use tokio_util::sync::CancellationToken;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Proxy, QueueHandle, delegate_dispatch};
use wayland_protocols::wp::security_context::v1::client::wp_security_context_manager_v1::WpSecurityContextManagerV1;
use wayland_protocols::wp::security_context::v1::client::wp_security_context_v1::WpSecurityContextV1;

use crate::process::mark_as_not_cloexec;

struct AppState {
	security_manager: WpSecurityContextManagerV1,
	contexts: Vec<WpSecurityContextV1>,
	children: HashMap<String, ImeChild>,
}

struct ImeChild {
	command: String,
	child: Child,
}

#[derive(Debug)]
struct SecurityContextData {
	conn: Arc<Mutex<Option<UnixStream>>>,
}

impl Drop for SecurityContextData {
	fn drop(&mut self) {
		if let Some(stream) = self.conn.lock().unwrap().take() {
			let _ = stream.shutdown(std::net::Shutdown::Both);
		}
	}
}

fn wayland_display_from_env(env_vars: &[(String, String)]) -> Option<String> {
	env_vars
		.iter()
		.find(|(key, _)| key == "WAYLAND_DISPLAY")
		.map(|(_, value)| value.clone())
}

fn create_security_listener(
	manager: &WpSecurityContextManagerV1,
	qh: &QueueHandle<AppState>,
) -> Result<WpSecurityContextV1> {
	let (close_fd_ours, close_fd) = pipe().wrap_err("pipe for security context close fd")?;
	let name: String = Alphanumeric.sample_string(&mut rand::rng(), 50);
	let addr = SocketAddr::from_abstract_name(name.as_bytes())
		.wrap_err("abstract socket name for security context")?;
	let listener = UnixListener::bind_addr(&addr).wrap_err("bind security context listener")?;
	let context = manager.create_listener(
		listener.as_fd(),
		close_fd.as_fd(),
		qh,
		SecurityContextData {
			conn: Arc::new(Mutex::new(None)),
		},
	);
	let conn = UnixStream::connect_addr(&addr).wrap_err("connect security context socket")?;
	drop(close_fd_ours);

	let data = context.data::<SecurityContextData>().unwrap();
	*data.conn.lock().unwrap() = Some(conn);

	Ok(context)
}

fn spawn_ime(command: &str, wayland_socket: UnixStream) -> Result<Child> {
	let socket_fd = wayland_socket.as_raw_fd();
	mark_as_not_cloexec(&wayland_socket)?;

	let log_path = format!(
		"/tmp/ime-{}.log",
		std::path::Path::new(command)
			.file_name()
			.and_then(|n| n.to_str())
			.unwrap_or("unknown")
	);
	let log_file = std::fs::File::create(&log_path).ok();

	let mut cmd = Command::new(command);
	cmd.env("WAYLAND_SOCKET", socket_fd.to_string())
		.env_remove("WAYLAND_DISPLAY")
		.stdin(Stdio::null());

	if let Some(f) = log_file {
		let f2 = f.try_clone().wrap_err("clone IME log fd")?;
		cmd.stdout(Stdio::from(f));
		cmd.stderr(Stdio::from(f2));
	} else {
		cmd.stdout(Stdio::null()).stderr(Stdio::null());
	}

	// SAFETY: pre_exec runs in the child between fork and exec.
	unsafe {
		cmd.pre_exec(move || {
			let flags = libc::fcntl(socket_fd, libc::F_GETFD);
			if flags != -1 {
				libc::fcntl(socket_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
			}
			Ok(())
		});
	}

	let child = cmd
		.spawn()
		.wrap_err_with(|| format!("spawn IME {}", command))?;
	drop(wayland_socket);
	Ok(child)
}

fn launch_ime(
	state: &mut AppState,
	qh: &QueueHandle<AppState>,
	event_queue: &mut wayland_client::EventQueue<AppState>,
	app_id: &str,
	command: &str,
) -> Result<()> {
	if let Some(mut existing) = state.children.remove(app_id) {
		let _ = existing.child.kill();
		let _ = existing.child.wait();
	}

	let context = create_security_listener(&state.security_manager, qh)?;
	context.set_app_id(app_id.to_string());
	context.commit();

	event_queue
		.roundtrip(state)
		.wrap_err("roundtrip after security context commit")?;

	let data = context.data::<SecurityContextData>().unwrap();
	let wayland_socket = data
		.conn
		.lock()
		.unwrap()
		.take()
		.wrap_err("security context socket missing after commit")?;

	let child = spawn_ime(command, wayland_socket)?;
	info!("Launched input method '{}' ({})", app_id, command);

	state.contexts.push(context);
	state.children.insert(
		app_id.to_string(),
		ImeChild {
			command: command.to_string(),
			child,
		},
	);
	Ok(())
}

fn launch_all_imes(
	state: &mut AppState,
	qh: &QueueHandle<AppState>,
	event_queue: &mut wayland_client::EventQueue<AppState>,
) {
	let conf = cosmic_config::Config::new("com.system76.CosmicComp", CosmicCompConfig::VERSION)
		.ok()
		.map(|helper| CosmicCompConfig::get_entry(&helper).unwrap_or_else(|(_, c)| c))
		.unwrap_or_default();
	if conf.input_method_map.is_empty() {
		info!("No input method map configured");
		return;
	}

	let mut launched = HashSet::new();
	for entry in conf.input_method_map.values() {
		if launched.contains(&entry.app_id) {
			continue;
		}
		launched.insert(entry.app_id.clone());
		if let Err(err) = launch_ime(state, qh, event_queue, &entry.app_id, &entry.command) {
			error!(
				"Failed to launch input method '{}' ({}): {:?}",
				entry.app_id, entry.command, err
			);
		}
	}
}

fn restart_exited(
	state: &mut AppState,
	qh: &QueueHandle<AppState>,
	event_queue: &mut wayland_client::EventQueue<AppState>,
) {
	let exited: Vec<String> = state
		.children
		.iter_mut()
		.filter_map(|(app_id, ime)| match ime.child.try_wait() {
			Ok(Some(status)) => {
				warn!("Input method '{}' exited with {:?}", app_id, status);
				Some(app_id.clone())
			}
			Ok(None) => None,
			Err(err) => {
				error!("Error waiting on input method '{}': {}", app_id, err);
				Some(app_id.clone())
			}
		})
		.collect();

	for app_id in exited {
		let command = state.children.remove(&app_id).map(|c| c.command);
		if let Some(command) = command
			&& let Err(err) = launch_ime(state, qh, event_queue, &app_id, &command)
		{
			error!("Failed to restart input method '{}': {:?}", app_id, err);
		}
	}
}

fn stop_all(state: &mut AppState) {
	for (_, mut ime) in state.children.drain() {
		let _ = ime.child.kill();
		let _ = ime.child.wait();
	}
	state.contexts.clear();
}

fn connect_to_display(env_vars: &[(String, String)]) -> Result<Connection> {
	let display = wayland_display_from_env(env_vars)
		.wrap_err("WAYLAND_DISPLAY missing from compositor environment")?;

	let socket_path = if display.contains('/') {
		std::path::PathBuf::from(display)
	} else {
		let runtime_dir = env_vars
			.iter()
			.find(|(key, _)| key == "XDG_RUNTIME_DIR")
			.map(|(_, value)| value.clone())
			.or_else(|| std::env::var("XDG_RUNTIME_DIR").ok())
			.wrap_err("XDG_RUNTIME_DIR not set")?;
		std::path::Path::new(&runtime_dir).join(&display)
	};

	let stream = UnixStream::connect(&socket_path)
		.wrap_err_with(|| format!("connect to Wayland socket {}", socket_path.display()))?;

	Connection::from_socket(stream).wrap_err("init wayland connection")
}

fn run_supervisor(env_vars: Vec<(String, String)>, token: CancellationToken) -> Result<()> {
	let conn = connect_to_display(&env_vars)?;
	let (globals, mut event_queue) =
		registry_queue_init::<AppState>(&conn).wrap_err("init wayland registry")?;
	let qh = event_queue.handle();

	let security_manager: WpSecurityContextManagerV1 = globals
		.bind(&qh, 1..=1, ())
		.wrap_err("bind wp_security_context_manager_v1")?;

	let mut state = AppState {
		security_manager,
		contexts: Vec::new(),
		children: HashMap::new(),
	};

	event_queue
		.roundtrip(&mut state)
		.wrap_err("initial wayland roundtrip")?;

	launch_all_imes(&mut state, &qh, &mut event_queue);

	if state.children.is_empty() {
		info!("No native input methods to supervise");
		return Ok(());
	}

	info!(
		"Supervising {} native input method(s)",
		state.children.len()
	);

	while !token.is_cancelled() {
		event_queue
			.dispatch_pending(&mut state)
			.wrap_err("dispatch wayland events")?;
		restart_exited(&mut state, &qh, &mut event_queue);
		std::thread::sleep(Duration::from_millis(500));
	}

	stop_all(&mut state);
	Ok(())
}

impl wayland_client::Dispatch<WlRegistry, GlobalListContents> for AppState {
	fn event(
		_state: &mut AppState,
		_proxy: &WlRegistry,
		_event: wayland_client::protocol::wl_registry::Event,
		_data: &GlobalListContents,
		_conn: &Connection,
		_qh: &QueueHandle<AppState>,
	) {
	}
}

delegate_dispatch!(AppState: [WpSecurityContextManagerV1: ()] => AppState);
delegate_dispatch!(AppState: [WpSecurityContextV1: SecurityContextData] => AppState);

/// Run the IME supervisor in the foreground (for one-off launch in an existing
/// session).
pub fn run_standalone() -> Result<()> {
	let env_vars = vec![
		(
			"WAYLAND_DISPLAY".to_string(),
			std::env::var("WAYLAND_DISPLAY").wrap_err("WAYLAND_DISPLAY not set")?,
		),
		(
			"XDG_RUNTIME_DIR".to_string(),
			std::env::var("XDG_RUNTIME_DIR").wrap_err("XDG_RUNTIME_DIR not set")?,
		),
	];
	let token = CancellationToken::new();
	run_supervisor(env_vars, token)
}

/// Start the native IME supervisor after the compositor is ready.
pub fn start(env_vars: Vec<(String, String)>, token: CancellationToken) {
	tokio::spawn(async move {
		let result = tokio::task::spawn_blocking(move || run_supervisor(env_vars, token)).await;
		match result {
			Ok(Ok(())) => {}
			Ok(Err(err)) => error!("Input method supervisor failed: {:?}", err),
			Err(err) => error!("Input method supervisor task failed: {:?}", err),
		}
	});
}
