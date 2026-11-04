// SPDX-License-Identifier: GPL-3.0-only

//! Launch native COSMIC input methods from cosmic-comp's `input_method_map`.
//!
//! Each IME is spawned through `wp_security_context` so cosmic-comp can
//! identify it by `app_id` and grant access to input-method globals.
//! Process lifecycle uses the session `ProcessManager`, same as notifications.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{ContextCompat, Result, WrapErr};
use launch_pad::ProcessManager;
use launch_pad::process::Process;
use rustix::pipe::pipe;
use serde::Deserialize;
use tracing::Instrument;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, delegate_noop};
use wayland_protocols::wp::security_context::v1::client::wp_security_context_manager_v1::WpSecurityContextManagerV1;
use wayland_protocols::wp::security_context::v1::client::wp_security_context_v1::WpSecurityContextV1;

const COMP_CONFIG: &str = "cosmic/com.system76.CosmicComp/v1/input_method_map";
const WAYLAND_SOCKET: &str = "WAYLAND_SOCKET";

#[derive(Debug, Clone, Deserialize)]
struct InputMethodEntry {
	app_id: String,
	command: String,
}

struct SecurityContextData {
	conn: Mutex<Option<UnixStream>>,
}

impl Drop for SecurityContextData {
	fn drop(&mut self) {
		if let Some(stream) = self.conn.lock().unwrap().take() {
			let _ = stream.shutdown(std::net::Shutdown::Both);
		}
	}
}

struct AppState {
	security_manager: WpSecurityContextManagerV1,
	/// Kept alive so the compositor retains each IME's security context.
	contexts: Vec<WpSecurityContextV1>,
}

/// Wayland client that mints `wp_security_context` sockets for IME processes.
struct SecurityFactory {
	inner: Mutex<FactoryInner>,
}

struct FactoryInner {
	_conn: Connection,
	state: AppState,
	event_queue: wayland_client::EventQueue<AppState>,
}

impl SecurityFactory {
	fn connect(env_vars: &[(String, String)]) -> Result<Self> {
		let conn = connect_to_display(env_vars)?;
		let (globals, mut event_queue) =
			registry_queue_init::<AppState>(&conn).wrap_err("init wayland registry")?;
		let qh = event_queue.handle();
		let security_manager: WpSecurityContextManagerV1 = globals
			.bind(&qh, 1..=1, ())
			.wrap_err("bind wp_security_context_manager_v1")?;
		let mut state = AppState {
			security_manager,
			contexts: Vec::new(),
		};
		event_queue
			.roundtrip(&mut state)
			.wrap_err("initial wayland roundtrip")?;
		Ok(Self {
			inner: Mutex::new(FactoryInner {
				_conn: conn,
				state,
				event_queue,
			}),
		})
	}

	fn mint(&self, app_id: &str) -> Result<OwnedFd> {
		let mut inner = self.inner.lock().unwrap();
		let FactoryInner {
			state,
			event_queue,
			..
		} = &mut *inner;
		let qh = event_queue.handle();

		let (close_fd_ours, close_fd) = pipe().wrap_err("pipe for security context close fd")?;
		let addr = SocketAddr::from_abstract_name(abstract_socket_name().as_bytes())
			.wrap_err("abstract socket name for security context")?;
		let listener = UnixListener::bind_addr(&addr).wrap_err("bind security context listener")?;
		let context = state.security_manager.create_listener(
			listener.as_fd(),
			close_fd.as_fd(),
			&qh,
			SecurityContextData {
				conn: Mutex::new(None),
			},
		);
		let conn = UnixStream::connect_addr(&addr).wrap_err("connect security context socket")?;
		drop(close_fd_ours);

		let data = context.data::<SecurityContextData>().unwrap();
		*data.conn.lock().unwrap() = Some(conn);

		context.set_app_id(app_id.to_string());
		context.commit();
		event_queue
			.roundtrip(state)
			.wrap_err("roundtrip after security context commit")?;

		let stream = context
			.data::<SecurityContextData>()
			.unwrap()
			.conn
			.lock()
			.unwrap()
			.take()
			.wrap_err("security context socket missing after commit")?;

		state.contexts.push(context);
		Ok(OwnedFd::from(stream))
	}
}

fn env_get(env_vars: &[(String, String)], key: &str) -> Option<String> {
	env_vars
		.iter()
		.find(|(k, _)| k == key)
		.map(|(_, v)| v.clone())
}

fn load_input_method_map() -> HashMap<String, InputMethodEntry> {
	let Some(path) = input_method_map_path() else {
		return HashMap::new();
	};
	match fs::read_to_string(&path) {
		Ok(contents) => match ron::from_str(&contents) {
			Ok(map) => map,
			Err(err) => {
				error!(
					"Failed to parse input method map {}: {}",
					path.display(),
					err
				);
				HashMap::new()
			}
		},
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
		Err(err) => {
			error!(
				"Failed to read input method map {}: {}",
				path.display(),
				err
			);
			HashMap::new()
		}
	}
}

fn input_method_map_path() -> Option<PathBuf> {
	let relative = Path::new(COMP_CONFIG);
	let user = env::var_os("XDG_CONFIG_HOME")
		.filter(|s| !s.is_empty())
		.map(PathBuf::from)
		.or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
		.map(|base| base.join(relative));
	if let Some(path) = user.filter(|p| p.is_file()) {
		return Some(path);
	}
	let system = Path::new("/usr/share").join(relative);
	system.is_file().then_some(system)
}

fn abstract_socket_name() -> String {
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	format!(
		"cosmic-ime-{}-{}",
		std::process::id(),
		COUNTER.fetch_add(1, Ordering::Relaxed)
	)
}

fn connect_to_display(env_vars: &[(String, String)]) -> Result<Connection> {
	let display = env_get(env_vars, "WAYLAND_DISPLAY")
		.wrap_err("WAYLAND_DISPLAY missing from compositor environment")?;

	let socket_path = if display.contains('/') {
		PathBuf::from(display)
	} else {
		let runtime_dir = env_get(env_vars, "XDG_RUNTIME_DIR")
			.or_else(|| env::var("XDG_RUNTIME_DIR").ok())
			.wrap_err("XDG_RUNTIME_DIR not set")?;
		Path::new(&runtime_dir).join(&display)
	};

	let stream = UnixStream::connect(&socket_path)
		.wrap_err_with(|| format!("connect to Wayland socket {}", socket_path.display()))?;

	Connection::from_socket(stream).wrap_err("init wayland connection")
}

fn ime_process(
	app_id: String,
	command: String,
	mut env_vars: Vec<(String, String)>,
	fd: OwnedFd,
	factory: Arc<SecurityFactory>,
) -> Process {
	env_vars.retain(|(k, _)| k != "WAYLAND_DISPLAY" && k != WAYLAND_SOCKET);
	env_vars.push((WAYLAND_SOCKET.to_string(), fd.as_raw_fd().to_string()));

	let span = info_span!(parent: None, "ime", %app_id, %command);
	let stdout_span = span.clone();
	let stderr_span = span.clone();
	let app_id_for_exit = app_id.clone();
	let command_for_exit = command.clone();

	Process::new()
		.with_executable(command)
		.with_env(env_vars)
		.with_fds(move || vec![fd])
		.with_on_stdout(move |_, _, line| {
			let stdout_span = stdout_span.clone();
			async move {
				info!("{}", line);
			}
			.instrument(stdout_span)
		})
		.with_on_stderr(move |_, _, line| {
			let stderr_span = stderr_span.clone();
			async move {
				warn!("{}", line);
			}
			.instrument(stderr_span)
		})
		.with_on_exit(move |mut pman, key, err_code, will_restart| {
			let app_id = app_id_for_exit.clone();
			let command = command_for_exit.clone();
			let new_fd = will_restart.then(|| factory.mint(&app_id));
			async move {
				if let Some(code) = err_code {
					error!("input method '{app_id}' ({command}) exited with {code}");
				}
				let Some(result) = new_fd else {
					return;
				};
				match result {
					Ok(fd) => {
						let socket = fd.as_raw_fd().to_string();
						if let Err(err) = pman
							.update_process_env(&key, [(WAYLAND_SOCKET, socket)])
							.await
						{
							error!("Failed to update WAYLAND_SOCKET for '{app_id}': {err:?}");
						}
						if let Err(err) = pman.update_process_fds(&key, move || vec![fd]).await {
							error!("Failed to update fds for '{app_id}': {err:?}");
						}
					}
					Err(err) => {
						error!("Failed to recreate security context for '{app_id}': {err:?}");
					}
				}
			}
		})
}

/// Start configured native IMEs after the compositor is ready.
pub fn start(env_vars: Vec<(String, String)>, process_manager: ProcessManager) {
	tokio::spawn(async move {
		if let Err(err) = start_inner(env_vars, process_manager).await {
			error!("Input method launcher failed: {err:?}");
		}
	});
}

async fn start_inner(
	env_vars: Vec<(String, String)>,
	process_manager: ProcessManager,
) -> Result<()> {
	let map = load_input_method_map();
	if map.is_empty() {
		info!("No input method map configured");
		return Ok(());
	}

	let env_for_connect = env_vars.clone();
	let factory = tokio::task::spawn_blocking(move || SecurityFactory::connect(&env_for_connect))
		.await
		.wrap_err("security context factory task failed")??;
	let factory = Arc::new(factory);

	let mut launched = HashSet::new();
	for entry in map.into_values() {
		if !launched.insert(entry.app_id.clone()) {
			continue;
		}

		let factory = factory.clone();
		let app_id = entry.app_id.clone();
		let fd = tokio::task::spawn_blocking({
			let factory = factory.clone();
			let app_id = app_id.clone();
			move || factory.mint(&app_id)
		})
		.await
		.wrap_err("mint security context task failed")?
		.wrap_err_with(|| format!("mint security context for {}", entry.app_id))?;

		let process = ime_process(
			entry.app_id.clone(),
			entry.command.clone(),
			env_vars.clone(),
			fd,
			factory,
		);
		match process_manager.start(process).await {
			Ok(_) => info!(
				"Launched input method '{}' ({})",
				entry.app_id, entry.command
			),
			Err(err) => error!(
				"Failed to start input method '{}' ({}): {err:?}",
				entry.app_id, entry.command
			),
		}
	}

	Ok(())
}

impl Dispatch<WlRegistry, GlobalListContents> for AppState {
	fn event(
		_state: &mut Self,
		_proxy: &WlRegistry,
		_event: wayland_client::protocol::wl_registry::Event,
		_data: &GlobalListContents,
		_conn: &Connection,
		_qh: &QueueHandle<Self>,
	) {
	}
}

delegate_noop!(AppState: ignore WpSecurityContextManagerV1);

impl Dispatch<WpSecurityContextV1, SecurityContextData> for AppState {
	fn event(
		_state: &mut Self,
		_proxy: &WpSecurityContextV1,
		_event: <WpSecurityContextV1 as Proxy>::Event,
		_data: &SecurityContextData,
		_conn: &Connection,
		_qh: &QueueHandle<Self>,
	) {
	}
}
