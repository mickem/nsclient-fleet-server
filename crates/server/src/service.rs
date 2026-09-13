//! Running as a Windows service.
//!
//! The service control manager does not start a program and leave it alone the way systemd
//! does. It starts the process, then waits to be called back: within seconds the process
//! has to connect to the SCM, register a handler, and report `SERVICE_RUNNING`, or the
//! service is declared failed and killed. That is why a console binary registered with
//! `sc.exe create` fails with "the service did not respond to the start request in a timely
//! fashion" — nothing is wrong with the program, it simply never answered.
//!
//! So the same binary is both things, and which one it is is not a flag:
//! [`run_if_started_by_scm`] offers itself to the SCM, and the SCM's refusal
//! (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) is exactly the signal that this is an
//! ordinary foreground run. A console, a container and `sc.exe start` therefore all work
//! with no arguments to get right, and nothing has to be kept in sync between the command
//! line the installer writes and the one the operator types.
//!
//! Configuration reaches the service through `--env-file`, not the environment: the SCM
//! hands a service the machine-wide environment, and `MASTER_KEY` in there would be
//! readable by every process on the host. See [`fleet_server::env_file`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The name `sc.exe`, `Get-Service` and the registry all know this by.
const SERVICE_NAME: &str = "nsclient-fleet";
const DISPLAY_NAME: &str = "NSClient Fleet control plane";
const DESCRIPTION: &str = "Serves the NSClient Fleet operator UI and the agent mTLS API. \
                           Configuration is read from the env file named on its command line.";

/// Own process, not shared: this binary is the whole service.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// The SCM kills a service that has not reported `SERVICE_STOPPED` within its stop timeout
/// (30 seconds by default). A `wait_hint` this long, sent with `StopPending`, tells it the
/// drain is deliberate — comfortably over `shutdown::DRAIN_TIMEOUT` and under the default.
const STOP_WAIT_HINT: Duration = Duration::from_secs(25);

/// How long the service is left alone after a crash before Windows restarts it. The
/// systemd unit says `RestartSec=5`; this is the same answer.
const RESTART_DELAY: Duration = Duration::from_secs(5);

/// Set once, in `service_main`, so the control handler can move the service to
/// `StopPending` while the listeners drain.
static STATUS_HANDLE: OnceLock<service_control_handler::ServiceStatusHandle> = OnceLock::new();

/// Names of the variables that came from the env file, for the startup log. Crossing into
/// `service_main` has to go through a static: the SCM calls it, so there is no argument of
/// ours to pass.
static ENV_FILE_VARS: OnceLock<Vec<String>> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Offer this process to the service control manager.
///
/// Returns `true` when it was started as a service — by then the service has already run
/// and stopped, because the SCM's dispatcher does not return until it has. Returns `false`
/// when there is no SCM to talk to, which is every ordinary run.
pub fn run_if_started_by_scm(env_file_vars: &[String]) -> Result<bool> {
    let _ = ENV_FILE_VARS.set(env_file_vars.to_vec());

    match windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            Ok(false)
        }
        Err(e) => Err(anyhow::Error::new(e).context("connecting to the service control manager")),
    }
}

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` — "the service process could not connect to
/// the service controller", which is what a process not started by the SCM is told.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// The SCM's entry point. Arguments here are the ones passed to `sc start`, not the ones in
/// the registered command line — those arrive as ordinary `std::env::args` and have already
/// been parsed by the time this runs.
fn service_main(_scm_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        // The status report below is the one thing that must still happen: without it the
        // SCM waits out its timeout and reports a hang rather than the failure.
        tracing::error!(error = %e, "service stopped with an error");
        if let Some(handle) = STATUS_HANDLE.get() {
            let _ =
                handle.set_service_status(status(ServiceState::Stopped, ServiceExitCode::Win32(1)));
        }
    }
}

fn run_service() -> Result<()> {
    let (trigger, shutdown) = fleet_server::shutdown::channel();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            // Shutdown is the machine going down; the response to both is the same, and
            // accepting Shutdown is what stops a reboot from cutting a drain short.
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(handle) = STATUS_HANDLE.get() {
                    let _ = handle.set_service_status(ServiceStatus {
                        current_state: ServiceState::StopPending,
                        wait_hint: STOP_WAIT_HINT,
                        ..status(ServiceState::StopPending, ServiceExitCode::Win32(0))
                    });
                }
                trigger.fire();
                ServiceControlHandlerResult::NoError
            }
            // Answering means "still here". The SCM asks; a service that does not answer
            // looks stuck.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering the service control handler")?;
    let _ = STATUS_HANDLE.set(status_handle);

    status_handle
        .set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)))
        .context("reporting SERVICE_RUNNING")?;
    tracing::info!("running as a Windows service");

    let vars = ENV_FILE_VARS.get().cloned().unwrap_or_default();
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    let result = runtime.block_on(crate::serve(shutdown, &vars));

    // Reported whichever way the server ended, and before the error is returned: a service
    // that exits without this is one the SCM has to time out on.
    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::Win32(1),
    };
    status_handle
        .set_service_status(status(ServiceState::Stopped, exit))
        .context("reporting SERVICE_STOPPED")?;
    result
}

fn status(state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        // Only meaningful while running; the SCM ignores it in the other states.
        controls_accepted: match state {
            ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            _ => ServiceControlAccept::empty(),
        },
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

/// Register the service, pointing it at this executable and at `--env-file` if one was
/// given. Requires an elevated prompt.
pub fn install(args: &crate::cli::Args) -> Result<()> {
    let exe = std::env::current_exe().context("finding this executable")?;

    // A service's working directory is `C:\Windows\System32`, so anything relative in its
    // command line resolves somewhere nobody meant. Absolute is not optional here.
    let mut launch_arguments = Vec::new();
    if let Some(env_file) = &args.env_file {
        let absolute = absolute_path(env_file)?;
        if !absolute.is_file() {
            bail!(
                "no env file at {} — write it first, then install the service",
                absolute.display()
            );
        }
        launch_arguments.push(OsString::from("--env-file"));
        launch_arguments.push(absolute.into_os_string());
    } else {
        // Not fatal: an operator may be setting the machine environment deliberately. But
        // it is the one mistake this command can see coming, and `MASTER_KEY` in the
        // machine environment is readable by every process on the host.
        tracing::warn!(
            "installing without --env-file; the service will read the machine environment, \
             where MASTER_KEY would be readable by every process on this host"
        );
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(elevation_hint)
    .context("opening the service control manager")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        // Starts with the machine, like `WantedBy=multi-user.target` on the other side.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments,
        dependencies: vec![],
        // LocalSystem. Narrowing this to a virtual service account is worth doing and is a
        // separate step, because the data directory's ACL has to be changed with it — the
        // Windows install guide walks through it.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(already_exists_hint)
        .context("creating the service")?;

    service
        .set_description(DESCRIPTION)
        .context("setting the service description")?;

    // The unit file says `Restart=on-failure`; this is that. Without it a crashed control
    // plane stays down until somebody notices the fleet has stopped reporting.
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: RESTART_DELAY,
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: RESTART_DELAY,
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: RESTART_DELAY,
                },
            ]),
        })
        .context("setting the restart-on-failure policy")?;

    println!("Installed the {SERVICE_NAME} service.");
    println!("  Executable:  {}", exe.display());
    match &args.env_file {
        Some(path) => println!("  Env file:    {}", absolute_path(path)?.display()),
        None => println!("  Env file:    none — reads the machine environment"),
    }
    println!("\nStart it with:  sc.exe start {SERVICE_NAME}");
    Ok(())
}

/// Stop the service if it is running, then remove it. Requires an elevated prompt.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(elevation_hint)
        .context("opening the service control manager")?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("opening the service — is it installed?")?;

    let state = service
        .query_status()
        .context("querying the service")?
        .current_state;
    if state != ServiceState::Stopped && state != ServiceState::StopPending {
        service.stop().context("stopping the service")?;
        println!("Stopping {SERVICE_NAME}…");
        // The SCM removes a service that still has an open handle only once every handle
        // is closed, so waiting for the stop here is what makes the deletion take effect
        // now rather than at the next reboot.
        wait_for_stop(&service)?;
    }

    service.delete().context("deleting the service")?;
    println!("Removed the {SERVICE_NAME} service. Its data directory was left alone.");
    Ok(())
}

/// Poll until the service reports stopped, or the drain deadline passes.
fn wait_for_stop(service: &windows_service::service::Service) -> Result<()> {
    let deadline = std::time::Instant::now() + STOP_WAIT_HINT;
    loop {
        let state = service
            .query_status()
            .context("querying the service")?
            .current_state;
        if state == ServiceState::Stopped {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("the service did not stop within {STOP_WAIT_HINT:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `std::path::absolute` without the `\\?\` prefix `canonicalize` would add — that prefix
/// is legal but shows up in `sc qc` output and in every log line that quotes the command.
fn absolute_path(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))
}

/// Access denied here means one thing in practice, and saying so saves a web search.
fn elevation_hint(e: windows_service::Error) -> anyhow::Error {
    const ERROR_ACCESS_DENIED: i32 = 5;
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
            return anyhow::Error::new(e).context(
                "access denied — run this from an elevated prompt (Run as administrator)",
            );
        }
    }
    anyhow::Error::new(e)
}

/// Likewise for a second install over an existing service.
fn already_exists_hint(e: windows_service::Error) -> anyhow::Error {
    const ERROR_SERVICE_EXISTS: i32 = 1073;
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(ERROR_SERVICE_EXISTS) {
            return anyhow::Error::new(e).context(format!(
                "the {SERVICE_NAME} service is already installed — remove it with \
                 --service-uninstall first, or change it with sc.exe config"
            ));
        }
    }
    anyhow::Error::new(e)
}
