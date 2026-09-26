use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::ipc::IpcServer;
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn on_signal(_sig: i32) { RUNNING.store(false, Ordering::Relaxed); }

fn main() {
    let mut socket = "/tmp/mitos-bluetooth.sock".to_string();
    let mut data_dir = "/var/lib/mitos-bluetooth".to_string();
    let mut serial: Option<String> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" if i + 1 < args.len() => { socket = args[i + 1].clone(); i += 1; }
            "--data" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 1; }
            "--serial" if i + 1 < args.len() => { serial = Some(args[i + 1].clone()); i += 1; }
            _ => {}
        }
        i += 1;
    }
    let mgr = match BluetoothManager::new(&data_dir) {
        Ok(m) => m,
        Err(e) => { eprintln!("[bluetooth] storage init failed: {e} (try --data)"); std::process::exit(1); }
    };
    if let Some(path) = &serial {
        match mgr.power_on_serial(0, path) {
            Ok(info) => println!("[bluetooth] serial adapter up: {} ({})", info.address, info.name),
            Err(e) => eprintln!("[bluetooth] serial adapter failed: {e}"),
        }
    } else if let Err(e) = mgr.init() {
        eprintln!("[bluetooth] init: {e}");
    }
    for a in mgr.adapters() { println!("[bluetooth] adapter hci{} ready: {} ({})", a.index, a.address, a.name); }
    println!("[bluetooth] state: {:?}", mgr.state());

    unsafe {
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
    }
    let ipc = IpcServer::new(socket, mgr.clone());
    if let Err(e) = ipc.run(&RUNNING) { eprintln!("[ipc] {e}"); }

    // graceful shutdown: release the controllers
    let indexes: Vec<u32> = mgr.adapters().iter().map(|a| a.index).collect();
    for idx in indexes { let _ = mgr.power_off(idx); }
    println!("[bluetooth] stopped");
}