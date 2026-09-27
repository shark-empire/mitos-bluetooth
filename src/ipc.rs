use crate::bluetooth::BluetoothManager;
use crate::device::{Address, AddressType, DeviceId};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus};
use crate::profile::ProfileKind;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Line-delimited JSON over a Unix socket.
///   Request:  {"id": 1, "method": "start_discovery", "params": {...}}
///   Response: {"id": 1, "ok": true, "result": ...} | {"id": 1, "ok": false, "error": "..."}
///   Events (after "subscribe"): {"event": {"type": "deviceFound", "data": {...}}}
pub struct IpcServer {
    pub path: PathBuf,
    pub mgr: Arc<BluetoothManager>,
}

impl IpcServer {
    pub fn new(path: impl Into<PathBuf>, mgr: Arc<BluetoothManager>) -> Self {
        IpcServer { path: path.into(), mgr }
    }

    pub fn run(&self, running: &AtomicBool) -> Result<()> {
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path)?;
        listener.set_nonblocking(true)?;
        println!("[ipc] listening on {}", self.path.display());
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mgr = self.mgr.clone();
                    let bus = self.mgr.bus.clone();
                    std::thread::spawn(move || handle_client(stream, mgr, bus));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => return Err(e.into()),
            }
        }
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}

fn handle_client(stream: UnixStream, mgr: Arc<BluetoothManager>, bus: Arc<EventBus>) {
    let out = match stream.try_clone() {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => { eprintln!("[ipc] clone stream: {e}"); return; }
    };
    let alive = Arc::new(AtomicBool::new(true));
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let req: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => { write_line(&out, &json!({"id": null, "ok": false, "error": format!("bad request: {e}")})); continue; }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = req.get("params").cloned().unwrap_or(json!({}));
        if method == "subscribe" {
            let rx = bus.subscribe();
            let out2 = out.clone();
            let alive2 = alive.clone();
            std::thread::spawn(move || pump_events(rx, out2, alive2));
            write_line(&out, &json!({"id": id, "ok": true, "result": "subscribed"}));
            continue;
        }
        let resp = match dispatch(&mgr, &method, &params) {
            Ok(v) => json!({"id": id, "ok": true, "result": v}),
            Err(e) => json!({"id": id, "ok": false, "error": e.to_string()}),
        };
        write_line(&out, &resp);
    }
    alive.store(false, Ordering::Relaxed);
}

fn pump_events(rx: Receiver<Event>, out: Arc<Mutex<UnixStream>>, alive: Arc<AtomicBool>) {
    while alive.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(ev) => write_line(&out, &json!({"event": ev})),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn peer_is_privileged(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as u32;
    let ok = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
                         &mut cred as *mut _ as *mut libc::c_void, &mut len) == 0
    };
    ok && cred.uid == unsafe { libc::geteuid() }
}

fn write_line(out: &Arc<Mutex<UnixStream>>, v: &Value) {
    let mut s = out.lock().unwrap();
    let _ = writeln!(s, "{}", serde_json::to_string(v).unwrap_or_default());
    let _ = s.flush();
}

fn dispatch(mgr: &BluetoothManager, method: &str, p: &Value, privileged: bool) -> Result<Value> {
    Ok(match method {
            if !privileged && matches!(method, "power_on" | "power_off" | "pair" | "remove_device") {
        return Err(Error::PermissionDenied(format!("method '{method}' requires local privileges")));
          }
        "ping" => json!("pong"),
        "get_state" => serde_json::to_value(mgr.state())?,
        "get_adapters" => serde_json::to_value(mgr.adapters())?,
        "get_bonds" => serde_json::to_value(mgr.bonds_list())?,
        "power_on" => { let i = p_index(p)?; serde_json::to_value(mgr.power_on(i)?)? }
        "power_off" => { let i = p_index(p)?; mgr.power_off(i)?; json!(true) }
        "set_discoverable" => { let i = p_index(p)?; mgr.set_discoverable(i, p_bool(p, "on"))?; json!(true) }
        "set_name" => { let i = p_index(p)?; let n = p_str(p, "name")?; mgr.set_name(i, &n)?; json!(true) }
        "start_discovery" => {
            let i = p_index(p)?;
            let le = p.get("le").and_then(|v| v.as_bool()).unwrap_or(true);
            let bredr = p.get("bredr").and_then(|v| v.as_bool()).unwrap_or(true);
            let t = p.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(12);
            mgr.start_discovery(i, bredr, le, t)?;
            json!(true)
        }
        "stop_discovery" => { let i = p_index(p)?; mgr.stop_discovery(i)?; json!(true) }
        "get_devices" => { let i = p_index(p)?; serde_json::to_value(mgr.devices(i)?)? }
        "get_device" => {
            let i = p_index(p)?;
            let id = resolve_device(mgr, i, p)?;
            match mgr.get_device(i, &id)? { Some(d) => serde_json::to_value(d)?, None => Value::Null }
        }
        "pair" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.pair(i, &id)?; json!(true) }
        "pairing_confirm" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.pairing_confirm(i, &id, p_bool(p, "accept"))?; json!(true) }
        "provide_pin" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; let pin = p_str(p, "pin")?; mgr.provide_pin(i, &id, &pin)?; json!(true) }
        "provide_passkey" => {
            let i = p_index(p)?;
            let id = resolve_device(mgr, i, p)?;
            let k = p.get("passkey").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("passkey required".into()))? as u32;
            mgr.provide_passkey(i, &id, k)?; json!(true)
        }
        "cancel_pairing" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.cancel_pairing(i, &id)?; json!(true) }
        "connect" => {
            let i = p_index(p)?;
            let id = resolve_device(mgr, i, p)?;
            let kind = ProfileKind::from_label(p.get("profile").and_then(|v| v.as_str()).unwrap_or("hid"))
                .ok_or_else(|| Error::InvalidArgument("profile must be one of: hid, a2dp, avrcp, hfp, hsp, gatt".into()))?;
            mgr.connect(i, &id, kind)?;
            json!(true)
        }
        "disconnect" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.disconnect(i, &id)?; json!(true) }
        "get_connections" => { let i = p_index(p)?; serde_json::to_value(mgr.connections(i)?)? }
        "set_trusted" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.set_trusted(&id, p_bool(p, "on"))?; json!(true) }
        "remove_device" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.remove_device(i, &id)?; json!(true) }
                "gatt_services" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; serde_json::to_value(mgr.gatt_services(i, &id)?)? }
        "gatt_characteristics" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let svc = p.get("service").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("service (start handle) required".into()))? as u16;
            serde_json::to_value(mgr.gatt_characteristics(i, &id, svc)?)?
        }
        "gatt_read" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let attr = p.get("attribute").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("attribute required".into()))? as u16;
            serde_json::to_value(crate::device::to_hex(&mgr.gatt_read(i, &id, attr)?))?
        }
        "gatt_write" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let attr = p.get("attribute").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("attribute required".into()))? as u16;
            let data = crate::device::from_hex(&p_str(p, "data")?)?;
            mgr.gatt_write(i, &id, attr, &data, p_bool(p, "response"))?;
            json!(true)
        }
        "gatt_subscribe" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let attr = p.get("attribute").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("attribute required".into()))? as u16;
            let kind = p.get("kind").and_then(|v| v.as_u64()).unwrap_or(1) as u16; // 1 notify, 2 indicate
            mgr.gatt_subscribe(i, &id, attr, kind)?;
            json!(true)
        }
                "a2dp_start" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.a2dp_start(i, &id)?; json!(true) }
        "a2dp_suspend" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.a2dp_suspend(i, &id)?; json!(true) }
        "a2dp_state" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; serde_json::to_value(mgr.a2dp_state(i, &id)?)? }
        "a2dp_send_sbc" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let data = crate::device::from_hex(&p_str(p, "data")?)?;
            let nframes = p.get("frames").and_then(|v| v.as_u64()).unwrap_or(1) as u32; // pass real count when batching
            mgr.a2dp_send_sbc(i, &id, &data, nframes)?;
            json!(true)
        }
        "avrcp_command" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let op = p_str(p, "op")?; // play | pause | stop | next | prev | volup | voldown | mute
            mgr.avrcp_command(i, &id, &op)?;
            json!(true)
        }
        "set_volume" => {
            let i = p_index(p)?; let id = resolve_device(mgr, i, p)?;
            let v = p.get("volume").and_then(|v| v.as_u64()).ok_or_else(|| Error::InvalidArgument("volume required".into()))? as u8;
            mgr.set_volume(i, &id, v)?;
            json!(true)
        }
        "hfp_connect_sco" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.hfp_connect_sco(i, &id)?; json!(true) }
        "hfp_disconnect_sco" => { let i = p_index(p)?; let id = resolve_device(mgr, i, p)?; mgr.hfp_disconnect_sco(i, &id)?; json!(true) }
        other => return Err(Error::NotFound(format!("unknown method '{other}'"))),
    })
}

fn p_index(p: &Value) -> Result<u32> {
    p.get("index").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| Error::InvalidArgument("index required".into()))
}
fn p_bool(p: &Value, k: &str) -> bool { p.get(k).and_then(|v| v.as_bool()).unwrap_or(false) }
fn p_str(p: &Value, k: &str) -> Result<String> {
    p.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
        .ok_or_else(|| Error::InvalidArgument(format!("{k} required")))
}

/// Find a DeviceId by address — prefers the learned type from the device table.
fn resolve_device(mgr: &BluetoothManager, index: u32, p: &Value) -> Result<DeviceId> {
    let addr_s = p_str(p, "address")?;
    let address = Address::parse(&addr_s)?;
    let rt = mgr.runtime(index)?;
    if let Some(d) = rt.devices.lock().unwrap().values().find(|d| d.id.address == address) {
        return Ok(d.id);
    }
    let at = match p.get("type").and_then(|v| v.as_str()) {
        Some("le") | Some("lePublic") => AddressType::LePublic,
        Some("leRandom") => AddressType::LeRandom,
        _ => AddressType::Bredr,
    };
    Ok(DeviceId { address, address_type: at })
}