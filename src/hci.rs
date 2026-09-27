use crate::device::Address;
use crate::error::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const fn opcode(ogf: u16, ocf: u16) -> u16 { ((ogf & 0x3f) << 10) | (ocf & 0x3ff) }

pub mod op {
    use super::opcode;
    pub const INQUIRY: u16 = opcode(0x01, 0x0001);
    pub const INQUIRY_CANCEL: u16 = opcode(0x01, 0x0002);
    pub const CREATE_CONNECTION: u16 = opcode(0x01, 0x0005);
    pub const DISCONNECT: u16 = opcode(0x01, 0x0006);
    pub const ACCEPT_CONNECTION_REQUEST: u16 = opcode(0x01, 0x0009);
    pub const REJECT_CONNECTION_REQUEST: u16 = opcode(0x01, 0x000a);
    pub const LINK_KEY_REQUEST_REPLY: u16 = opcode(0x01, 0x000b);
    pub const LINK_KEY_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x000c);
    pub const PIN_CODE_REQUEST_REPLY: u16 = opcode(0x01, 0x000d);
    pub const PIN_CODE_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x000e);
    pub const AUTHENTICATION_REQUESTED: u16 = opcode(0x01, 0x0010);
    pub const SET_CONNECTION_ENCRYPTION: u16 = opcode(0x01, 0x0011);
    pub const REMOTE_NAME_REQUEST: u16 = opcode(0x01, 0x0014);
    pub const READ_REMOTE_SUPPORTED_FEATURES: u16 = opcode(0x01, 0x0016);
    pub const SETUP_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x001b);
    pub const ACCEPT_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x001c);
    pub const REJECT_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x001d);
    pub const IO_CAPABILITY_REQUEST_REPLY: u16 = opcode(0x01, 0x001e);
    pub const USER_CONFIRMATION_REQUEST_REPLY: u16 = opcode(0x01, 0x002c);
    pub const USER_CONFIRMATION_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x002d);
    pub const USER_PASSKEY_REQUEST_REPLY: u16 = opcode(0x01, 0x002e);
    pub const USER_PASSKEY_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x002f);
    pub const REMOTE_OOB_DATA_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x0031);
    pub const SET_EVENT_MASK: u16 = opcode(0x03, 0x0001);
    pub const RESET: u16 = opcode(0x03, 0x0003);
    pub const WRITE_LOCAL_NAME: u16 = opcode(0x03, 0x0013);
    pub const WRITE_PAGE_TIMEOUT: u16 = opcode(0x03, 0x0018);
    pub const WRITE_SCAN_ENABLE: u16 = opcode(0x03, 0x001a);
    pub const READ_SCAN_ENABLE: u16 = opcode(0x03, 0x001b);
    pub const WRITE_CLASS_OF_DEVICE: u16 = opcode(0x03, 0x0024);
    pub const WRITE_INQUIRY_MODE: u16 = opcode(0x03, 0x0045);
    pub const WRITE_EXTENDED_INQUIRY_RESPONSE: u16 = opcode(0x03, 0x0052);
    pub const WRITE_SIMPLE_PAIRING_MODE: u16 = opcode(0x03, 0x0056);
    pub const WRITE_LE_HOST_SUPPORT: u16 = opcode(0x03, 0x006d);
    pub const READ_LOCAL_VERSION: u16 = opcode(0x04, 0x0001);
    pub const READ_LOCAL_SUPPORTED_FEATURES: u16 = opcode(0x04, 0x0003);
    pub const READ_BUFFER_SIZE: u16 = opcode(0x04, 0x0005);
    pub const READ_BD_ADDR: u16 = opcode(0x04, 0x0009);
    pub const LE_READ_BUFFER_SIZE: u16 = opcode(0x08, 0x0002);
    pub const LE_SET_SCAN_PARAMETERS: u16 = opcode(0x08, 0x000b);
    pub const LE_SET_SCAN_ENABLE: u16 = opcode(0x08, 0x000c);
    pub const LE_CREATE_CONNECTION: u16 = opcode(0x08, 0x000d);
    pub const LE_CREATE_CONNECTION_CANCEL: u16 = opcode(0x08, 0x000e);
    pub const LE_START_ENCRYPTION: u16 = opcode(0x08, 0x0019);
    pub const LE_LTK_REQUEST_REPLY: u16 = opcode(0x08, 0x001a);
    pub const LE_LTK_REQUEST_NEG_REPLY: u16 = opcode(0x08, 0x001b);
}

pub mod ev {
    pub const INQUIRY_COMPLETE: u8 = 0x01;
    pub const INQUIRY_RESULT: u8 = 0x02;
    pub const CONNECTION_COMPLETE: u8 = 0x03;
    pub const CONNECTION_REQUEST: u8 = 0x04;
    pub const DISCONNECTION_COMPLETE: u8 = 0x05;
    pub const AUTHENTICATION_COMPLETE: u8 = 0x06;
    pub const REMOTE_NAME_REQUEST_COMPLETE: u8 = 0x07;
    pub const ENCRYPTION_CHANGE: u8 = 0x08;
    pub const READ_REMOTE_SUPPORTED_FEATURES_COMPLETE: u8 = 0x0b;
    pub const COMMAND_COMPLETE: u8 = 0x0e;
    pub const COMMAND_STATUS: u8 = 0x0f;
    pub const ROLE_CHANGE: u8 = 0x12;
    pub const NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
    pub const PIN_CODE_REQUEST: u8 = 0x16;
    pub const LINK_KEY_REQUEST: u8 = 0x17;
    pub const LINK_KEY_NOTIFICATION: u8 = 0x18;
    pub const SYNCHRONOUS_CONNECTION_COMPLETE: u8 = 0x2c;
    pub const INQUIRY_RESULT_WITH_RSSI: u8 = 0x22;
    pub const EXTENDED_INQUIRY_RESULT: u8 = 0x2f;
    pub const IO_CAPABILITY_REQUEST: u8 = 0x31;
    pub const IO_CAPABILITY_RESPONSE: u8 = 0x32;
    pub const USER_CONFIRMATION_REQUEST: u8 = 0x33;
    pub const USER_PASSKEY_REQUEST: u8 = 0x34;
    pub const REMOTE_OOB_DATA_REQUEST: u8 = 0x35;
    pub const SIMPLE_PAIRING_COMPLETE: u8 = 0x36;
    pub const USER_PASSKEY_NOTIFICATION: u8 = 0x3b;
    pub const LE_META_EVENT: u8 = 0x3e;
    pub const LE_CONNECTION_COMPLETE: u8 = 0x01;
    pub const LE_ADVERTISING_REPORT: u8 = 0x02;
    pub const LE_LTK_REQUEST: u8 = 0x05;
    pub const SYNCHRONOUS_CONNECTION_COMPLETE: u8 = 0x2c;
}

pub const ACL_PB_START: u16 = 0x1000;
pub const ACL_PB_CONT: u16 = 0x2000;
pub const INQUIRY_LAP_GENERAL: [u8; 3] = [0x33, 0x8b, 0x9e];

#[derive(Clone, Debug)]
pub struct HciEvent {
    pub code: u8,
    pub params: Vec<u8>,
}
impl HciEvent {
    pub fn u8(&self, o: usize) -> u8 { self.params.get(o).copied().unwrap_or(0) }
    pub fn u16(&self, o: usize) -> u16 { let b = self.bytes(o, 2); u16::from_le_bytes([b[0], b[1]]) }
    pub fn u32(&self, o: usize) -> u32 { let b = self.bytes(o, 4); u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    pub fn addr(&self, o: usize) -> Address { Address(self.bytes(o, 6).try_into().unwrap()) }
    pub fn bytes(&self, o: usize, n: usize) -> &[u8] {
        if o + n <= self.params.len() { &self.params[o..o + n] } else { &self.params[self.params.len().min(o)..] }
    }
    pub fn le_sub(&self) -> u8 { self.params.first().copied().unwrap_or(0) }
}

#[derive(Debug)]
pub struct AclSdu { pub handle: u16, pub cid: u16, pub data: Vec<u8> }

/// One H4-framed packet at a time (type byte included).
pub trait HciTransport: Send {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize>;
    fn try_clone(&self) -> Result<Box<dyn HciTransport>>;
    fn name(&self) -> String;
}

// ---------------- Linux: HCI user-channel socket (exclusive access, H4 framing) ----------------
const HCIDEVDOWN: libc::c_ulong = 0x400448CA;

pub struct LinuxHciSocket { fd: i32 }

impl LinuxHciSocket {
    fn new(fd: i32) -> Self { LinuxHciSocket { fd } }
}

impl Drop for LinuxHciSocket {
    fn drop(&mut self) { unsafe { libc::close(self.fd) }; }
}

impl HciTransport for LinuxHciSocket {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < packet.len() {
            let n = unsafe { libc::write(self.fd, packet[off..].as_ptr() as *const libc::c_void, packet.len() - off) };
            if n < 0 { return Err(Error::Io(std::io::Error::last_os_error())); }
            off += n as usize;
        }
        Ok(())
    }
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        out.resize(2048, 0);
        let n = unsafe { libc::read(self.fd, out.as_mut_ptr() as *mut libc::c_void, out.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => Error::Timeout("hci recv"),
                _ => Error::Io(e),
            });
        }
        if n == 0 { return Err(Error::TransportClosed); }
        out.truncate(n as usize);
        Ok(n as usize)
    }
    fn try_clone(&self) -> Result<Box<dyn HciTransport>> {
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 { return Err(Error::Io(std::io::Error::last_os_error())); }
        Ok(Box::new(LinuxHciSocket::new(fd)))
    }
    fn name(&self) -> String { format!("hci-user-fd-{}", self.fd) }
}

#[repr(C)]
struct SockAddrHci { family: u16, dev: u16, channel: u16 }

/// The user channel requires the adapter to be DOWN (kernel stack must not own it).
pub fn hci_dev_down(index: u32) {
    unsafe {
        let fd = libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 1);
        if fd >= 0 {
            let _ = libc::ioctl(fd, HCIDEVDOWN, index as libc::c_int); // ignore "already down"
            libc::close(fd);
        }
    }
}

pub fn open_hci_user_channel(index: u32) -> Result<LinuxHciSocket> {
    hci_dev_down(index);
    unsafe {
        let fd = libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 1);
        if fd < 0 { return Err(Error::PermissionDenied(format!("hci socket: {}", std::io::Error::last_os_error()))); }
        // in open_hci_user_channel():
let sa = SockAddrHci { family: libc::AF_BLUETOOTH as u16, dev: index as u16,
                       channel: 1 /* HCI_CHANNEL_USER — 2 is the read-only monitor channel */ };
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<SockAddrHci>() as u32) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(Error::PermissionDenied(format!("bind user channel hci{index}: {e}")));
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
        Ok(LinuxHciSocket::new(fd))
    }
}

pub fn list_linux_adapters() -> Vec<(u32, String)> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/bluetooth") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(idx) = name.strip_prefix("hci") {
                if let Ok(i) = idx.parse::<u32>() {
                    let addr = std::fs::read_to_string(e.path().join("address")).map(|s| s.trim().to_string()).unwrap_or_default();
                    v.push((i, addr));
                }
            }
        }
    }
    v.sort();
    v
}

// ---------------- Serial H4 (e.g. UART Bluetooth module on your own hardware) ----------------
pub struct SerialH4 { port: Box<dyn std::io::Read + Send>, writer: Box<dyn std::io::Write + Send>, buf: Vec<u8>, label: String }

impl SerialH4 {
    pub fn open(path: &str) -> Result<Self> {
        let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let w = f.try_clone()?;
        Ok(SerialH4 { port: Box::new(f), writer: Box::new(w), buf: Vec::new(), label: path.to_string() })
    }
    fn fill(&mut self, need: usize) -> Result<()> {
        while self.buf.len() < need {
            let mut tmp = [0u8; 256];
            let n = self.port.read(&mut tmp)?;
            if n == 0 { return Err(Error::TransportClosed); }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }
}

impl HciTransport for SerialH4 {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.writer.write_all(packet)?;
        self.writer.flush()
    }
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        // H4 stream framing: [type][hdr][len][body]
        self.fill(1)?;
        let ty = self.buf[0];
        let hdr = match ty { 0x01 => 3, 0x02 | 0x03 => 4, 0x04 => 2, _ => { self.buf.remove(0); return self.recv_packet(out); } };
        self.fill(1 + hdr)?;
        let len = match ty {
            0x01 => self.buf[3] as usize,
            0x02 | 0x03 => u16::from_le_bytes([self.buf[3], self.buf[4]]) as usize,
            0x04 => self.buf[2] as usize,
            _ => 0,
        };
        let total = 1 + hdr + len;
        self.fill(total)?;
        out.clear();
        out.extend_from_slice(&self.buf[..total]);
        self.buf.drain(..total);
        Ok(total)
    }
    fn try_clone(&self) -> Result<Box<dyn HciTransport>> {
    // Re-open the same device: the reader thread owns one fd, the writer another.
    let f = std::fs::OpenOptions::new().read(true).write(true).open(&self.label)?;
    let w = f.try_clone()?;
    Ok(Box::new(SerialH4 { port: Box::new(f), writer: Box::new(w), buf: Vec::new(), label: self.label.clone() }))
      }
    fn name(&self) -> String { self.label.clone() }
}

// ---------------- HciClient ----------------
struct PendState {
    complete: HashMap<u16, Vec<Sender<Vec<u8>>>>,
    status: HashMap<u16, Vec<Sender<u8>>>,
    event_waiters: VecDeque<(u64, Box<dyn Fn(&HciEvent) -> bool + Send>, Sender<HciEvent>)>,
    acl_rx: HashMap<u16, Vec<u8>>,
}
struct Credits { mtu: u16, available: u32, set: bool }

struct Inner {
    transport: Mutex<Box<dyn HciTransport>>,
    state: Mutex<PendState>,
    cmd_lock: Mutex<()>,
    credits: Mutex<Credits>,
    credits_cv: Condvar,
    handler: Mutex<Option<Box<dyn Fn(HciEvent) + Send>>>,
    acl_tx: Mutex<Option<Sender<AclSdu>>>,
    sco_tx: Mutex<Option<Sender<(u16, Vec<u8>)>>>,
    running: AtomicBool,
    next_event_id: AtomicU64,
}

pub struct HciClient {
    index: u32,
    inner: Arc<Inner>,
    cmd_timeout: Duration,
    reader: Mutex<Option<JoinHandle<()>>>,
}

fn hci_cmd_buf(opcode: u16, params: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + params.len());
    v.push(0x01);
    v.extend_from_slice(&opcode.to_le_bytes());
    v.push(params.len() as u8);
    v.extend_from_slice(params);
    v
}

impl HciClient {
    pub fn open(index: u32, transport: Box<dyn HciTransport>) -> Result<Self> {
        let reader_tr = transport.try_clone()?;
        let inner = Arc::new(Inner {
            transport: Mutex::new(transport),
            state: Mutex::new(PendState { complete: HashMap::new(), status: HashMap::new(), event_waiters: VecDeque::new(), acl_rx: HashMap::new() }),
            cmd_lock: Mutex::new(()),
            credits: Mutex::new(Credits { mtu: 27, available: 8, set: false }),
            credits_cv: Condvar::new(),
            handler: Mutex::new(None),
            acl_tx: Mutex::new(None),
            sco_tx: Mutex::new(None),
            running: AtomicBool::new(true),
            next_event_id: AtomicU64::new(1),
        });
        let i2 = inner.clone();
        let jh = std::thread::Builder::new().name(format!("hci{index}-reader")).spawn(move || reader_loop(reader_tr, i2))?;
        Ok(HciClient { index, inner, cmd_timeout: Duration::from_secs(5), reader: Mutex::new(Some(jh)) })
    }
    /// Send a raw SCO data packet (H4 type 3). Payload follows the voice setting
    /// (0x0060 => 16-bit linear PCM); the controller CVSD-encodes over the air.
    pub fn send_sco(&self, handle: u16, data: &[u8]) -> Result<()> {
        let mut pkt = Vec::with_capacity(5 + data.len());
        pkt.push(0x03);
        pkt.extend_from_slice(&handle.to_le_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_le_bytes());
        pkt.extend_from_slice(data);
        self.inner.transport.lock().unwrap().send_packet(&pkt)
    }

    pub fn index(&self) -> u32 { self.index }
    pub fn shutdown(&self) { self.inner.running.store(false, Ordering::Relaxed); }
    pub fn set_event_handler(&self, f: Box<dyn Fn(HciEvent) + Send>) { *self.inner.handler.lock().unwrap() = Some(f); }
    pub fn set_acl_handler(&self, tx: Sender<AclSdu>) { *self.inner.acl_tx.lock().unwrap() = Some(tx); }
    pub fn set_sco_handler(&self, tx: Sender<(u16, Vec<u8>)>) { *self.inner.sco_tx.lock().unwrap() = Some(tx); }

    /// Send a command, wait for CommandComplete. Returns return params (status byte included, always 0 here).
    pub fn command(&self, opcode: u16, params: &[u8]) -> Result<Vec<u8>> {
        let _g = self.inner.cmd_lock.lock().unwrap();
        let (tx, rx) = channel();
        {
            let mut p = self.inner.state.lock().unwrap();
            p.complete.entry(opcode).or_default().push(tx);
        }
        let send = self.inner.transport.lock().unwrap().send_packet(&hci_cmd_buf(opcode, params));
        if let Err(e) = send {
            let mut p = self.inner.state.lock().unwrap();
            p.complete.remove(&opcode);
            return Err(e);
        }
        match rx.recv_timeout(self.cmd_timeout) {
            Ok(r) => {
                if r.is_empty() { Err(Error::TransportClosed) }
                else if r[0] != 0 { Err(Error::Hci { opcode, status: r[0] }) }
                else { Ok(r) }
            }
            Err(_) => {
                let mut p = self.inner.state.lock().unwrap();
                p.complete.remove(&opcode);
                Err(Error::Timeout("command complete"))
            }
        }
    }

    /// Send a command, wait for CommandStatus only (Inquiry, Create Connection, ...).
    pub fn command_status(&self, opcode: u16, params: &[u8]) -> Result<()> {
        let _g = self.inner.cmd_lock.lock().unwrap();
        let (tx, rx) = channel();
        {
            let mut p = self.inner.state.lock().unwrap();
            p.status.entry(opcode).or_default().push(tx);
        }
        let send = self.inner.transport.lock().unwrap().send_packet(&hci_cmd_buf(opcode, params));
        if let Err(e) = send {
            let mut p = self.inner.state.lock().unwrap();
            p.status.remove(&opcode);
            return Err(e);
        }
        match rx.recv_timeout(self.cmd_timeout) {
            Ok(status) => if status == 0 { Ok(()) } else { Err(Error::Hci { opcode, status }) },
            Err(_) => {
                let mut p = self.inner.state.lock().unwrap();
                p.status.remove(&opcode);
                Err(Error::Timeout("command status"))
            }
        }
    }

    /// Wait for an event matching `pred`. Does not consume other waiters or the core handler.
    pub fn wait_event<F>(&self, pred: F, timeout: Duration) -> Result<HciEvent>
    where F: Fn(&HciEvent) -> bool + Send + 'static {
        let (tx, rx) = channel();
        let id = self.inner.next_event_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut p = self.inner.state.lock().unwrap();
            p.event_waiters.push_back((id, Box::new(pred), tx));
        }
        match rx.recv_timeout(timeout) {
            Ok(ev) => Ok(ev),
            Err(_) => {
                let mut p = self.inner.state.lock().unwrap();
                p.event_waiters.retain(|(i, _, _)| *i != id);
                Err(Error::Timeout("event"))
            }
        }
    }

    /// Send a full L2CAP SDU, fragmenting to controller ACL MTU and respecting buffer credits.
    pub fn send_acl(&self, handle: u16, sdu: &[u8]) -> Result<()> {
        self.wait_credits();
        let mtu = { self.inner.credits.lock().unwrap().mtu.max(27) as usize };
        let mut off = 0;
        let mut first = true;
        loop {
            let n = mtu.min(sdu.len() - off);
            let hf = handle | if first { ACL_PB_START } else { ACL_PB_CONT };
            let mut pkt = Vec::with_capacity(5 + n);
            pkt.push(0x02);
            pkt.extend_from_slice(&hf.to_le_bytes());
            pkt.extend_from_slice(&(n as u16).to_le_bytes());
            pkt.extend_from_slice(&sdu[off..off + n]);
            self.inner.transport.lock().unwrap().send_packet(&pkt)?;
            off += n;
            first = false;
            if off >= sdu.len() { break; }
            self.wait_credits();
        }
        Ok(())
    }

    fn wait_credits(&self) {
        let mut c = self.inner.credits.lock().unwrap();
        if c.set && c.available == 0 {
            let start = Instant::now();
            while c.available == 0 && start.elapsed() < Duration::from_secs(5) {
                let (g, _) = self.inner.credits_cv.wait_timeout(c, Duration::from_millis(100)).unwrap();
                c = g;
            }
            // On timeout we send anyway (some transports don't report credits).
        }
        if c.available > 0 { c.available -= 1; }
    }
}

fn reader_loop(mut transport: Box<dyn HciTransport>, inner: Arc<Inner>) {
    let mut buf = Vec::with_capacity(2048);
    while inner.running.load(Ordering::Relaxed) {
        buf.clear();
        match transport.recv_packet(&mut buf) {
            Ok(_) => process_packet(&inner, &buf),
            Err(Error::Timeout(_)) => continue,
            Err(e) => { eprintln!("[hci] transport closed: {e}"); break; }
        }
    }
}

fn process_packet(inner: &Inner, pkt: &[u8]) {
    match pkt.first() {
        Some(0x04) => {
            if pkt.len() >= 3 {
                let ev = HciEvent { code: pkt[1], params: pkt[3..].to_vec() };
                handle_event(inner, ev);
            }
        }
        Some(0x02) => handle_acl(inner, pkt),
        Some(0x03) => {
            if pkt.len() >= 5 {
                let handle = u16::from_le_bytes([pkt[1], pkt[2]]) & 0x0fff;
                let len = u16::from_le_bytes([pkt[3], pkt[4]]) as usize;
                let data = pkt[5..(5 + len).min(pkt.len())].to_vec();
                if let Some(tx) = inner.sco_tx.lock().unwrap().as_ref() { let _ = tx.send((handle, data)); }
            }
        }
        _ => {}
    }
}

fn handle_event(inner: &Inner, ev: HciEvent) {
    match ev.code {
        ev::COMMAND_COMPLETE => {
            let opcode = ev.u16(2);
            let ret = ev.params[4..].to_vec();
            on_credits(inner, opcode, &ret);
            let waiters = { let mut p = inner.state.lock().unwrap(); p.complete.remove(&opcode).unwrap_or_default() };
            for w in waiters { let _ = w.send(ret.clone()); }
            return;
        }
        ev::COMMAND_STATUS => {
            let status = ev.u8(0);
            let opcode = ev.u16(2);
            let waiters = { let mut p = inner.state.lock().unwrap(); p.status.remove(&opcode).unwrap_or_default() };
            for w in waiters { let _ = w.send(status); }
            return;
        }
        ev::NUMBER_OF_COMPLETED_PACKETS => {
            let n = ev.u8(0) as usize;
            let mut add = 0u32;
            let mut i = 1;
            for _ in 0..n {
                add += ev.u16(i + 2) as u32;
                i += 4;
            }
            let mut c = inner.credits.lock().unwrap();
            c.available = c.available.saturating_add(add);
            inner.credits_cv.notify_all();
            return;
        }
        _ => {}
    }
    let matched: Vec<Sender<HciEvent>> = {
        let mut p = inner.state.lock().unwrap();
        let mut out = Vec::new();
        let mut i = 0;
        while i < p.event_waiters.len() {
            if (p.event_waiters[i].1)(&ev) {
                let (_, _, tx) = p.event_waiters.remove(i).unwrap();
                out.push(tx);
            } else { i += 1; }
        }
        out
    };
    for tx in matched { let _ = tx.send(ev.clone()); }
    if let Some(h) = inner.handler.lock().unwrap().as_ref() { h(ev); }
}

fn on_credits(inner: &Inner, opcode: u16, ret: &[u8]) {
    let mut c = inner.credits.lock().unwrap();
    if opcode == op::READ_BUFFER_SIZE && ret.len() >= 9 && ret[0] == 0 {
        let mtu = u16::from_le_bytes([ret[1], ret[2]]);
        let num = u16::from_le_bytes([ret[5], ret[6]]);
        if num > 0 { *c = Credits { mtu, available: num as u32, set: true }; }
    } else if opcode == op::LE_READ_BUFFER_SIZE && ret.len() >= 4 && ret[0] == 0 && !c.set {
        let mtu = u16::from_le_bytes([ret[1], ret[2]]);
        let num = ret[3];
        if num > 0 { *c = Credits { mtu, available: num as u32, set: true }; }
    }
}

fn handle_acl(inner: &Inner, pkt: &[u8]) {
    if pkt.len() < 5 { return; }
    let hf = u16::from_le_bytes([pkt[1], pkt[2]]);
    let handle = hf & 0x0fff;
    let pb = (hf >> 12) & 0x3;
    let len = u16::from_le_bytes([pkt[3], pkt[4]]) as usize;
    let data = &pkt[5..(5 + len).min(pkt.len())];
    let mut deliver: Option<(u16, Vec<u8>)> = None;
    {
        let mut p = inner.state.lock().unwrap();
        if pb == 0 || pb == 1 {
            if data.len() >= 4 {
                let want = u16::from_le_bytes([data[0], data[1]]) as usize + 4;
                let cid = u16::from_le_bytes([data[2], data[3]]);
                if data.len() == want {
                    deliver = Some((cid, data[4..].to_vec()));
                } else if data.len() < want {
                    p.acl_rx.insert(handle, data.to_vec());
                } else {
                    deliver = Some((cid, data[4..want].to_vec()));
                }
            }
        } else {
            if let Some(buf) = p.acl_rx.get_mut(&handle) {
                buf.extend_from_slice(data);
                if buf.len() >= 4 {
                    let want = u16::from_le_bytes([buf[0], buf[1]]) as usize + 4;
                    if buf.len() == want {
                        let cid = u16::from_le_bytes([buf[2], buf[3]]);
                        deliver = Some((cid, buf[4..].to_vec()));
                    }
                }
            }
            if deliver.is_some() { p.acl_rx.remove(&handle); }
        }
        if deliver.is_some() { p.acl_rx.remove(&handle); }
    }
    if let Some((cid, data)) = deliver {
        if let Some(tx) = inner.acl_tx.lock().unwrap().as_ref() {
            let _ = tx.send(AclSdu { handle, cid, data });
        }
    }
}