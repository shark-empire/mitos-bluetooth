use crate::device::Address;
use crate::error::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const fn opcode(ogf: u16, ocf: u16) -> u16 { ((ogf & 0x3f) << 10) | (ocf & 0x3ff) }

pub mod op {
    use super::opcode;
    pub const INQUIRY: u16 = opcode(0x01, 0x0001);
    pub const INQUIRY_CANCEL: u16 = opcode(0x01, 0x0002);
    pub const CREATE_CONNECTION: u16 = opcode(0x01, 0x0005);
    pub const DISCONNECT: u16 = opcode(0x01, 0x0006);
    pub const CREATE_CONNECTION_CANCEL: u16 = opcode(0x01, 0x0008);
    pub const ACCEPT_CONNECTION_REQUEST: u16 = opcode(0x01, 0x0009);
    pub const REJECT_CONNECTION_REQUEST: u16 = opcode(0x01, 0x000a);
    pub const LINK_KEY_REQUEST_REPLY: u16 = opcode(0x01, 0x000b);
    pub const LINK_KEY_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x000c);
    pub const PIN_CODE_REQUEST_REPLY: u16 = opcode(0x01, 0x000d);
    pub const PIN_CODE_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x000e);
    pub const AUTHENTICATION_REQUESTED: u16 = opcode(0x01, 0x0011);
    pub const SET_CONNECTION_ENCRYPTION: u16 = opcode(0x01, 0x0013);
    pub const REMOTE_NAME_REQUEST: u16 = opcode(0x01, 0x0019);
    pub const READ_REMOTE_SUPPORTED_FEATURES: u16 = opcode(0x01, 0x001b);
    pub const SETUP_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x0028);
    pub const ACCEPT_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x0029);
    pub const REJECT_SYNCHRONOUS_CONNECTION: u16 = opcode(0x01, 0x002a);
    pub const IO_CAPABILITY_REQUEST_REPLY: u16 = opcode(0x01, 0x002b);
    pub const USER_CONFIRMATION_REQUEST_REPLY: u16 = opcode(0x01, 0x002c);
    pub const USER_CONFIRMATION_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x002d);
    pub const USER_PASSKEY_REQUEST_REPLY: u16 = opcode(0x01, 0x002e);
    pub const USER_PASSKEY_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x002f);
    pub const REMOTE_OOB_DATA_REQUEST_NEG_REPLY: u16 = opcode(0x01, 0x0033);
    pub const SET_EVENT_MASK: u16 = opcode(0x03, 0x0001);
    pub const RESET: u16 = opcode(0x03, 0x0003);
    pub const WRITE_LOCAL_NAME: u16 = opcode(0x03, 0x0013);
    pub const WRITE_PAGE_TIMEOUT: u16 = opcode(0x03, 0x0018);
    pub const WRITE_SCAN_ENABLE: u16 = opcode(0x03, 0x001a);
    pub const READ_SCAN_ENABLE: u16 = opcode(0x03, 0x0019);
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
}

/// ACL packet-boundary flags, already shifted into bits 12..13 (Core Vol 4 Part E 5.4.2).
/// Host -> controller: 00 = first fragment (valid for BR/EDR and LE), 01 = continuing fragment.
pub const ACL_PB_START: u16 = 0x0000;
pub const ACL_PB_CONT: u16 = 0x1000;
pub const INQUIRY_LAP_GENERAL: [u8; 3] = [0x33, 0x8b, 0x9e];

#[derive(Clone, Debug)]
pub struct HciEvent {
    pub code: u8,
    pub params: Vec<u8>,
}
impl HciEvent {
    pub fn u8(&self, o: usize) -> u8 {
        self.params.get(o).copied().unwrap_or(0)
    }
    pub fn u16(&self, o: usize) -> u16 {
        u16::from_le_bytes([self.u8(o), self.u8(o + 1)])
    }
    pub fn u32(&self, o: usize) -> u32 {
        u32::from_le_bytes([self.u8(o), self.u8(o + 1), self.u8(o + 2), self.u8(o + 3)])
    }
    pub fn addr(&self, o: usize) -> Address {
        let mut a = [0u8; 6];
        for (i, b) in a.iter_mut().enumerate() {
            *b = self.u8(o + i);
        }
        Address(a)
    }
    pub fn bytes(&self, o: usize, n: usize) -> &[u8] {
        let start = o.min(self.params.len());
        let end = o.saturating_add(n).min(self.params.len());
        &self.params[start..end]
    }
    pub fn le_sub(&self) -> u8 {
        self.params.first().copied().unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct AclSdu { pub handle: u16, pub cid: u16, pub data: Vec<u8> }

/// One H4-framed packet at a time (type byte included).
pub trait HciTransport: Send {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize>;
    fn try_clone(&self) -> Result<Box<dyn HciTransport>>;
    fn name(&self) -> String;
    /// Release the underlying device now (idempotent). Dropping the transport must also release it.
    fn close(&mut self) {}
}

// ---------------- Linux: HCI user-channel socket (exclusive access, H4 framing) ----------------
const HCIDEVDOWN: libc::c_ulong = 0x400448CA;

pub struct LinuxHciSocket { fd: i32 }

impl LinuxHciSocket {
    fn new(fd: i32) -> Self {
        LinuxHciSocket { fd }
    }
    fn close_fd(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own `fd` and never use it again (it is reset to -1 below).
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

impl Drop for LinuxHciSocket {
    fn drop(&mut self) {
        self.close_fd();
    }
}

impl HciTransport for LinuxHciSocket {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < packet.len() {
            // SAFETY: `packet[off..]` is valid for `packet.len() - off` bytes.
            let n = unsafe { libc::write(self.fd, packet[off..].as_ptr() as *const libc::c_void, packet.len() - off) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::Io(e));
            }
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
                Some(libc::EAGAIN) | Some(libc::EINTR) => Error::Timeout("hci recv"), // EWOULDBLOCK == EAGAIN on Linux
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
    fn close(&mut self) { self.close_fd(); }
}

const BTPROTO_HCI: libc::c_int = 1;
const HCI_CHANNEL_USER: u16 = 1; // 0 = raw, 2 = monitor (read-only), 3 = control

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
    let mut last_err = std::io::Error::from_raw_os_error(libc::EBUSY);
    for attempt in 0..8 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
        hci_dev_down(index);
        // SAFETY: plain socket/bind/setsockopt calls on an fd we own; the sockaddr buffer outlives them.
        unsafe {
            let fd = libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI);
            if fd < 0 {
                return Err(Error::PermissionDenied(format!("hci socket: {}", std::io::Error::last_os_error())));
            }
            // struct sockaddr_hci { sa_family_t hci_family; unsigned short hci_dev; unsigned short hci_channel; }
            let mut sa = [0u8; 6];
            sa[0..2].copy_from_slice(&(libc::AF_BLUETOOTH as u16).to_ne_bytes());
            sa[2..4].copy_from_slice(&(index as u16).to_ne_bytes());
            sa[4..6].copy_from_slice(&HCI_CHANNEL_USER.to_ne_bytes());
            if libc::bind(fd, sa.as_ptr() as *const libc::sockaddr, sa.len() as libc::socklen_t) < 0 {
                last_err = std::io::Error::last_os_error();
                libc::close(fd);
                // the controller may still be going down, or bluetoothd raced us: try again
                if matches!(last_err.raw_os_error(), Some(libc::EBUSY) | Some(libc::EAGAIN) | Some(libc::EINTR)) {
                    continue;
                }
                break;
            }
            let tv = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void,
                             std::mem::size_of::<libc::timeval>() as libc::socklen_t);
            return Ok(LinuxHciSocket::new(fd));
        }
    }
    Err(Error::PermissionDenied(format!("bind user channel hci{index}: {last_err}")))
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
/// Raw 8N1 with RTS/CTS. Baud comes from `MITOS_BT_BAUD` (default 115200). Anything that is not a tty
/// (pipes, files, test fixtures) is left untouched.
fn configure_tty(f: &std::fs::File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = f.as_raw_fd();
    // SAFETY: termios is a plain C struct; the calls only touch `fd`, which `f` keeps open.
    unsafe {
        if libc::isatty(fd) != 1 {
            return Ok(());
        }
        let mut tio: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut tio) != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        tio.c_iflag = 0;
        tio.c_oflag = 0;
        tio.c_lflag = 0;
        tio.c_cflag = libc::CS8 | libc::CREAD | libc::CLOCAL | libc::CRTSCTS;
        tio.c_cc[libc::VMIN] = 1;
        tio.c_cc[libc::VTIME] = 0;
        let speed = match std::env::var("MITOS_BT_BAUD").ok().and_then(|v| v.parse::<u32>().ok()) {
            Some(3_000_000) => libc::B3000000,
            Some(921_600) => libc::B921600,
            Some(460_800) => libc::B460800,
            Some(230_400) => libc::B230400,
            Some(57_600) => libc::B57600,
            _ => libc::B115200,
        };
        libc::cfsetispeed(&mut tio, speed);
        libc::cfsetospeed(&mut tio, speed);
        if libc::tcsetattr(fd, libc::TCSANOW, &tio) != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        libc::tcflush(fd, libc::TCIOFLUSH);
    }
    Ok(())
}
pub struct SerialH4 { port: Box<dyn std::io::Read + Send>, writer: Box<dyn std::io::Write + Send>, buf: Vec<u8>, label: String }

impl SerialH4 {
    pub fn open(path: &str) -> Result<Self> {
        let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        configure_tty(&f)?;
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
        Ok(self.writer.flush()?)
    }
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        // H4 stream framing: [type][header][payload]
        loop {
            self.fill(1)?;
            let hdr = match self.buf[0] {
                0x01 => 3, // command: opcode(2) + len(1)
                0x02 => 4, // ACL: handle(2) + len(2)
                0x03 => 3, // SCO: handle(2) + len(1)
                0x04 => 2, // event: code(1) + len(1)
                0x05 => 4, // ISO: handle(2) + len(2, 14 bits)
                _ => {
                    self.buf.remove(0); // not a packet type: resynchronise
                    continue;
                }
            };
            self.fill(1 + hdr)?;
            let len = match self.buf[0] {
                0x01 | 0x03 => usize::from(self.buf[3]),
                0x02 => usize::from(u16::from_le_bytes([self.buf[3], self.buf[4]])),
                0x04 => usize::from(self.buf[2]),
                _ => usize::from(u16::from_le_bytes([self.buf[3], self.buf[4]]) & 0x3fff),
            };
            let total = 1 + hdr + len;
            self.fill(total)?;
            out.clear();
            out.extend_from_slice(&self.buf[..total]);
            self.buf.drain(..total);
            return Ok(total);
        }
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
/// Decides whether an event is the one a caller waits for. Runs on the reader thread: keep it tiny, never block.
pub type EventPredicate = Box<dyn Fn(&HciEvent) -> bool + Send>;
/// Receives every event that is not a command completion. Runs on the reader thread.
pub type EventHandler = Box<dyn Fn(HciEvent) + Send>;
pub type ScoSender = Sender<(u16, Vec<u8>)>;

struct PendState {
    complete: HashMap<u16, Vec<Sender<Vec<u8>>>>,
    status: HashMap<u16, Vec<Sender<u8>>>,
    event_waiters: VecDeque<(u64, EventPredicate, Sender<HciEvent>)>,
    acl_rx: HashMap<u16, Vec<u8>>,
}

/// Controller ACL buffer accounting (Core Vol 4 Part E 4.1.1, host-to-controller data flow control).
struct Credits {
    mtu: u16,
    /// LE ACL packet length when the controller has dedicated LE buffers (0 = LE shares the BR/EDR ones).
    le_mtu: u16,
    total: u32,
    available: u32,
    set: bool,
    /// Packets handed to the controller per connection and not yet reported as completed.
    in_flight: HashMap<u16, u32>,
}

struct Inner {
    transport: Mutex<Box<dyn HciTransport>>,
    state: Mutex<PendState>,
    cmd_lock: Mutex<()>,
    credits: Mutex<Credits>,
    credits_cv: Condvar,
    handler: Mutex<Option<EventHandler>>,
    acl_tx: Mutex<Option<Sender<AclSdu>>>,
    sco_tx: Mutex<Option<ScoSender>>,
    running: AtomicBool,
    next_event_id: AtomicU64,
}

pub struct HciClient {
    index: u32,
    inner: Arc<Inner>,
    cmd_timeout: Duration,
}

/// A registered interest in one HCI event. Create it *before* sending the command that provokes the
/// event, so the event cannot slip past between "command sent" and "start waiting".
/// Dropping an unused waiter deregisters it.
pub struct EventWaiter {
    id: u64,
    rx: Receiver<HciEvent>,
    inner: Arc<Inner>,
}

impl EventWaiter {
    pub fn wait(self, timeout: Duration) -> Result<HciEvent> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(ev),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout("event")),
            Err(RecvTimeoutError::Disconnected) => Err(Error::TransportClosed),
        }
    }
}

impl Drop for EventWaiter {
    fn drop(&mut self) {
        let id = self.id;
        self.inner.state.lock().unwrap().event_waiters.retain(|(i, _, _)| *i != id);
    }
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
        let reader_transport = transport.try_clone()?;
        let inner = Arc::new(Inner {
            transport: Mutex::new(transport),
            state: Mutex::new(PendState {
                complete: HashMap::new(),
                status: HashMap::new(),
                event_waiters: VecDeque::new(),
                acl_rx: HashMap::new(),
            }),
            cmd_lock: Mutex::new(()),
            credits: Mutex::new(Credits { mtu: 27, le_mtu: 0, total: 8, available: 8, set: false, in_flight: HashMap::new() }),
            credits_cv: Condvar::new(),
            handler: Mutex::new(None),
            acl_tx: Mutex::new(None),
            sco_tx: Mutex::new(None),
            running: AtomicBool::new(true),
            next_event_id: AtomicU64::new(1),
        });
        let reader_inner = inner.clone();
        let _reader = std::thread::Builder::new()
            .name(format!("hci{index}-reader"))
            .spawn(move || reader_loop(reader_transport, reader_inner))?;
        Ok(HciClient { index, inner, cmd_timeout: Duration::from_secs(5) })
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Stop the reader, release the controller and drop every handler so that the threads (and `Arc`
    /// cycles) built on top of this client unwind. Safe to call more than once.
    pub fn shutdown(&self) {
        teardown(&self.inner);
    }

    pub fn set_event_handler(&self, f: EventHandler) {
        *self.inner.handler.lock().unwrap() = Some(f);
    }

    pub fn set_acl_handler(&self, tx: Sender<AclSdu>) {
        *self.inner.acl_tx.lock().unwrap() = Some(tx);
    }

    pub fn set_sco_handler(&self, tx: ScoSender) {
        *self.inner.sco_tx.lock().unwrap() = Some(tx);
    }

    /// HCI SCO data packet: handle(2) + length(1) + data (Core Vol 4 Part E 5.4.3).
    pub fn send_sco(&self, handle: u16, data: &[u8]) -> Result<()> {
        if data.len() > 255 {
            return Err(Error::InvalidArgument("sco packet longer than 255 bytes".into()));
        }
        let mut pkt = Vec::with_capacity(4 + data.len());
        pkt.push(0x03);
        pkt.extend_from_slice(&handle.to_le_bytes());
        pkt.push(data.len() as u8);
        pkt.extend_from_slice(data);
        self.inner.transport.lock().unwrap().send_packet(&pkt)
    }

    /// Send a command and wait for its Command Complete; returns the return parameters (status byte first).
    pub fn command(&self, opcode: u16, params: &[u8]) -> Result<Vec<u8>> {
        if !self.is_running() {
            return Err(Error::TransportClosed);
        }
        let _one_at_a_time = self.inner.cmd_lock.lock().unwrap();
        let (tx, rx) = channel();
        self.inner.state.lock().unwrap().complete.entry(opcode).or_default().push(tx);
        let sent = self.inner.transport.lock().unwrap().send_packet(&hci_cmd_buf(opcode, params));
        if let Err(e) = sent {
            self.inner.state.lock().unwrap().complete.remove(&opcode);
            return Err(e);
        }
        match rx.recv_timeout(self.cmd_timeout) {
            Ok(r) if r.is_empty() => Err(Error::TransportClosed),
            Ok(r) if r[0] != 0 => Err(Error::Hci { opcode, status: r[0] }),
            Ok(r) => Ok(r),
            Err(_) => {
                self.inner.state.lock().unwrap().complete.remove(&opcode);
                Err(Error::Timeout("command complete"))
            }
        }
    }

    /// Send a command whose result arrives as Command Status (the real outcome comes in a later event).
    pub fn command_status(&self, opcode: u16, params: &[u8]) -> Result<()> {
        if !self.is_running() {
            return Err(Error::TransportClosed);
        }
        let _one_at_a_time = self.inner.cmd_lock.lock().unwrap();
        let (tx, rx) = channel();
        self.inner.state.lock().unwrap().status.entry(opcode).or_default().push(tx);
        let sent = self.inner.transport.lock().unwrap().send_packet(&hci_cmd_buf(opcode, params));
        if let Err(e) = sent {
            self.inner.state.lock().unwrap().status.remove(&opcode);
            return Err(e);
        }
        match rx.recv_timeout(self.cmd_timeout) {
            Ok(0) => Ok(()),
            Ok(status) => Err(Error::Hci { opcode, status }),
            Err(_) => {
                self.inner.state.lock().unwrap().status.remove(&opcode);
                Err(Error::Timeout("command status"))
            }
        }
    }

    /// Register for the first future event accepted by `pred`.
    pub fn expect_event<F>(&self, pred: F) -> EventWaiter
    where
        F: Fn(&HciEvent) -> bool + Send + 'static,
    {
        let (tx, rx) = channel();
        let id = self.inner.next_event_id.fetch_add(1, Ordering::Relaxed);
        self.inner.state.lock().unwrap().event_waiters.push_back((id, Box::new(pred), tx));
        EventWaiter { id, rx, inner: self.inner.clone() }
    }

    /// Wait for the next event accepted by `pred`. Only events that arrive *after* this call are seen:
    /// when the event is provoked by a command, use `expect_event` before sending the command.
    pub fn wait_event<F>(&self, pred: F, timeout: Duration) -> Result<HciEvent>
    where
        F: Fn(&HciEvent) -> bool + Send + 'static,
    {
        self.expect_event(pred).wait(timeout)
    }

    /// Fragment `sdu` into controller-sized ACL packets and send them, honouring the controller's buffer credits.
    pub fn send_acl(&self, handle: u16, le: bool, sdu: &[u8]) -> Result<()> {
        if !self.is_running() {
            return Err(Error::TransportClosed);
        }
        let mtu = {
            let c = self.inner.credits.lock().unwrap();
            let m = if le && c.le_mtu > 0 { c.le_mtu } else { c.mtu };
            usize::from(m.max(27))
        };
        let mut off = 0;
        let mut first = true;
        loop {
            self.take_credit(handle);
            let n = mtu.min(sdu.len() - off);
            let flags = handle | if first { ACL_PB_START } else { ACL_PB_CONT };
            let mut pkt = Vec::with_capacity(5 + n);
            pkt.push(0x02);
            pkt.extend_from_slice(&flags.to_le_bytes());
            pkt.extend_from_slice(&(n as u16).to_le_bytes());
            pkt.extend_from_slice(&sdu[off..off + n]);
            self.inner.transport.lock().unwrap().send_packet(&pkt)?;
            off += n;
            first = false;
            if off >= sdu.len() {
                return Ok(());
            }
        }
    }

    /// Reserve one controller buffer for `handle` (blocks up to 5 s while the controller is full).
    fn take_credit(&self, handle: u16) {
        let mut c = self.inner.credits.lock().unwrap();
        if c.set && c.available == 0 {
            let start = Instant::now();
            while c.available == 0 && start.elapsed() < Duration::from_secs(5) && self.is_running() {
                let (guard, _) = self.inner.credits_cv.wait_timeout(c, Duration::from_millis(100)).unwrap();
                c = guard;
            }
        }
        if c.available > 0 {
            c.available -= 1;
            *c.in_flight.entry(handle).or_insert(0) += 1;
        }
    }
}

impl Drop for HciClient {
    fn drop(&mut self) {
        teardown(&self.inner);
    }
}

/// Release everything that keeps the controller (and the threads above it) alive.
fn teardown(inner: &Inner) {
    inner.running.store(false, Ordering::Relaxed);
    inner.transport.lock().unwrap().close();
    *inner.handler.lock().unwrap() = None;
    *inner.acl_tx.lock().unwrap() = None;
    *inner.sco_tx.lock().unwrap() = None;
    {
        let mut p = inner.state.lock().unwrap();
        p.complete.clear();
        p.status.clear();
        p.event_waiters.clear();
        p.acl_rx.clear();
    }
    inner.credits_cv.notify_all();
}

fn reader_loop(mut transport: Box<dyn HciTransport>, inner: Arc<Inner>) {
    let mut buf = Vec::with_capacity(2048);
    while inner.running.load(Ordering::Relaxed) {
        buf.clear();
        match transport.recv_packet(&mut buf) {
            Ok(_) => process_packet(&inner, &buf),
            Err(Error::Timeout(_)) => continue,
            Err(e) => {
                if inner.running.load(Ordering::Relaxed) {
                    eprintln!("[hci] transport closed: {e}");
                }
                break;
            }
        }
    }
    // controller gone, or we were shut down: fail everything that is still waiting
    teardown(&inner);
}

fn process_packet(inner: &Inner, pkt: &[u8]) {
    match pkt.first() {
        Some(0x04) if pkt.len() >= 3 => {
            handle_event(inner, HciEvent { code: pkt[1], params: pkt[3..].to_vec() });
        }
        Some(0x02) => handle_acl(inner, pkt),
        Some(0x03) if pkt.len() >= 4 => {
            let handle = u16::from_le_bytes([pkt[1], pkt[2]]) & 0x0fff;
            let end = (4 + usize::from(pkt[3])).min(pkt.len());
            if let Some(tx) = inner.sco_tx.lock().unwrap().as_ref() {
                let _ = tx.send((handle, pkt[4..end].to_vec()));
            }
        }
        _ => {}
    }
}

/// The controller reported the connection gone: forget its partial PDU and give back its buffers.
fn release_handle(inner: &Inner, handle: u16) {
    inner.state.lock().unwrap().acl_rx.remove(&handle);
    let mut c = inner.credits.lock().unwrap();
    if let Some(n) = c.in_flight.remove(&handle) {
        c.available = c.available.saturating_add(n).min(c.total);
        inner.credits_cv.notify_all();
    }
}

fn handle_event(inner: &Inner, ev: HciEvent) {
    match ev.code {
        ev::COMMAND_COMPLETE => {
            let opcode = ev.u16(1);
            let ret = ev.params.get(3..).unwrap_or(&[]).to_vec();
            on_credits(inner, opcode, &ret);
            let waiters = inner.state.lock().unwrap().complete.remove(&opcode).unwrap_or_default();
            for w in waiters {
                let _ = w.send(ret.clone());
            }
            return;
        }
        ev::COMMAND_STATUS => {
            let opcode = ev.u16(2);
            let status = ev.u8(0);
            let waiters = inner.state.lock().unwrap().status.remove(&opcode).unwrap_or_default();
            for w in waiters {
                let _ = w.send(status);
            }
            return;
        }
        ev::NUMBER_OF_COMPLETED_PACKETS => {
            // [num_handles][handle(2) count(2)] * num_handles
            let n = usize::from(ev.u8(0));
            let mut c = inner.credits.lock().unwrap();
            for k in 0..n {
                let handle = ev.u16(1 + 4 * k) & 0x0fff;
                let count = u32::from(ev.u16(3 + 4 * k));
                let done = match c.in_flight.get_mut(&handle) {
                    Some(flying) => {
                        let d = count.min(*flying);
                        *flying -= d;
                        d
                    }
                    None => 0,
                };
                c.available = c.available.saturating_add(done).min(c.total);
            }
            inner.credits_cv.notify_all();
            return;
        }
        ev::DISCONNECTION_COMPLETE if ev.u8(0) == 0 => release_handle(inner, ev.u16(1) & 0x0fff),
        _ => {}
    }
    // wake whoever registered for this event
    let matched: Vec<Sender<HciEvent>> = {
        let mut p = inner.state.lock().unwrap();
        let mut hit = Vec::new();
        let mut i = 0;
        while i < p.event_waiters.len() {
            if (p.event_waiters[i].1)(&ev) {
                if let Some((_, _, tx)) = p.event_waiters.remove(i) {
                    hit.push(tx);
                }
            } else {
                i += 1;
            }
        }
        hit
    };
    for tx in matched {
        let _ = tx.send(ev.clone());
    }
    if let Some(h) = inner.handler.lock().unwrap().as_ref() {
        h(ev);
    }
}

fn on_credits(inner: &Inner, opcode: u16, ret: &[u8]) {
    let mut c = inner.credits.lock().unwrap();
    if opcode == op::READ_BUFFER_SIZE && ret.len() >= 8 && ret[0] == 0 {
        // status(1) acl_len(2) sco_len(1) acl_packets(2) sco_packets(2)
        let mtu = u16::from_le_bytes([ret[1], ret[2]]);
        let num = u16::from_le_bytes([ret[4], ret[5]]);
        if num > 0 && mtu > 0 {
            c.mtu = mtu;
            c.total = u32::from(num);
            c.available = u32::from(num);
            c.set = true;
            c.in_flight.clear();
        }
    } else if opcode == op::LE_READ_BUFFER_SIZE && ret.len() >= 4 && ret[0] == 0 {
        // status(1) le_acl_len(2) le_acl_packets(1); zero means "shared with BR/EDR"
        let mtu = u16::from_le_bytes([ret[1], ret[2]]);
        let num = ret[3];
        if num > 0 && mtu > 0 {
            c.le_mtu = mtu;
            if !c.set {
                c.mtu = mtu;
                c.total = u32::from(num);
                c.available = u32::from(num);
                c.set = true;
            }
        }
    }
}

fn handle_acl(inner: &Inner, pkt: &[u8]) {
    if pkt.len() < 5 {
        return;
    }
    let flags = u16::from_le_bytes([pkt[1], pkt[2]]);
    let handle = flags & 0x0fff;
    let pb = (flags >> 12) & 0x3;
    let len = usize::from(u16::from_le_bytes([pkt[3], pkt[4]]));
    let data = &pkt[5..(5 + len).min(pkt.len())];
    let mut deliver: Option<(u16, Vec<u8>)> = None;
    {
        let mut p = inner.state.lock().unwrap();
        if pb != 0b01 {
            // first (or only) fragment of an L2CAP PDU: 00, 10 or 11
            p.acl_rx.remove(&handle);
            if data.len() >= 4 {
                let want = usize::from(u16::from_le_bytes([data[0], data[1]])) + 4;
                let cid = u16::from_le_bytes([data[2], data[3]]);
                if data.len() < want {
                    p.acl_rx.insert(handle, data.to_vec());
                } else {
                    deliver = Some((cid, data[4..want].to_vec()));
                }
            }
        } else if let Some(buf) = p.acl_rx.get_mut(&handle) {
            // continuing fragment (01)
            buf.extend_from_slice(data);
            let want = usize::from(u16::from_le_bytes([buf[0], buf[1]])) + 4;
            if buf.len() >= want {
                let cid = u16::from_le_bytes([buf[2], buf[3]]);
                deliver = Some((cid, buf[4..want].to_vec()));
                p.acl_rx.remove(&handle);
            }
        }
    }
    if let Some((cid, data)) = deliver {
        if let Some(tx) = inner.acl_tx.lock().unwrap().as_ref() {
            let _ = tx.send(AclSdu { handle, cid, data });
        }
    }
}

// ---------------- Mock controller (tests, CI, offline development) ----------------
// Implements enough of HCI to drive the full manager stack without hardware:
// command completion/status, scripted follow-up events, a complete SSP pairing chain
// (link key request -> IO cap -> user confirmation -> notification), re-authentication with a
// stored key, and "Number of Completed Packets" for every ACL packet the host sends.

pub struct MockTransport {
    state: Arc<Mutex<MockState>>,
}

#[derive(Default)]
pub struct MockState {
    outbox: VecDeque<(Instant, Vec<u8>)>, // packets to the host, with a ready-at time
    sent: Vec<Vec<u8>>,                   // commands received from the host
    acl_sent: Vec<Vec<u8>>,               // ACL packets received from the host
    handles: HashMap<u16, [u8; 6]>,
    next_handle: u16,
}

impl MockTransport {
    pub fn new() -> Self {
        MockTransport { state: Arc::new(Mutex::new(MockState { next_handle: 1, ..Default::default() })) }
    }
    /// Shared handle for assertions and event injection from tests.
    pub fn shared(&self) -> Arc<Mutex<MockState>> {
        self.state.clone()
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockState {
    pub fn sent_commands(&self) -> Vec<Vec<u8>> {
        self.sent.clone()
    }
    /// Every ACL packet (H4 type byte included) the host has sent so far.
    pub fn acl_packets(&self) -> Vec<Vec<u8>> {
        self.acl_sent.clone()
    }
    /// Inject a raw H4 packet (event 0x04, ACL 0x02, ...) for the host to receive.
    pub fn inject_event(&mut self, event: Vec<u8>) {
        self.outbox.push_back((Instant::now(), event));
    }
}

impl HciTransport for MockTransport {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        match packet.first() {
            Some(0x01) if packet.len() >= 4 => {
                let opcode = u16::from_le_bytes([packet[1], packet[2]]);
                st.sent.push(packet.to_vec());
                mock_on_command(&mut st, opcode, &packet[4..]);
            }
            Some(0x02) if packet.len() >= 5 => {
                let handle = u16::from_le_bytes([packet[1], packet[2]]) & 0x0fff;
                st.acl_sent.push(packet.to_vec());
                // the controller hands the buffer back as soon as it has "transmitted" the packet
                let done = mock_ev(ev::NUMBER_OF_COMPLETED_PACKETS, &[1, handle as u8, (handle >> 8) as u8, 1, 0]);
                st.outbox.push_back((Instant::now(), done));
            }
            _ => {}
        }
        Ok(())
    }
    fn recv_packet(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            {
                let mut st = self.state.lock().unwrap();
                if let Some((at, _)) = st.outbox.front() {
                    if *at <= Instant::now() {
                        let (_, pkt) = st.outbox.pop_front().unwrap();
                        out.clear();
                        out.extend_from_slice(&pkt);
                        return Ok(pkt.len());
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout("mock recv"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn try_clone(&self) -> Result<Box<dyn HciTransport>> {
        Ok(Box::new(MockTransport { state: self.state.clone() }))
    }
    fn name(&self) -> String {
        "mock".into()
    }
}

fn mock_cc(opcode: u16, ret: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04, 0x0E, (3 + ret.len()) as u8, 0x01];
    v.extend_from_slice(&opcode.to_le_bytes());
    v.extend_from_slice(ret);
    v
}

fn mock_cs(opcode: u16) -> Vec<u8> {
    vec![0x04, 0x0F, 0x04, 0x00, 0x01, opcode as u8, (opcode >> 8) as u8]
}

fn mock_ev(code: u8, params: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04, code, params.len() as u8];
    v.extend_from_slice(params);
    v
}

fn mock_on_command(st: &mut MockState, opcode: u16, params: &[u8]) {
    let addr_param = params.get(0..6).map(<[u8; 6]>::try_from).and_then(|r| r.ok());
    let t = |ms: u64| Instant::now() + Duration::from_millis(ms);

    // 1. immediate completion
    let status_cmds = [
        op::INQUIRY,
        op::CREATE_CONNECTION,
        op::DISCONNECT,
        op::ACCEPT_CONNECTION_REQUEST,
        op::REJECT_CONNECTION_REQUEST,
        op::REMOTE_NAME_REQUEST,
        op::AUTHENTICATION_REQUESTED,
        op::SET_CONNECTION_ENCRYPTION,
        op::LE_CREATE_CONNECTION,
        op::LE_START_ENCRYPTION,
        op::SETUP_SYNCHRONOUS_CONNECTION,
        op::ACCEPT_SYNCHRONOUS_CONNECTION,
        op::REJECT_SYNCHRONOUS_CONNECTION,
        op::READ_REMOTE_SUPPORTED_FEATURES,
    ];
    if status_cmds.contains(&opcode) {
        st.outbox.push_back((t(0), mock_cs(opcode)));
    } else {
        let ret: Vec<u8> = match opcode {
            op::READ_BD_ADDR => vec![0x00, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            op::READ_LOCAL_VERSION => vec![0x00, 0x0B, 0x00, 0x00, 0x09, 0x0F, 0x00, 0x00, 0x00],
            // status + 8 LMP feature bytes of a typical dual-mode controller (byte 4 bit 6 = LE supported)
            op::READ_LOCAL_SUPPORTED_FEATURES => vec![0x00, 0xFF, 0xFE, 0x8F, 0xFE, 0xD8, 0x3F, 0x5B, 0x87],
            // status, ACL length 1021, SCO length 96, 8 ACL packets, 8 SCO packets
            op::READ_BUFFER_SIZE => vec![0x00, 0xFD, 0x03, 0x60, 0x08, 0x00, 0x08, 0x00],
            // status, LE ACL length 251, 8 packets
            op::LE_READ_BUFFER_SIZE => vec![0x00, 0xFB, 0x00, 0x08],
            _ => vec![0x00],
        };
        st.outbox.push_back((t(0), mock_cc(opcode, &ret)));
    }

    // 2. scripted follow-ups
    match opcode {
        op::CREATE_CONNECTION | op::ACCEPT_CONNECTION_REQUEST => {
            if let Some(addr) = addr_param {
                let handle = st.next_handle;
                st.next_handle += 1;
                st.handles.insert(handle, addr);
                let mut p = vec![0x00]; // status
                p.extend_from_slice(&handle.to_le_bytes());
                p.extend_from_slice(&addr);
                p.push(0x01); // link type: ACL
                p.push(0x00); // not encrypted
                st.outbox.push_back((t(50), mock_ev(0x03, &p))); // Connection Complete
            }
        }
        op::DISCONNECT => {
            if params.len() >= 2 {
                let handle = u16::from_le_bytes([params[0], params[1]]);
                st.handles.remove(&handle);
                let mut p = vec![0x00];
                p.extend_from_slice(&handle.to_le_bytes());
                p.push(0x13);
                st.outbox.push_back((t(50), mock_ev(0x05, &p))); // Disconnection Complete
            }
        }
        op::SET_CONNECTION_ENCRYPTION => {
            if params.len() >= 2 {
                let handle = u16::from_le_bytes([params[0], params[1]]);
                st.outbox.push_back((t(50), mock_ev(0x08, &[0x00, handle as u8, (handle >> 8) as u8, 0x01])));
            }
        }
        op::AUTHENTICATION_REQUESTED => {
            if params.len() >= 2 {
                let handle = u16::from_le_bytes([params[0], params[1]]);
                if let Some(addr) = st.handles.get(&handle).copied() {
                    st.outbox.push_back((t(20), mock_ev(0x17, &addr))); // Link Key Request
                }
            }
        }
        op::LINK_KEY_REQUEST_NEG_REPLY => {
            if let Some(addr) = addr_param {
                st.outbox.push_back((t(20), mock_ev(0x31, &addr))); // IO Capability Request
            }
        }
        op::LINK_KEY_REQUEST_REPLY => {
            // the stored key was accepted: authentication of the link completes
            if let Some(addr) = addr_param {
                let handle = st.handles.iter().find(|(_, a)| **a == addr).map(|(h, _)| *h);
                if let Some(h) = handle {
                    st.outbox.push_back((t(20), mock_ev(ev::AUTHENTICATION_COMPLETE, &[0x00, h as u8, (h >> 8) as u8])));
                }
            }
        }
        op::IO_CAPABILITY_REQUEST_REPLY => {
            if let Some(addr) = addr_param {
                let mut p = addr.to_vec();
                p.extend_from_slice(&123456u32.to_le_bytes());
                st.outbox.push_back((t(20), mock_ev(0x33, &p))); // User Confirmation Request
            }
        }
        op::USER_CONFIRMATION_REQUEST_REPLY => {
            if let Some(addr) = addr_param {
                let mut sp = vec![0x00];
                sp.extend_from_slice(&addr);
                st.outbox.push_back((t(20), mock_ev(0x36, &sp))); // Simple Pairing Complete
                let mut lk = addr.to_vec();
                lk.extend_from_slice(&[0x11u8; 16]); // the "link key"
                lk.push(0x05); // authenticated combination key
                st.outbox.push_back((t(20), mock_ev(0x18, &lk))); // Link Key Notification
            }
        }
        op::REMOTE_NAME_REQUEST => {
            if let Some(addr) = addr_param {
                let mut p = vec![0x00];
                p.extend_from_slice(&addr);
                let mut name = b"Mock Keyboard\0".to_vec();
                name.resize(248, 0);
                p.extend_from_slice(&name);
                st.outbox.push_back((t(50), mock_ev(0x07, &p)));
            }
        }
        op::READ_REMOTE_SUPPORTED_FEATURES => {
            if params.len() >= 2 {
                let handle = u16::from_le_bytes([params[0], params[1]]);
                let mut p = vec![0x00]; // status = success
                p.extend_from_slice(&handle.to_le_bytes());
                p.extend_from_slice(&[0xBF, 0xFF, 0xFE, 0x02, 0x00, 0x00, 0x00, 0x00]); // feature bitmask
                st.outbox.push_back((t(50), mock_ev(ev::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE, &p)));
            }
        }
        op::INQUIRY => {
            let addr = [0x66, 0x55, 0x44, 0x33, 0x22, 0x12];
            let mut eir = vec![0x0E, 0x09]; // len 14, complete local name
            eir.extend_from_slice(b"Mock Keyboard");
            eir.resize(240, 0);
            let mut p = vec![0x01];
            p.extend_from_slice(&addr);
            p.push(0x02);
            p.push(0x00);
            p.extend_from_slice(&[0x40, 0x05, 0x00]); // CoD 0x0540 = keyboard
            p.extend_from_slice(&0u16.to_le_bytes());
            p.push(0xC4); // RSSI = -60
            p.extend_from_slice(&eir);
            st.outbox.push_back((t(80), mock_ev(0x2F, &p))); // Extended Inquiry Result
            st.outbox.push_back((t(200), mock_ev(0x01, &[0x00]))); // Inquiry Complete
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_match_the_core_spec() {
        // (OGF << 10) | OCF, copied from Bluetooth Core Vol 4 Part E section 7. The mock controller shares these
        // constants with the stack, so only literals like these can catch a wrong number.
        assert_eq!(op::INQUIRY, 0x0401);
        assert_eq!(op::INQUIRY_CANCEL, 0x0402);
        assert_eq!(op::CREATE_CONNECTION, 0x0405);
        assert_eq!(op::DISCONNECT, 0x0406);
        assert_eq!(op::CREATE_CONNECTION_CANCEL, 0x0408);
        assert_eq!(op::ACCEPT_CONNECTION_REQUEST, 0x0409);
        assert_eq!(op::REJECT_CONNECTION_REQUEST, 0x040A);
        assert_eq!(op::LINK_KEY_REQUEST_REPLY, 0x040B);
        assert_eq!(op::LINK_KEY_REQUEST_NEG_REPLY, 0x040C);
        assert_eq!(op::PIN_CODE_REQUEST_REPLY, 0x040D);
        assert_eq!(op::PIN_CODE_REQUEST_NEG_REPLY, 0x040E);
        assert_eq!(op::AUTHENTICATION_REQUESTED, 0x0411);
        assert_eq!(op::SET_CONNECTION_ENCRYPTION, 0x0413);
        assert_eq!(op::REMOTE_NAME_REQUEST, 0x0419);
        assert_eq!(op::READ_REMOTE_SUPPORTED_FEATURES, 0x041B);
        assert_eq!(op::SETUP_SYNCHRONOUS_CONNECTION, 0x0428);
        assert_eq!(op::ACCEPT_SYNCHRONOUS_CONNECTION, 0x0429);
        assert_eq!(op::REJECT_SYNCHRONOUS_CONNECTION, 0x042A);
        assert_eq!(op::IO_CAPABILITY_REQUEST_REPLY, 0x042B);
        assert_eq!(op::USER_CONFIRMATION_REQUEST_REPLY, 0x042C);
        assert_eq!(op::USER_CONFIRMATION_REQUEST_NEG_REPLY, 0x042D);
        assert_eq!(op::USER_PASSKEY_REQUEST_REPLY, 0x042E);
        assert_eq!(op::USER_PASSKEY_REQUEST_NEG_REPLY, 0x042F);
        assert_eq!(op::REMOTE_OOB_DATA_REQUEST_NEG_REPLY, 0x0433);
        assert_eq!(op::SET_EVENT_MASK, 0x0C01);
        assert_eq!(op::RESET, 0x0C03);
        assert_eq!(op::WRITE_LOCAL_NAME, 0x0C13);
        assert_eq!(op::WRITE_PAGE_TIMEOUT, 0x0C18);
        assert_eq!(op::READ_SCAN_ENABLE, 0x0C19);
        assert_eq!(op::WRITE_SCAN_ENABLE, 0x0C1A);
        assert_eq!(op::WRITE_CLASS_OF_DEVICE, 0x0C24);
        assert_eq!(op::WRITE_INQUIRY_MODE, 0x0C45);
        assert_eq!(op::WRITE_EXTENDED_INQUIRY_RESPONSE, 0x0C52);
        assert_eq!(op::WRITE_SIMPLE_PAIRING_MODE, 0x0C56);
        assert_eq!(op::WRITE_LE_HOST_SUPPORT, 0x0C6D);
        assert_eq!(op::READ_LOCAL_VERSION, 0x1001);
        assert_eq!(op::READ_LOCAL_SUPPORTED_FEATURES, 0x1003);
        assert_eq!(op::READ_BUFFER_SIZE, 0x1005);
        assert_eq!(op::READ_BD_ADDR, 0x1009);
        assert_eq!(op::LE_READ_BUFFER_SIZE, 0x2002);
        assert_eq!(op::LE_SET_SCAN_PARAMETERS, 0x200B);
        assert_eq!(op::LE_SET_SCAN_ENABLE, 0x200C);
        assert_eq!(op::LE_CREATE_CONNECTION, 0x200D);
        assert_eq!(op::LE_CREATE_CONNECTION_CANCEL, 0x200E);
        assert_eq!(op::LE_START_ENCRYPTION, 0x2019);
        assert_eq!(op::LE_LTK_REQUEST_REPLY, 0x201A);
        assert_eq!(op::LE_LTK_REQUEST_NEG_REPLY, 0x201B);
    }

    #[test]
    fn short_events_never_panic() {
        let e = HciEvent { code: ev::CONNECTION_COMPLETE, params: vec![0x00, 0x01] };
        assert_eq!(e.u16(1), 1);
        assert_eq!(e.addr(3), Address([0; 6]));
        assert_eq!(e.u32(100), 0);
        assert!(e.bytes(50, 4).is_empty());
    }

    #[test]
    fn acl_is_fragmented_with_spec_pb_flags() {
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = HciClient::open(0, Box::new(mock)).unwrap();
        let sdu: Vec<u8> = (0..60u8).collect();
        hci.send_acl(0x0001, false, &sdu).unwrap();
        let sent = shared.lock().unwrap().acl_packets();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0][..5], [0x02, 0x01, 0x00, 27, 0]); // handle 1, PB=00 first fragment, 27 bytes
        assert_eq!(sent[1][..5], [0x02, 0x01, 0x10, 27, 0]); // PB=01 continuing fragment
        assert_eq!(sent[2][..5], [0x02, 0x01, 0x10, 6, 0]);
        let payload: Vec<u8> = sent.iter().flat_map(|p| p[5..].iter().copied()).collect();
        assert_eq!(payload, sdu);
        hci.shutdown();
    }

    #[test]
    fn acl_is_reassembled_from_start_and_continuing_fragments() {
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = HciClient::open(0, Box::new(mock)).unwrap();
        let (tx, rx) = channel();
        hci.set_acl_handler(tx);
        // L2CAP PDU: length 6, CID 0x0040, payload 1..=6, split into 6 + 4 bytes
        let pdu = [0x06, 0x00, 0x40, 0x00, 1, 2, 3, 4, 5, 6];
        let mut first = vec![0x02, 0x01, 0x20, 6, 0]; // handle 1, PB=10 (start, as controllers send it)
        first.extend_from_slice(&pdu[..6]);
        let mut rest = vec![0x02, 0x01, 0x10, 4, 0]; // PB=01 (continuing)
        rest.extend_from_slice(&pdu[6..]);
        shared.lock().unwrap().inject_event(first);
        shared.lock().unwrap().inject_event(rest);
        let sdu = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!((sdu.handle, sdu.cid), (1, 0x0040));
        assert_eq!(sdu.data, vec![1, 2, 3, 4, 5, 6]);
        hci.shutdown();
    }

    #[test]
    fn events_before_the_waiter_exists_are_not_replayed() {
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = HciClient::open(0, Box::new(mock)).unwrap();
        shared.lock().unwrap().inject_event(mock_ev(ev::INQUIRY_COMPLETE, &[0x00]));
        std::thread::sleep(Duration::from_millis(100));
        // a stale event must not satisfy a later wait ...
        let stale = hci.wait_event(|e| e.code == ev::INQUIRY_COMPLETE, Duration::from_millis(150));
        assert!(matches!(stale, Err(Error::Timeout(_))));
        // ... but a waiter registered first sees the event even if it arrives before wait() is called
        let waiter = hci.expect_event(|e| e.code == ev::INQUIRY_COMPLETE);
        shared.lock().unwrap().inject_event(mock_ev(ev::INQUIRY_COMPLETE, &[0x00]));
        std::thread::sleep(Duration::from_millis(100));
        assert!(waiter.wait(Duration::from_secs(1)).is_ok());
        hci.shutdown();
    }
}
