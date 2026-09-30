use crate::device::{Address, DeviceId, DeviceTable};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus};
use crate::hci::{op, HciClient, HciEvent};
use crate::l2cap::{L2Packet, L2cap, PSM_AVCTP, PSM_AVDTP};
use crate::rfcomm::RfcommClient;
use crate::sdp::SdpClient;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};

const UUID_HFP_HF: u16 = 0x111e; // headset advertising the Handsfree role
const UUID_HSP_HS: u16 = 0x1108; // headset advertising the Headset role
const AG_FEATURES: u32 = 0xC2;   // EC/NR + enhanced call status/control + extended error codes

mod avdtp {
    pub const DISCOVER: u8 = 0x01;
    pub const GET_CAPABILITIES: u8 = 0x02;
    pub const SET_CONFIGURATION: u8 = 0x03;
    pub const OPEN: u8 = 0x06;
    pub const START: u8 = 0x07;
    pub const CLOSE: u8 = 0x08;
    pub const SUSPEND: u8 = 0x09;
    pub const CAT_MEDIA_TRANSPORT: u8 = 0x01;
    pub const CAT_MEDIA_CODEC: u8 = 0x08;
}

// AVDTP media packets: [1-byte media packet header (0x00 = single/unfragmented)][RTP][payload].
// Some sinks accept raw RTP without the leading byte — if a sink drops all audio, flip this.
const PREPEND_MEDIA_HEADER: bool = true;
// SCO/eSCO parameters (CVSD, 16-bit 2's-complement host samples, best-effort eSCO)
const SCO_TX_BW: u32 = 16000;
const SCO_MAX_LATENCY: u16 = 0xFFFF;
const VOICE_SETTING: u16 = 0x0060;
const SCO_RETX: u8 = 0x02;
const SCO_PKT_TYPES: u16 = 0x03FF;

// ===================== negotiated SBC configuration =====================

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SbcConfig {
    pub frequency: u8,   // one-hot: 0x80=16k, 0x40=32k, 0x20=44.1k, 0x10=48k
    pub mode: u8,        // 0x08=mono, 0x04=dual, 0x02=stereo, 0x01=joint
    pub blocks: u8,      // 0x80=4, 0x40=8, 0x20=12, 0x10=16
    pub subbands: u8,    // 0x08=4, 0x04=8
    pub allocation: u8,  // 0x02=loudness, 0x01=snr
    pub bitpool: u8,
    pub min_bp: u8,
}

impl SbcConfig {
    pub fn samples_per_frame(&self) -> u32 {
        let blocks = match self.blocks { 0x80 => 4, 0x40 => 8, 0x20 => 12, _ => 16 };
        let sub = if self.subbands == 0x08 { 4 } else { 8 };
        (blocks * sub) as u32
    }
    pub fn config_bytes(&self) -> [u8; 4] {
        [self.frequency | self.mode, self.blocks | self.subbands | self.allocation, self.min_bp, self.bitpool]
    }
    /// Choose a configuration from the sink's 4-byte SBC capabilities.
    pub fn pick(caps: &[u8; 4]) -> Option<SbcConfig> {
        let frequency = if caps[0] & 0x20 != 0 { 0x20 } else if caps[0] & 0x10 != 0 { 0x10 }
                        else if caps[0] & 0x40 != 0 { 0x40 } else if caps[0] & 0x80 != 0 { 0x80 } else { return None };
        let mode = if caps[0] & 0x01 != 0 { 0x01 } else if caps[0] & 0x02 != 0 { 0x02 }
                   else if caps[0] & 0x08 != 0 { 0x08 } else if caps[0] & 0x04 != 0 { 0x04 } else { return None };
        let blocks = if caps[1] & 0x10 != 0 { 0x10 } else if caps[1] & 0x80 != 0 { 0x80 }
                     else if caps[1] & 0x40 != 0 { 0x40 } else if caps[1] & 0x20 != 0 { 0x20 } else { return None };
        let subbands = if caps[1] & 0x04 != 0 { 0x04 } else if caps[1] & 0x08 != 0 { 0x08 } else { return None };
        let allocation = if caps[1] & 0x02 != 0 { 0x02 } else if caps[1] & 0x01 != 0 { 0x01 } else { return None };
        let (min_bp, max_bp) = (caps[2], caps[3]);
        let bitpool = if min_bp <= max_bp { 53u8.clamp(min_bp, max_bp) } else { max_bp };
        Some(SbcConfig { frequency, mode, blocks, subbands, allocation, bitpool, min_bp })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct A2dpInfo {
    pub started: bool,
    pub config: SbcConfig,
    pub mtu: u16,
    pub max_packet_payload: u16, // mtu - RTP overhead: the encoder's budget per media packet
    pub delay_ms: Option<u32>,
    pub socket_path: Option<String>,
}

// ===================== sessions =====================

pub struct AudioSession {
    pub conn_handle: u16,
    pub a2dp: Option<A2dpSession>,
    pub avrcp: Option<AvrcpSession>,
    pub hfp: Option<HfpSession>,
    pub sco_handle: Option<u16>,
}
pub struct A2dpSession {
    pub sig: Sender<SigMsg>,
    pub sig_cid: u16,
    pub media_cid: u16,
    pub seid: u8,
    pub cfg: SbcConfig,
    pub started: bool,
    pub seq: u16,
    pub ts: u32,
    pub ssrc: u32,
    pub delay_ms: Arc<Mutex<Option<u32>>>,   // sink-reported render delay (AVDTP Delay Report)
    pub sock: Option<Arc<BinSock>>,          // per-speaker media socket (created on start)
    pub socket_path: Option<String>,
}
pub struct AvrcpSession { pub cid: u16, pub ctl: Sender<AvrMsg> }
pub struct HfpSession { pub cid: u16, pub is_hsp: bool, pub volume: u8, pub mic_volume: u8 }

// ===================== small binary-socket helper =====================
// Protocol: [2-byte BE length][payload], both directions. Used by the A2DP and SCO bridges.

pub struct BinSock {
    clients: Mutex<Vec<UnixStream>>,
    running: AtomicBool,
    path: String,
}

impl BinSock {
    fn start(path: String, on_rx: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<Self> {
        let sock = Arc::new(BinSock { clients: Mutex::new(Vec::new()),
                                      running: AtomicBool::new(true), path: path.clone() });
        let s = sock.clone();
        std::thread::spawn(move || {
            let _ = std::fs::remove_file(&path);
            if let Ok(listener) = UnixListener::bind(&s.path) {
                let _ = listener.set_nonblocking(true);
                println!("[audio] serving {}", s.path);
                while s.running.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((c, _)) => {
                            if let Ok(bc) = c.try_clone() { s.clients.lock().unwrap().push(bc); }
                            let on = on_rx.clone();
                            std::thread::spawn(move || {
                                let mut c = c;
                                loop {
                                    let mut len = [0u8; 2];
                                    if c.read_exact(&mut len).is_err() { break; }
                                    let n = u16::from_be_bytes(len) as usize;
                                    let mut buf = vec![0u8; n];
                                    if n > 0 && c.read_exact(&mut buf).is_err() { break; }
                                    on(&buf);
                                }
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(200)),
                        Err(_) => break,
                    }
                }
                let _ = std::fs::remove_file(&s.path);
            }
        });
        sock
    }
    fn stop(&self) { self.running.store(false, Ordering::Relaxed); }
    fn broadcast(&self, data: &[u8]) {
        let mut msg = Vec::with_capacity(data.len() + 2);
        msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        msg.extend_from_slice(data);
        let mut cs = self.clients.lock().unwrap();
        cs.retain_mut(|c| c.write_all(&msg).and_then(|_| c.flush()).is_ok());
    }
}

// ===================== manager =====================

pub struct AudioManager {
    pub hci: Arc<HciClient>,
    pub l2: Arc<L2cap>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    st: Arc<Mutex<HashMap<DeviceId, AudioSession>>>,
    #[allow(dead_code)]
    a2dp_sock: Arc<BinSock>,
    #[allow(dead_code)]
    sco_sock: Arc<BinSock>,
}

impl AudioManager {
    pub fn new(hci: Arc<HciClient>, l2: Arc<L2cap>, devices: Arc<DeviceTable>, bus: Arc<EventBus>) -> Arc<Self> {
        let st: Arc<Mutex<HashMap<DeviceId, AudioSession>>> = Arc::new(Mutex::new(HashMap::new()));
        let a2dp_path = std::env::var("MITOS_A2DP_SOCK").unwrap_or_else(|_| "/tmp/mitos-bluetooth-a2dp.sock".into());
        let sco_path = std::env::var("MITOS_SCO_SOCK").unwrap_or_else(|_| "/tmp/mitos-bluetooth-sco.sock".into());

        // A2DP media socket: message = [frame count u8][SBC frames for one RTP packet]
        let l2c = l2.clone();
        let stc = st.clone();
        let a2dp_on: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |data: &[u8]| {
            if data.is_empty() { return; }
            let nframes = data[0] as u32;
            let frames = &data[1..];
            let mut st = stc.lock().unwrap();
            for s in st.values_mut() {
                if let Some(a) = s.a2dp.as_mut() {
                    if a.started { let _ = send_media_packet(&l2c, a, frames, nframes); break; }
                }
            }
        });
        let a2dp_sock = BinSock::start(a2dp_path, a2dp_on);

        // SCO socket: client -> controller (raw PCM) / controller -> client
        let hcic = hci.clone();
        let stc2 = st.clone();
        let sco_on: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |data: &[u8]| {
            let h = stc2.lock().unwrap().values().find_map(|s| s.sco_handle);
            if let Some(h) = h { let _ = hcic.send_sco(h, data); }
        });
        let sco_sock = BinSock::start(sco_path, sco_on);
        let (sctx, scrx) = channel::<(u16, Vec<u8>)>();
        hci.set_sco_handler(sctx);
        let bc = sco_sock.clone();
        std::thread::spawn(move || {
            while let Ok((_h, d)) = scrx.recv() { bc.broadcast(&d); }
        });

        Arc::new(AudioManager { hci, l2, devices, bus, st, a2dp_sock, sco_sock })
    }

    /// Look up (or create) a device's session within an *already-locked* map, so the
    /// returned `&mut AudioSession` borrows from the caller's own guard rather than one
    /// local to this function (which would be dropped before the reference could be used).
    fn session_entry<'a>(st: &'a mut HashMap<DeviceId, AudioSession>, device: &DeviceId, handle: u16) -> &'a mut AudioSession {
        st.entry(*device).or_insert_with(|| AudioSession { conn_handle: handle, a2dp: None, avrcp: None, hfp: None, sco_handle: None })
    }

    // ===================== A2DP (AVDTP source role) =====================

    pub fn connect_a2dp(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        let sig_cid = self.l2.connect(handle, PSM_AVDTP)?;
        let delay_ms = Arc::new(Mutex::new(None));
        let sig = spawn_sig_actor(self.l2.clone(), sig_cid, delay_ms.clone());
        // 1. find a free audio sink endpoint
        let seps = avdtp_cmd(&sig, avdtp::DISCOVER, &[])?;
        let mut seid = None;
        for pair in seps.chunks(2) {
            if pair.len() < 2 { break; }
            let in_use = pair[0] & 0x02 != 0;
            let media_type = pair[1] >> 4;
            let tsep = pair[1] & 0x0F;
            if media_type == 0 && tsep == 1 && !in_use { seid = Some(pair[0] >> 2); break; }
        }
        let seid = seid.ok_or_else(|| Error::NotSupported("no available audio sink endpoint".into()))?;
        // 2. SBC capabilities
        let caps = avdtp_cmd(&sig, avdtp::GET_CAPABILITIES, &[seid << 2])?;
        let sbc_caps = parse_sbc_caps(&caps).ok_or_else(|| Error::NotSupported("sink does not support SBC".into()))?;
        let cfg = SbcConfig::pick(&sbc_caps).ok_or_else(|| Error::NotSupported("no usable SBC configuration".into()))?;
        // 3. configure + open
        let mut p = vec![seid << 2, 1 << 2]; // ACP SEID, our (INT) SEID
        p.extend_from_slice(&[avdtp::CAT_MEDIA_TRANSPORT, 0x00]);
        if caps_has_category(&caps, 0x0B) {
            p.extend_from_slice(&[0x0B, 0x00]); // Delay Reporting — mitos-audio's latency input
        }
        p.extend_from_slice(&[avdtp::CAT_MEDIA_CODEC, 0x05, 0x00]); // audio/SBC
        p.extend_from_slice(&cfg.config_bytes());
        
        avdtp_cmd(&sig, avdtp::SET_CONFIGURATION, &p)?;
        avdtp_cmd(&sig, avdtp::OPEN, &[seid << 2])?;
        // 4. media transport channel (second L2CAP connection to the same PSM)
        let media_cid = self.l2.connect(handle, PSM_AVDTP)?;
        let mut ssrc = [0u8; 4];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") { let _ = f.read_exact(&mut ssrc); }
        let mut guard = self.st.lock().unwrap();
        let s = Self::session_entry(&mut guard, device, handle);
        s.a2dp = Some(A2dpSession {
            sig, sig_cid, media_cid, seid, cfg,
            started: false, seq: 0, ts: 0, ssrc: u32::from_le_bytes(ssrc),
            delay_ms, sock: None, socket_path: None,
        });
        self.bus.publish(Event::A2dpStateChanged { id: *device, state: "open".into() });
        Ok(())
    }

      pub fn a2dp_start(&self, device: &DeviceId) -> Result<()> {
        let (sig, seid) = {
            let st = self.st.lock().unwrap();
            let a = st.get(device).and_then(|s| s.a2dp.as_ref()).ok_or_else(|| Error::InvalidState("a2dp not connected".into()))?;
            (a.sig.clone(), a.seid)
        };
        avdtp_cmd(&sig, avdtp::START, &[seid << 2])?;
        let socket_path;
        {
            let mut st = self.st.lock().unwrap();
            let a = st.get_mut(device).and_then(|s| s.a2dp.as_mut())
                .ok_or_else(|| Error::InvalidState("a2dp not connected".into()))?;
            a.started = true;
            if a.sock.is_none() {
                // one media socket per speaker — this is the multi-speaker fan-out path
                let dir = std::env::var("MITOS_A2DP_SOCK_DIR").unwrap_or_else(|_| "/tmp".into());
                let path = format!("{dir}/mitos-bluetooth-a2dp-{}.sock", device.address.to_string().replace(':', "-"));
                let l2c = self.l2.clone();
                let stc = self.st.clone();
                let dev = *device;
                let on: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |data: &[u8]| {
                    if data.is_empty() { return; }
                    let nframes = data[0] as u32;
                    let frames = &data[1..];
                    if let Some(a) = stc.lock().unwrap().get_mut(&dev).and_then(|s| s.a2dp.as_mut()) {
                        let _ = send_media_packet(&l2c, a, frames, nframes);
                    }
                });
                a.sock = Some(BinSock::start(path.clone(), on));
                a.socket_path = Some(path);
            }
            socket_path = a.socket_path.clone();
        }
        self.bus.publish(Event::A2dpStateChanged { id: *device, state: "started".into() });
        if let Some(p) = socket_path { self.bus.publish(Event::A2dpStreamReady { id: *device, socket_path: p }); }
        Ok(())
    }

        pub fn a2dp_suspend(&self, device: &DeviceId) -> Result<()> {
        let (sig, seid) = {
            let st = self.st.lock().unwrap();
            let a = st.get(device).and_then(|s| s.a2dp.as_ref()).ok_or_else(|| Error::InvalidState("a2dp not connected".into()))?;
            (a.sig.clone(), a.seid)
        };
        avdtp_cmd(&sig, avdtp::SUSPEND, &[seid << 2])?;
        {
            let mut st = self.st.lock().unwrap();
            if let Some(a) = st.get_mut(device).and_then(|s| s.a2dp.as_mut()) {
                a.started = false;
                if let Some(sock) = a.sock.take() { sock.stop(); }
                a.socket_path = None;
            }
        }
        self.bus.publish(Event::A2dpStateChanged { id: *device, state: "suspended".into() });
        Ok(())
    }

    /// Negotiated state — the encoder must match `config` and stay within `max_packet_payload`.
        pub fn a2dp_info(&self, device: &DeviceId) -> Option<A2dpInfo> {
        let st = self.st.lock().unwrap();
        let a = st.get(device)?.a2dp.as_ref()?;
        let mtu = self.l2.remote_mtu(a.media_cid);
        let info = Some(A2dpInfo {
            started: a.started, config: a.cfg, mtu,
            max_packet_payload: mtu.saturating_sub(13 + PREPEND_MEDIA_HEADER as u16),
            delay_ms: *a.delay_ms.lock().unwrap(),
            socket_path: a.socket_path.clone(),
        });
        info
    }

    /// Send pre-encoded SBC frames (one RTP packet's worth). `nframes` advances RTP timestamps.
    pub fn a2dp_send_sbc(&self, device: &DeviceId, frames: &[u8], nframes: u32) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        let a = st.get_mut(device).and_then(|s| s.a2dp.as_mut())
            .ok_or_else(|| Error::InvalidState("a2dp not connected".into()))?;
        send_media_packet(&self.l2, a, frames, nframes)
    }

    // ===================== AVRCP =====================

    pub fn connect_avrcp(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        let cid = self.l2.connect(handle, PSM_AVCTP)?;
        let ctl = spawn_avrcp_actor(self.l2.clone(), cid, *device, self.bus.clone());
        let mut guard = self.st.lock().unwrap();
        let s = Self::session_entry(&mut guard, device, handle);
        s.avrcp = Some(AvrcpSession { cid, ctl });
        Ok(())
    }

    pub fn avrcp_passthrough(&self, device: &DeviceId, op: u8) -> Result<()> {
        let ctl = {
            let st = self.st.lock().unwrap();
            st.get(device).and_then(|s| s.avrcp.as_ref()).map(|v| v.ctl.clone())
                .ok_or_else(|| Error::InvalidState("avrcp not connected".into()))?
        };
        let (tx, rx) = channel();
        ctl.send(AvrMsg::Cmd(AvrcpCmd { avc: vec![0x7C, 0x48, op, 0x00], reply: Some(tx) }))
            .map_err(|_| Error::InvalidState("avrcp session gone".into()))?;
        rx.recv_timeout(Duration::from_secs(5))??;
        Ok(())
    }

    /// Absolute volume, 0-127 (AVRCP 1.4+).
    pub fn set_absolute_volume(&self, device: &DeviceId, volume: u8) -> Result<()> {
        let ctl = {
            let st = self.st.lock().unwrap();
            st.get(device).and_then(|s| s.avrcp.as_ref()).map(|v| v.ctl.clone())
                .ok_or_else(|| Error::InvalidState("avrcp not connected".into()))?
        };
        let v = volume.min(127);
        let (tx, rx) = channel();
        let avc = vec![0x00, 0x48, 0x00, 0x19, 0x58, 0x19, 0x00, 0x00, 0x01, v];
        ctl.send(AvrMsg::Cmd(AvrcpCmd { avc, reply: Some(tx) }))
            .map_err(|_| Error::InvalidState("avrcp session gone".into()))?;
        rx.recv_timeout(Duration::from_secs(5))??;
        Ok(())
    }

    // ===================== HFP / HSP (Audio Gateway role) =====================

    pub fn connect_hfp(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        self.connect_hf(device, handle, UUID_HFP_HF, false)
    }
    pub fn connect_hsp(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        self.connect_hf(device, handle, UUID_HSP_HS, true)
    }

    fn connect_hf(self: &Arc<Self>, device: &DeviceId, handle: u16, uuid: u16, is_hsp: bool) -> Result<()> {
        let mut sdp = SdpClient::connect(self.l2.clone(), handle)?;
        let svc = sdp.query(uuid)?;
        let ch = svc.rfcomm_channel.ok_or_else(|| Error::NotSupported("no RFCOMM channel in SDP record".into()))?;
        let rf = RfcommClient::connect(self.l2.clone(), handle, ch)?;
        let cid = rf.cid;
        let l2 = self.l2.clone();
        let bus = self.bus.clone();
        let st = self.st.clone();
        let dev = *device;
        std::thread::Builder::new().name("hfp-at".into()).spawn(move || {
            let mut buf: Vec<u8> = Vec::new();
            loop {
                match rf.recv_timeout(Duration::from_secs(1)) {
                    Ok(data) => {
                        buf.extend_from_slice(&data);
                        while let Some(pos) = buf.iter().position(|&b| b == b'\r') {
                            let line: Vec<u8> = buf.drain(..=pos).collect();
                            handle_at(&rf, &l2, &bus, &st, &dev, &line[..line.len() - 1]);
                        }
                    }
                    Err(_) => if rf.is_closed() { break } else { continue },
                }
            }
            st.lock().unwrap().get_mut(&dev).and_then(|s| s.hfp.take());
        }).ok();
        let mut guard = self.st.lock().unwrap();
        let s = Self::session_entry(&mut guard, device, handle);
        s.hfp = Some(HfpSession { cid, is_hsp, volume: 9, mic_volume: 9 });
        Ok(())
    }

    // ===================== SCO / eSCO =====================

    /// We initiate the voice connection (HCI Setup Synchronous Connection on the ACL handle).
    pub fn hfp_connect_sco(&self, device: &DeviceId) -> Result<()> {
        let h = { self.st.lock().unwrap().get(device).map(|s| s.conn_handle)
            .ok_or_else(|| Error::InvalidState("no audio session".into()))? };
        let mut p = h.to_le_bytes().to_vec();
        p.extend_from_slice(&SCO_TX_BW.to_le_bytes());
        p.extend_from_slice(&SCO_TX_BW.to_le_bytes());
        p.extend_from_slice(&SCO_MAX_LATENCY.to_le_bytes());
        p.extend_from_slice(&VOICE_SETTING.to_le_bytes());
        p.push(SCO_RETX);
        p.extend_from_slice(&SCO_PKT_TYPES.to_le_bytes());
        self.hci.command_status(op::SETUP_SYNCHRONOUS_CONNECTION, &p)
    }

    pub fn hfp_disconnect_sco(&self, device: &DeviceId) -> Result<()> {
        let h = { self.st.lock().unwrap().get(device).and_then(|s| s.sco_handle)
            .ok_or_else(|| Error::InvalidState("no SCO connection".into()))? };
        let mut p = h.to_le_bytes().to_vec();
        p.push(0x13);
        self.hci.command_status(op::DISCONNECT, &p)
    }

    /// Called by ConnectionManager when the *device* initiates a SCO connection.
    pub fn accept_sync(&self, addr: &Address) -> bool {
        let found = { self.st.lock().unwrap().iter().any(|(id, s)| id.address == *addr && s.hfp.is_some()) };
        if !found { return false; }
        let mut p = addr.0.to_vec();
        p.extend_from_slice(&SCO_TX_BW.to_le_bytes());
        p.extend_from_slice(&SCO_TX_BW.to_le_bytes());
        p.extend_from_slice(&SCO_MAX_LATENCY.to_le_bytes());
        p.extend_from_slice(&VOICE_SETTING.to_le_bytes());
        p.push(SCO_RETX);
        p.extend_from_slice(&SCO_PKT_TYPES.to_le_bytes());
        self.hci.command_status(op::ACCEPT_SYNCHRONOUS_CONNECTION, &p).is_ok()
    }

    /// Called from the adapter dispatch thread.
    pub fn on_sco_complete(&self, ev: &HciEvent) {
        let status = ev.u8(0);
        let handle = ev.u16(1);
        let addr = ev.addr(3);
        let dev = { self.st.lock().unwrap().keys().find(|id| id.address == addr).copied() };
        if let Some(id) = dev {
            if status == 0 {
                if let Some(s) = self.st.lock().unwrap().get_mut(&id) { s.sco_handle = Some(handle); }
                self.bus.publish(Event::ScoStateChanged { id, connected: true });
            } else {
                eprintln!("[audio] SCO connection failed: status 0x{status:02x}");
                self.bus.publish(Event::ScoStateChanged { id, connected: false });
            }
        }
    }

    // ===================== teardown =====================

    pub fn disconnect(&self, device: &DeviceId) -> Result<()> {
        let session = self.st.lock().unwrap().remove(device);
        if let Some(mut s) = session {
            if let Some(mut a) = s.a2dp.take() {
                if let Some(sock) = a.sock.take() { sock.stop(); }
                let _ = avdtp_cmd(&a.sig, avdtp::CLOSE, &[a.seid << 2]);
                let _ = self.l2.disconnect(a.media_cid);
                let _ = self.l2.disconnect(a.sig_cid);
            }
            if let Some(v) = s.avrcp.take() { let _ = self.l2.disconnect(v.cid); }
            if let Some(h) = s.hfp.take() { let _ = self.l2.disconnect(h.cid); }
            if let Some(h) = s.sco_handle.take() {
                let mut p = h.to_le_bytes().to_vec();
                p.push(0x13);
                let _ = self.hci.command_status(op::DISCONNECT, &p);
            }
        }
        Ok(())
    }
}

// ===================== AVDTP internals =====================

struct SigCmd { signal: u8, payload: Vec<u8>, reply: Sender<Result<Vec<u8>>> }
pub enum SigMsg { Cmd(SigCmd), Pkt(L2Packet) }

/// Sequential AVDTP signaling actor per session: matches responses by transaction label.
fn spawn_sig_actor(l2: Arc<L2cap>, cid: u16, delay_ms: Arc<Mutex<Option<u32>>>) -> Sender<SigMsg> {
    let (mux_tx, mux_rx) = channel::<SigMsg>();
    let (ptx, prx) = channel::<L2Packet>();
    l2.register_handler(cid, ptx);
    let ftx = mux_tx.clone();
    std::thread::spawn(move || while let Ok(p) = prx.recv() { let _ = ftx.send(SigMsg::Pkt(p)); });
    std::thread::Builder::new().name("avdtp".into()).spawn(move || {
        let mut tl: u8 = 0;
        let mut waiting: Option<(u8, Sender<Result<Vec<u8>>>)> = None;
        while let Ok(m) = mux_rx.recv() {
            match m {
                SigMsg::Pkt(p) => {
                    if p.closed { break; }
                    let d = &p.data;
                    if d.len() < 2 { continue; }
                    let t = d[0] >> 4;
                    let mt = d[0] & 0x03;
                    if let Some((wtl, reply)) = waiting.take() {
                        if t == wtl {
                            let body = d[2..].to_vec();
                            if mt == 2 { let _ = reply.send(Ok(body)); }
                            else if mt == 3 {
                                let _ = reply.send(Err(Error::ConnectionFailed(
                                    format!("avdtp reject: code 0x{:02x}", body.first().copied().unwrap_or(0)))));
                            } else { waiting = Some((wtl, reply)); }
                            continue;
                        }
                        waiting = Some((wtl, reply));
                    }
                    // commands from the sink (message type 0)
                    if mt == 0 {
                        let signal = d[1] >> 2;
                        if signal == 0x0D && d.len() >= 5 {
                            // DELAYREPORT: [seid<<2][delay u16, tenths of ms]
                            let tenths = u16::from_be_bytes([d[3], d[4]]);
                            *delay_ms.lock().unwrap() = Some(tenths as u32 / 10);
                            let _ = l2.send(cid, &[(t << 4) | 0x02, 0x0D << 2]); // accept
                        } else {
                            // unknown sink command -> reject (error 0x01)
                            let _ = l2.send(cid, &[(t << 4) | 0x03, signal << 2, 0x01]);
                        }
                    }
                }
                SigMsg::Cmd(c) => {
                    if waiting.is_some() { let _ = c.reply.send(Err(Error::InvalidState("avdtp busy".into()))); continue; }
                    tl = (tl + 1) & 0x0F;
                    let mut pkt = vec![(tl << 4) | 0x00, c.signal << 2];
                    pkt.extend_from_slice(&c.payload);
                    if l2.send(cid, &pkt).is_ok() { waiting = Some((tl, c.reply)); }
                    else { let _ = c.reply.send(Err(Error::TransportClosed)); }
                }
            }
        }
    }).ok();
    mux_tx
}

fn avdtp_cmd(sig: &Sender<SigMsg>, signal: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let (tx, rx) = channel();
    sig.send(SigMsg::Cmd(SigCmd { signal, payload: payload.to_vec(), reply: tx }))
        .map_err(|_| Error::InvalidState("avdtp session gone".into()))?;
    rx.recv_timeout(Duration::from_secs(5))?
}

/// Find the SBC media-codec capability in a GET_CAPABILITIES response: [cat][len][data]...
fn parse_sbc_caps(payload: &[u8]) -> Option<[u8; 4]> {
    let mut i = 0;
    while i + 2 <= payload.len() {
        let cat = payload[i];
        let len = payload[i + 1] as usize;
        if cat == avdtp::CAT_MEDIA_CODEC && len >= 5 && i + 2 + len <= payload.len() && payload[i + 2] == 0x00 {
            return Some([payload[i + 3], payload[i + 4], payload[i + 5], payload[i + 6]]);
        }
        i += 2 + len;
    }
    None
}

fn caps_has_category(payload: &[u8], cat: u8) -> bool {
    let mut i = 0;
    while i + 2 <= payload.len() {
        let c = payload[i];
        let l = payload[i + 1] as usize;
        if c == cat { return true; }
        i += 2 + l;
    }
    false
}


/// Wrap pre-encoded SBC frames in RTP and send on the media channel.
fn send_media_packet(l2: &L2cap, a: &mut A2dpSession, frames: &[u8], nframes: u32) -> Result<()> {
    if !a.started { return Err(Error::InvalidState("stream not started".into())); }
    let mut pkt = Vec::with_capacity(14 + frames.len());
    if PREPEND_MEDIA_HEADER { pkt.push(0x00); }
    pkt.extend_from_slice(&[0x80, 0x60]); // RTP v2, PT=96 (dynamic), marker=0
    pkt.extend_from_slice(&a.seq.to_be_bytes());
    pkt.extend_from_slice(&a.ts.to_be_bytes());
    pkt.extend_from_slice(&a.ssrc.to_be_bytes());
    pkt.extend_from_slice(frames);
    let mtu = l2.remote_mtu(a.media_cid);
    if pkt.len() > mtu as usize {
        return Err(Error::InvalidArgument(format!(
            "media packet {} bytes > sink MTU {mtu}; send fewer frames per packet", pkt.len())));
    }
    l2.send(a.media_cid, &pkt)?;
    a.seq = a.seq.wrapping_add(1);
    a.ts = a.ts.wrapping_add(nframes.saturating_mul(a.cfg.samples_per_frame()));
    Ok(())
}

// ===================== AVRCP internals =====================

struct AvrcpCmd { avc: Vec<u8>, reply: Option<Sender<Result<Vec<u8>>>> }
pub enum AvrMsg { Cmd(AvrcpCmd), Pkt(L2Packet) }

/// AVRCP controller actor. Handles: command/response matching by transaction label,
/// VOLUME_CHANGED notifications (interim + final, with re-registration), and answers
/// incoming device commands with AV/C "not implemented".
fn spawn_avrcp_actor(l2: Arc<L2cap>, cid: u16, device: DeviceId, bus: Arc<EventBus>) -> Sender<AvrMsg> {
    let (mux_tx, mux_rx) = channel::<AvrMsg>();
    let (ptx, prx) = channel::<L2Packet>();
    l2.register_handler(cid, ptx);
    let ftx = mux_tx.clone();
    std::thread::spawn(move || while let Ok(p) = prx.recv() { let _ = ftx.send(AvrMsg::Pkt(p)); });
    std::thread::Builder::new().name("avrcp".into()).spawn(move || {
        let mut tl: u8 = 0;
        let mut waiting: Option<(u8, Sender<Result<Vec<u8>>>)> = None;
        let mut notify_tl: Option<u8> = None;
        let send_avctp = |tl: u8, cr: bool, avc: &[u8]| -> Result<()> {
            let mut pkt = vec![(tl << 4) | ((cr as u8) << 1), 0x48];
            pkt.extend_from_slice(avc);
            l2.send(cid, &pkt)
        };
        let register = |tl: &mut u8, notify_tl: &mut Option<u8>| {
            let t = (*tl + 1) & 0x0F;
            *tl = t;
            // RegisterNotification(VOLUME_CHANGED): vendor PDU 0x31, event id 0x0D
            let reg = [0x00u8, 0x48, 0x00, 0x19, 0x58, 0x31, 0x00, 0x00, 0x01, 0x0D];
            if send_avctp(t, false, &reg).is_ok() { *notify_tl = Some(t); }
        };
        register(&mut tl, &mut notify_tl); // initial subscription
        while let Ok(m) = mux_rx.recv() {
            match m {
                AvrMsg::Pkt(p) => {
                    if p.closed { break; }
                    let d = &p.data;
                    if d.len() < 3 { continue; }
                    let t = d[0] >> 4;
                    let cr = (d[0] >> 1) & 1;
                    let avc = &d[2..]; // skip profile identifier
                                        if cr == 0 {
                        // incoming command from the device
                        if avc.len() >= 4 && avc[0] == 0x7C && avc[1] == 0x48 {
                            // PASSTHROUGH: a button pressed on the speaker
                            let op = avc[2];
                            let dlen = avc[3] as usize;
                            let state = avc.get(4).copied().unwrap_or(0x00);
                            if dlen == 0 || state == 0x00 { // press (not release)
                            if let Some(name) = avrcp_op_name(op) {
                                    bus.publish(Event::MediaCommand { id: device, command: name.to_string() });
                                }
                            }
                            let _ = send_avctp(t, true, &[0x09, 0x48, op, avc[3]]); // ACCEPTED
                        } else if avc.len() >= 2 {
                            let _ = send_avctp(t, true, &[0x08, avc[1]]); // NOT IMPLEMENTED
                        }
                        continue;
                    }
                    let status = avc.first().copied().unwrap_or(0);
                    // VOLUME_CHANGED notification response?
                    if notify_tl == Some(t) && avc.len() >= 10
                        && avc[2] == 0x00 && avc[3] == 0x19 && avc[4] == 0x58 && avc[5] == 0x31 {
                        if let Some(v) = avc.get(9) {
                            bus.publish(Event::AudioVolumeChanged { id: device, volume: v & 0x7F });
                        }
                        if status != 0x0F {
                            // final (volume changed) -> re-register
                            notify_tl = None;
                            register(&mut tl, &mut notify_tl);
                        } // interim: keep waiting for the final on this label
                        continue;
                    }
                    if let Some((wtl, reply)) = waiting.take() {
                        if t == wtl {
                            let _ = reply.send(if matches!(status, 0x09 | 0x0C | 0x0F) { Ok(avc.to_vec()) }
                                else { Err(Error::ConnectionFailed(format!("avrcp rejected: status 0x{status:02x}"))) });
                            continue;
                        }
                        waiting = Some((wtl, reply));
                    }
                }
                AvrMsg::Cmd(c) => {
                    if waiting.is_some() {
                        if let Some(r) = c.reply { let _ = r.send(Err(Error::InvalidState("avrcp busy".into()))); }
                        continue;
                    }
                    loop { tl = (tl + 1) & 0x0F; if Some(tl) != notify_tl { break; } }
                    if send_avctp(tl, false, &c.avc).is_ok() {
                        if let Some(r) = c.reply { waiting = Some((tl, r)); }
                    } else if let Some(r) = c.reply {
                        let _ = r.send(Err(Error::TransportClosed));
                    }
                }
            }
        }
    }).ok();
    mux_tx
}

/// Map a friendly name to an AVRCP PASSTHROUGH opcode.
pub fn avrcp_op(name: &str) -> Option<u8> {
    match name {
        "play" => Some(0x44), "stop" => Some(0x45), "pause" => Some(0x46),
        "next" => Some(0x4B), "prev" => Some(0x4C),
        "volup" => Some(0x41), "voldown" => Some(0x42), "mute" => Some(0x43),
        _ => None,
    }
}

/// Inverse of `avrcp_op`: opcode -> friendly name (used for MediaCommand events).
pub fn avrcp_op_name(op: u8) -> Option<&'static str> {
    match op {
        0x44 => Some("play"), 0x45 => Some("stop"), 0x46 => Some("pause"),
        0x4B => Some("next"), 0x4C => Some("prev"),
        0x41 => Some("volup"), 0x42 => Some("voldown"), 0x43 => Some("mute"),
        0x48 => Some("fastforward"), 0x49 => Some("rewind"),
        _ => None,
    }
}

// ===================== HFP AT command handling (AG side) =====================

fn at_ok(rf: &RfcommClient, l2: &L2cap, extra: Option<&str>) {
    let mut r = Vec::new();
    if let Some(e) = extra { r.extend_from_slice(format!("\r\n{e}\r\n").as_bytes()); }
    r.extend_from_slice(b"\r\nOK\r\n");
    let _ = rf.send(l2, &r);
}
fn at_err(rf: &RfcommClient, l2: &L2cap) { let _ = rf.send(l2, b"\r\nERROR\r\n"); }

fn handle_at(
    rf: &RfcommClient, l2: &L2cap, bus: &Arc<EventBus>,
    st: &Arc<Mutex<HashMap<DeviceId, AudioSession>>>, device: &DeviceId, line: &[u8],
) {
    let l = String::from_utf8_lossy(line).trim().to_string();
    if l.is_empty() { return; }
    if let Some(_hf_features) = l.strip_prefix("AT+BRSF=") {
        at_ok(rf, l2, Some(&format!("+BRSF: {AG_FEATURES}")));
    } else if l == "AT+CIND=?" {
        at_ok(rf, l2, Some("+CIND: (\"service\",(0,1)),(\"call\",(0,1)),(\"callsetup\",(0,3)),(\"callheld\",(0,2)),(\"signal\",(0,5)),(\"roam\",(0,1)),(\"battchg\",(0,5))"));
    } else if l == "AT+CIND?" {
        at_ok(rf, l2, Some("+CIND: 1,0,0,0,5,0,5"));
    } else if l == "AT+CHLD=?" {
        at_ok(rf, l2, Some("+CHLD: (0,1,2,3)"));
    } else if let Some(v) = l.strip_prefix("AT+VGS=") { // headset speaker volume (0-15)
        match v.trim().parse::<u8>() {
            Ok(n) => {
                let n = n.min(15);
                if let Some(s) = st.lock().unwrap().get_mut(device) {
                    if let Some(h) = s.hfp.as_mut() { h.volume = n; }
                }
                bus.publish(Event::AudioVolumeChanged { id: *device, volume: (n as u16 * 127 / 15) as u8 });
                at_ok(rf, l2, None);
            }
            Err(_) => at_err(rf, l2),
        }
    } else if let Some(v) = l.strip_prefix("AT+VGM=") { // headset mic volume (0-15)
        match v.trim().parse::<u8>() {
            Ok(n) => {
                if let Some(s) = st.lock().unwrap().get_mut(device) {
                    if let Some(h) = s.hfp.as_mut() { h.mic_volume = n.min(15); }
                }
                at_ok(rf, l2, None);
            }
            Err(_) => at_err(rf, l2),
        }
    } else if l.starts_with("AT+CKPD=200") // HSP button press
        || l.starts_with("AT+CMER=")       // enable indicator events
        || l.starts_with("AT+CMEE=")
        || l.starts_with("AT+NREC=")
        || l.starts_with("AT+BIA")
        || l.starts_with("AT+CHLD=") {
        at_ok(rf, l2, None);
    } else {
        at_err(rf, l2);
    }
}
