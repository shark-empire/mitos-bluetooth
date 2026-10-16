use crate::adapter::{AdapterInfo, BluetoothAdapter, BluetoothState};
use crate::audio::AudioManager;
use crate::bonding::{Bond, BondStore};
use crate::connection::{ConnInfo, ConnectionDeps, ConnectionManager};
use crate::device::{AddressType, Device, DeviceClass, DeviceId, DeviceState, DeviceTable};
use crate::discovery::DiscoveryManager;
use crate::error::{Error, Result};
use crate::events::{Event, EventBus};
use crate::gatt::GattManager;
use crate::hci::{ev, list_linux_adapters, HciClient, HciEvent, SerialH4};
use crate::hid::HidHost;
use crate::l2cap::L2cap;
use crate::pairing::PairingManager;
use crate::profile::{ProfileKind, ProfileManager};
use crate::smp::Smp;
use crate::storage::{Config, Storage};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Everything that lives per radio (per HCI controller).
pub struct AdapterRuntime {
    pub index: u32,
    pub hci: Arc<HciClient>,
    pub l2: Arc<L2cap>,
    pub smp: Arc<Smp>,
    pub gatt: Arc<GattManager>,
    pub hid: Arc<HidHost>,
    pub audio: Arc<AudioManager>,
    pub profiles: Arc<ProfileManager>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub bonds: Arc<BondStore>,
    pub discovery: DiscoveryManager,
    pub pairing: PairingManager,
    pub connections: ConnectionManager,
    pub info: Mutex<AdapterInfo>,
    /// `trusted_only_connect` from the configuration: unbonded devices may connect only while discoverable.
    trusted_only: bool,
}

impl AdapterRuntime {
    pub fn open(index: u32, cfg: &Config, bus: Arc<EventBus>, bonds: Arc<BondStore>) -> Result<Arc<Self>> {
        let adapter = BluetoothAdapter::open(index)?;
        let info = adapter.init(&cfg.name, cfg.discoverable)?;
        Ok(Self::build(index, adapter.hci.clone(), info, cfg, bus, bonds))
    }
    /// Open an adapter with an explicit transport — used by tests, serial, and a
    /// future mitos-kernel driver (implement `HciTransport`, pass it here).
    pub fn open_with(
        index: u32,
        transport: Box<dyn crate::hci::HciTransport>,
        cfg: &Config,
        bus: Arc<EventBus>,
        bonds: Arc<BondStore>,
    ) -> Result<Arc<Self>> {
        let hci = Arc::new(crate::hci::HciClient::open(index, transport)?);
        let adapter = BluetoothAdapter { hci: hci.clone() };
        let info = adapter.init(&cfg.name, cfg.discoverable)?;
        Ok(Self::build(index, hci, info, cfg, bus, bonds))
    }

    pub fn open_serial(
        index: u32,
        path: &str,
        cfg: &Config,
        bus: Arc<EventBus>,
        bonds: Arc<BondStore>,
    ) -> Result<Arc<Self>> {
        let tr = SerialH4::open(path)?;
        let hci = Arc::new(HciClient::open(index, Box::new(tr))?);
        let adapter = BluetoothAdapter { hci: hci.clone() };
        let info = adapter.init(&cfg.name, cfg.discoverable)?;
        Ok(Self::build(index, hci, info, cfg, bus, bonds))
    }

    fn build(
        index: u32,
        hci: Arc<HciClient>,
        info: AdapterInfo,
        cfg: &Config,
        bus: Arc<EventBus>,
        bonds: Arc<BondStore>,
    ) -> Arc<Self> {
        let l2 = L2cap::new(hci.clone());
        let devices: Arc<DeviceTable> = Arc::new(Mutex::new(HashMap::new()));
        let smp = Smp::new(l2.clone(), hci.clone(), bus.clone(), bonds.clone(), info.address);
        let gatt = GattManager::new(l2.clone(), bus.clone(), devices.clone());
        let hid = HidHost::new(l2.clone(), gatt.clone(), devices.clone(), bus.clone());
        let audio = AudioManager::new(hci.clone(), l2.clone(), devices.clone(), bus.clone());
        let profiles = Arc::new(ProfileManager::new(hid.clone(), gatt.clone(), audio.clone()));
        let connections = ConnectionManager::new(
            ConnectionDeps {
                hci: hci.clone(),
                l2: l2.clone(),
                smp: smp.clone(),
                gatt: gatt.clone(),
                profiles: profiles.clone(),
                devices: devices.clone(),
                bus: bus.clone(),
                bonds: bonds.clone(),
            },
            cfg.trusted_only_connect && !info.discoverable,
        );
        let pairing = PairingManager::new(
            hci.clone(),
            devices.clone(),
            bus.clone(),
            bonds.clone(),
            cfg.auto_pin,
            cfg.default_pin.clone(),
        );
        let discovery = DiscoveryManager::new(hci.clone(), devices.clone(), bus.clone(), index);
        // seed the device table from the bond database so the GUI sees paired devices after boot
        {
            let mut ds = devices.lock().unwrap();
            for b in bonds.list() {
                let mut d = Device::new(b.device);
                d.paired = true;
                d.trusted = b.trusted;
                d.state = DeviceState::Paired;
                d.properties.name.clone_from(&b.name);
                d.properties.class = DeviceClass(b.class);
                d.profiles = b.profiles.clone();
                ds.entry(b.device).or_insert(d);
            }
        }
        let rt = Arc::new(AdapterRuntime {
            index,
            hci,
            l2,
            smp,
            gatt,
            hid,
            audio,
            profiles,
            devices,
            bus,
            bonds,
            discovery,
            pairing,
            connections,
            info: Mutex::new(info),
            trusted_only: cfg.trusted_only_connect,
        });
        // All manager work runs on a dedicated dispatch thread. The HCI reader thread only
        // forwards events into this channel — it must never block, or command-complete
        // delivery would deadlock (manager handlers issue HCI commands).
        // The thread holds only a Weak reference, so dropping the runtime releases the controller.
        let (tx, rx) = mpsc::channel::<HciEvent>();
        rt.hci.set_event_handler(Box::new(move |event| {
            let _ = tx.send(event);
        }));
        let weak = Arc::downgrade(&rt);
        std::thread::Builder::new()
            .name(format!("hci{index}-dispatch"))
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    match weak.upgrade() {
                        Some(rt) => rt.dispatch(&event),
                        None => break,
                    }
                }
            })
            .ok();
        rt
    }

    fn dispatch(&self, event: &HciEvent) {
        self.connections.on_event(event); // first: keeps handle maps current for the others
        self.discovery.on_event(event);
        self.pairing.on_event(event);
        match event.code {
            ev::AUTHENTICATION_COMPLETE => {
                let device = self.connections.device_of(event.u16(1));
                self.pairing.on_auth_complete(device, event.u8(0));
            }
            ev::ENCRYPTION_CHANGE => self.smp.on_encryption_change(event.u16(1), event.u8(0), event.u8(3) != 0),
            ev::LE_META_EVENT if event.le_sub() == ev::LE_LTK_REQUEST => self.smp.on_ltk_request(event),
            ev::SYNCHRONOUS_CONNECTION_COMPLETE => self.audio.on_sco_complete(event),
            _ => {}
        }
    }

    /// Orderly shutdown: stop scanning, hang up, stop the media sockets, then release the controller so the
    /// kernel (or the next power_on) can have it again.
    pub fn power_off(&self) -> Result<()> {
        let _ = self.discovery.stop();
        self.connections.disconnect_all();
        self.audio.shutdown();
        let _ = BluetoothAdapter { hci: self.hci.clone() }.off();
        self.l2.shutdown();
        Ok(())
    }

    pub fn set_discoverable(&self, on: bool) -> Result<()> {
        BluetoothAdapter { hci: self.hci.clone() }.set_scan(on, true)?;
        // while discoverable a brand-new device must be able to connect, whatever `trusted_only_connect` says
        self.connections.set_accept_unbonded(on || !self.trusted_only);
        let mut i = self.info.lock().unwrap();
        i.discoverable = on;
        let snapshot = i.clone();
        drop(i);
        self.bus.publish(Event::AdapterStateChanged {
            index: self.index,
            powered: true,
            discoverable: snapshot.discoverable,
            connectable: snapshot.connectable,
        });
        Ok(())
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        BluetoothAdapter { hci: self.hci.clone() }.set_name(name)?;
        self.info.lock().unwrap().name = name.to_string();
        Ok(())
    }
}

/// Top-level daemon API — this is what the IPC layer (and therefore the GUI) talks to.
pub struct BluetoothManager {
    pub bus: Arc<EventBus>,
    pub store: Arc<Storage>,
    pub bonds: Arc<BondStore>,
    pub cfg: Mutex<Config>,
    pub adapters: Mutex<HashMap<u32, Arc<AdapterRuntime>>>,
    state: Mutex<BluetoothState>,
    pub pair_timeout: Duration,
}

impl BluetoothManager {
    pub fn new(data_dir: &str) -> Result<Arc<Self>> {
        let store = Arc::new(Storage::new(data_dir)?);
        let cfg = store.load_config();
        let bonds = Arc::new(BondStore::new(store.clone()));
        Ok(Arc::new(BluetoothManager {
            bus: Arc::new(EventBus::new()),
            store,
            bonds,
            cfg: Mutex::new(cfg),
            adapters: Mutex::new(HashMap::new()),
            state: Mutex::new(BluetoothState::Off),
            pair_timeout: Duration::from_secs(120),
        }))
    }
    /// Bring an adapter up with an injected transport (tests / custom kernels).
    pub fn power_on_with(&self, index: u32, transport: Box<dyn crate::hci::HciTransport>) -> Result<AdapterInfo> {
        if let Some(rt) = self.adapters.lock().unwrap().get(&index) {
            return Ok(rt.info.lock().unwrap().clone());
        }
        let cfg = self.cfg.lock().unwrap().clone();
        let rt = AdapterRuntime::open_with(index, transport, &cfg, self.bus.clone(), self.bonds.clone())?;
        let info = rt.info.lock().unwrap().clone();
        let address = info.address;
        self.adapters.lock().unwrap().insert(index, rt);
        if *self.state.lock().unwrap() != BluetoothState::On {
            *self.state.lock().unwrap() = BluetoothState::On;
            self.publish_state();
        }
        self.bus.publish(Event::AdapterAdded { index, address: address.to_string() });
        Ok(info)
    }

    fn publish_state(&self) {
        let s = self.state.lock().unwrap().clone();
        self.bus.publish(Event::BluetoothStateChanged { state: s });
    }
    pub fn state(&self) -> BluetoothState {
        self.state.lock().unwrap().clone()
    }
    pub fn adapters(&self) -> Vec<AdapterInfo> {
        self.adapters.lock().unwrap().values().map(|r| r.info.lock().unwrap().clone()).collect()
    }
    pub fn runtime(&self, index: u32) -> Result<Arc<AdapterRuntime>> {
        self.adapters
            .lock()
            .unwrap()
            .get(&index)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("adapter hci{index} (is Bluetooth powered on?)")))
    }

    // ---- audio ----
    pub fn a2dp_start(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.audio.a2dp_start(id)
    }
    pub fn a2dp_suspend(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.audio.a2dp_suspend(id)
    }
    pub fn a2dp_send_sbc(&self, index: u32, id: &DeviceId, frames: &[u8], nframes: u32) -> Result<()> {
        self.runtime(index)?.audio.a2dp_send_sbc(id, frames, nframes)
    }
    pub fn a2dp_state(&self, index: u32, id: &DeviceId) -> Result<crate::audio::A2dpInfo> {
        self.runtime(index)?.audio.a2dp_info(id).ok_or_else(|| Error::InvalidState("a2dp not connected".into()))
    }
    pub fn avrcp_command(&self, index: u32, id: &DeviceId, op: &str) -> Result<()> {
        let o = crate::audio::avrcp_op(op).ok_or_else(|| Error::InvalidArgument(format!("unknown avrcp op '{op}'")))?;
        self.runtime(index)?.audio.avrcp_passthrough(id, o)
    }
    pub fn set_volume(&self, index: u32, id: &DeviceId, volume: u8) -> Result<()> {
        self.runtime(index)?.audio.set_absolute_volume(id, volume)
    }
    pub fn hfp_connect_sco(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.audio.hfp_connect_sco(id)
    }
    pub fn hfp_disconnect_sco(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.audio.hfp_disconnect_sco(id)
    }

    // ---- GATT (LE only for now) ----
    fn conn_handle(&self, index: u32, id: &DeviceId) -> Result<u16> {
        let rt = self.runtime(index)?;
        if id.address_type == AddressType::Bredr {
            return Err(Error::InvalidState("GATT requires an LE connection".into()));
        }
        rt.connections.handle_of(id).ok_or_else(|| Error::InvalidState("device not connected".into()))
    }
    pub fn gatt_services(&self, index: u32, id: &DeviceId) -> Result<Vec<crate::gatt::GattService>> {
        let h = self.conn_handle(index, id)?;
        self.runtime(index)?.gatt.discover_services(h)
    }
    pub fn gatt_characteristics(
        &self,
        index: u32,
        id: &DeviceId,
        service_start: u16,
    ) -> Result<Vec<crate::gatt::GattCharacteristic>> {
        let rt = self.runtime(index)?;
        let h = self.conn_handle(index, id)?;
        let svc = rt
            .gatt
            .discover_services(h)?
            .into_iter()
            .find(|s| s.start == service_start)
            .ok_or_else(|| Error::NotFound("service".into()))?;
        rt.gatt.discover_characteristics(h, &svc)
    }
    pub fn gatt_read(&self, index: u32, id: &DeviceId, attribute: u16) -> Result<Vec<u8>> {
        let h = self.conn_handle(index, id)?;
        self.runtime(index)?.gatt.read(h, attribute)
    }
    pub fn gatt_write(&self, index: u32, id: &DeviceId, attribute: u16, data: &[u8], response: bool) -> Result<()> {
        let h = self.conn_handle(index, id)?;
        self.runtime(index)?.gatt.write(h, attribute, data, response)
    }
    pub fn gatt_subscribe(&self, index: u32, id: &DeviceId, value_handle: u16, cccd_value: u16) -> Result<()> {
        let h = self.conn_handle(index, id)?;
        self.runtime(index)?.gatt.subscribe(h, value_handle, cccd_value)
    }
    /// Bring up every controller found on the system.
    pub fn init(&self) -> Result<()> {
        *self.state.lock().unwrap() = BluetoothState::TurningOn;
        self.publish_state();
        let cfg = self.cfg.lock().unwrap().clone();
        let mut ok = 0;
        for (idx, _addr) in list_linux_adapters() {
            match AdapterRuntime::open(idx, &cfg, self.bus.clone(), self.bonds.clone()) {
                Ok(rt) => {
                    let address = rt.info.lock().unwrap().address;
                    self.adapters.lock().unwrap().insert(idx, rt);
                    self.bus.publish(Event::AdapterAdded { index: idx, address: address.to_string() });
                    ok += 1;
                }
                Err(e) => eprintln!("[bluetooth] adapter hci{idx} unavailable: {e}"),
            }
        }
        *self.state.lock().unwrap() = if ok > 0 { BluetoothState::On } else { BluetoothState::Off };
        self.publish_state();
        Ok(())
    }

    pub fn power_on(&self, index: u32) -> Result<AdapterInfo> {
        self.open_adapter(index, None)
    }
    pub fn power_on_serial(&self, index: u32, path: &str) -> Result<AdapterInfo> {
        self.open_adapter(index, Some(path))
    }

    fn open_adapter(&self, index: u32, serial: Option<&str>) -> Result<AdapterInfo> {
        if let Some(rt) = self.adapters.lock().unwrap().get(&index) {
            return Ok(rt.info.lock().unwrap().clone());
        }
        let cfg = self.cfg.lock().unwrap().clone();
        let rt = match serial {
            Some(path) => AdapterRuntime::open_serial(index, path, &cfg, self.bus.clone(), self.bonds.clone())?,
            None => AdapterRuntime::open(index, &cfg, self.bus.clone(), self.bonds.clone())?,
        };
        let info = rt.info.lock().unwrap().clone();
        let address = info.address;
        self.adapters.lock().unwrap().insert(index, rt);
        if *self.state.lock().unwrap() != BluetoothState::On {
            *self.state.lock().unwrap() = BluetoothState::On;
            self.publish_state();
        }
        self.bus.publish(Event::AdapterAdded { index, address: address.to_string() });
        Ok(info)
    }

    pub fn power_off(&self, index: u32) -> Result<()> {
        let rt = self.runtime(index)?;
        rt.power_off()?;
        self.adapters.lock().unwrap().remove(&index);
        self.bus.publish(Event::AdapterRemoved { index });
        if self.adapters.lock().unwrap().is_empty() {
            *self.state.lock().unwrap() = BluetoothState::Off;
            self.publish_state();
        }
        Ok(())
    }

    // ---- discovery / devices ----
    pub fn start_discovery(&self, index: u32, bredr: bool, le: bool, timeout_secs: u64) -> Result<()> {
        self.runtime(index)?.discovery.start(bredr, le, timeout_secs)
    }
    pub fn stop_discovery(&self, index: u32) -> Result<()> {
        self.runtime(index)?.discovery.stop()
    }
    pub fn devices(&self, index: u32) -> Result<Vec<Device>> {
        let mut v: Vec<Device> = self.runtime(index)?.devices.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|d| d.id);
        Ok(v)
    }
    pub fn get_device(&self, index: u32, id: &DeviceId) -> Result<Option<Device>> {
        Ok(self.runtime(index)?.devices.lock().unwrap().get(id).cloned())
    }

    // ---- pairing ----
    /// Connect + authenticate + wait for PairingComplete (blocks up to ~2 min for user interaction).
    pub fn pair(&self, index: u32, id: &DeviceId) -> Result<()> {
        let rt = self.runtime(index)?;
        let rx = self.bus.subscribe(); // subscribe BEFORE triggering anything
        rt.devices.lock().unwrap().entry(*id).or_insert_with(|| Device::new(*id)).state = DeviceState::Pairing;
        let result = self.pair_inner(&rt, id, &rx);
        let state = match (&result, self.bonds.is_bonded(id)) {
            (Ok(()), _) | (Err(_), true) => DeviceState::Paired,
            (Err(_), false) => DeviceState::Discovered,
        };
        if let Some(d) = rt.devices.lock().unwrap().get_mut(id) {
            d.state = state;
        }
        result
    }

    fn pair_inner(&self, rt: &AdapterRuntime, id: &DeviceId, rx: &mpsc::Receiver<Event>) -> Result<()> {
        let bonded = self.bonds.is_bonded(id);
        let handle = rt.connections.connect_acl(id, Duration::from_secs(15))?;
        if id.address_type == AddressType::Bredr {
            if bonded {
                // already paired: authenticate with the stored link key instead of pairing again
                return rt.pairing.authenticate(handle, Duration::from_secs(15));
            }
            rt.pairing.request_auth(handle)?;
        } else if bonded {
            return rt.smp.encrypt_bond(handle);
        } else if !rt.smp.busy(handle) {
            rt.smp.start_pairing(handle, true)?;
        }
        let deadline = Instant::now() + self.pair_timeout;
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                break;
            }
            match rx.recv_timeout(remain) {
                Ok(Event::PairingComplete { id: dev, success, error }) if dev == *id => {
                    if !success {
                        return Err(Error::PairingFailed(error.unwrap_or_else(|| "pairing rejected or failed".into())));
                    }
                    if let Some(d) = rt.devices.lock().unwrap().get(id) {
                        self.bonds.set_class(id, d.properties.class.0);
                        if let Some(n) = &d.properties.name {
                            self.bonds.set_name(id, n);
                        }
                    }
                    return Ok(());
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        if id.address_type != AddressType::Bredr {
            rt.smp.cancel(handle); // tell the peer and drop the half-finished exchange
        }
        Err(Error::Timeout("pairing completion"))
    }

    pub fn pairing_confirm(&self, index: u32, id: &DeviceId, accept: bool) -> Result<()> {
        let rt = self.runtime(index)?;
        if id.address_type == AddressType::Bredr {
            rt.pairing.confirm(id, accept)
        } else {
            // LE legacy pairing continues by itself; declining ends it
            if !accept {
                rt.smp.cancel_device(id);
            }
            Ok(())
        }
    }
    pub fn provide_pin(&self, index: u32, id: &DeviceId, pin: &str) -> Result<()> {
        self.runtime(index)?.pairing.provide_pin(id, pin)
    }
    pub fn provide_passkey(&self, index: u32, id: &DeviceId, passkey: u32) -> Result<()> {
        let rt = self.runtime(index)?;
        if id.address_type == AddressType::Bredr {
            rt.pairing.provide_passkey(id, passkey)
        } else {
            rt.smp.provide_passkey(id, passkey)
        }
    }
    pub fn cancel_pairing(&self, index: u32, id: &DeviceId) -> Result<()> {
        let rt = self.runtime(index)?;
        rt.smp.cancel_device(id);
        rt.pairing.cancel(id)
    }

    // ---- connections / profiles ----
    pub fn connect(&self, index: u32, id: &DeviceId, kind: ProfileKind) -> Result<()> {
        self.runtime(index)?.connections.connect_profile(id, kind)
    }
    pub fn disconnect(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.connections.disconnect(id, 0x13)
    }
    /// Bring the link back up (with retries) after it dropped.
    pub fn reconnect(&self, index: u32, id: &DeviceId) -> Result<()> {
        self.runtime(index)?.connections.reconnect(id).map(|_| ())
    }
    /// Keyboard LEDs: numlock 0x01, caps 0x02, scroll 0x04.
    pub fn set_keyboard_leds(&self, index: u32, id: &DeviceId, leds: u8) -> Result<()> {
        self.runtime(index)?.hid.set_keyboard_leds(id, leds)
    }
    pub fn connections(&self, index: u32) -> Result<Vec<ConnInfo>> {
        Ok(self.runtime(index)?.connections.list())
    }

    // ---- adapter settings (persisted) ----
    pub fn set_discoverable(&self, index: u32, on: bool) -> Result<()> {
        self.runtime(index)?.set_discoverable(on)?;
        let cfg = {
            let mut c = self.cfg.lock().unwrap();
            c.discoverable = on;
            c.clone()
        };
        self.store.save_config(&cfg);
        Ok(())
    }
    pub fn set_name(&self, index: u32, name: &str) -> Result<()> {
        self.runtime(index)?.set_name(name)?;
        let cfg = {
            let mut c = self.cfg.lock().unwrap();
            c.name = name.to_string();
            c.clone()
        };
        self.store.save_config(&cfg);
        Ok(())
    }

    // ---- bonds ----
    pub fn bonds_list(&self) -> Vec<Bond> {
        self.bonds.list()
    }
    pub fn set_trusted(&self, id: &DeviceId, on: bool) -> Result<()> {
        if self.bonds.set_trusted(id, on) {
            Ok(())
        } else {
            Err(Error::NotFound("no bond for device".into()))
        }
    }
    pub fn remove_device(&self, index: u32, id: &DeviceId) -> Result<()> {
        let rt = self.runtime(index)?;
        let _ = rt.connections.disconnect(id, 0x13);
        if self.bonds.remove(id) {
            rt.devices.lock().unwrap().remove(id);
            self.bus.publish(Event::BondRemoved { id: *id });
        }
        Ok(())
    }
}
