use crate::adapter::BluetoothState;
use crate::device::{Device, DeviceId};
use crate::profile::ProfileKind;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingMethod { PinCode, PasskeyEntry, NumericComparison, JustWorks, Authorization }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub device: DeviceId,
    pub method: PairingMethod,
    /// Passkey / numeric value to show to the user (display & numeric comparison).
    pub passkey: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HidInput {
    Keyboard { modifiers: u8, keys: Vec<u8> },
    Mouse { buttons: u8, dx: i32, dy: i32, wheel: i32 },
    Gamepad { buttons: u32, axes: Vec<(u8, i32)> },
    Raw(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum Event {
    AdapterAdded { index: u32, address: String },
    AdapterRemoved { index: u32 },
    AdapterStateChanged { index: u32, powered: bool, discoverable: bool, connectable: bool },
    BluetoothStateChanged { state: BluetoothState },
    DiscoveryStarted { index: u32, le: bool },
    DiscoveryStopped { index: u32 },
    DeviceFound { device: Device },
    DeviceUpdated { device: Device },
    DeviceLost { id: DeviceId },
    DeviceConnected { id: DeviceId, profiles: Vec<ProfileKind> },
    DeviceDisconnected { id: DeviceId, reason: String },
    PairingRequested { request: PairingRequest },
    PairingComplete { id: DeviceId, success: bool, error: Option<String> },
    BondRemoved { id: DeviceId },
    GattNotification { id: DeviceId, attribute: u16, value: Vec<u8> },
    HidReport { id: DeviceId, input: HidInput },
    AudioVolumeChanged { id: DeviceId, volume: u8 },
    A2dpStateChanged { id: DeviceId, state: String },
    ScoStateChanged { id: DeviceId, connected: bool },
    DeviceAclConnected { id: DeviceId },
    MediaCommand { id: DeviceId, command: String },
    A2dpStreamReady { id: DeviceId, socket_path: String },
}

/// Per-subscriber queue depth. A subscriber that stops reading misses new events instead of
/// making the daemon's memory grow without bound.
const SUBSCRIBER_QUEUE: usize = 1024;

#[derive(Clone, Default)]
pub struct EventBus {
    subs: Arc<Mutex<Vec<SyncSender<Event>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        EventBus { subs: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE);
        self.subs.lock().unwrap().push(tx);
        rx
    }

    /// Never blocks: a full queue drops the event for that subscriber, a closed one unsubscribes it.
    pub fn publish(&self, ev: Event) {
        let mut subs = self.subs.lock().unwrap();
        subs.retain(|tx| !matches!(tx.try_send(ev.clone()), Err(TrySendError::Disconnected(_))));
    }
}
