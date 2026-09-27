use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::connection::ConnectionState;
use mitos_bluetooth::device::{Address, AddressType, DeviceId};
use mitos_bluetooth::events::Event;
use mitos_bluetooth::hci::MockTransport;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn temp_mgr(tag: &str) -> (Arc<BluetoothManager>, Arc<std::sync::Mutex<mitos_bluetooth::hci::MockState>>) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-conn-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mgr = BluetoothManager::new(dir.to_string_lossy().into_owned()).unwrap();
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}

fn wait_for(rx: &mitos_bluetooth::events::EventBus, secs: u64, mut f: impl FnMut(&Event) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
            if f(&ev) { return true; }
        }
    }
    false
}

#[test]
fn connect_and_disconnect_lifecycle() {
    let (mgr, _shared) = temp_mgr("lifecycle");
    let rx = mgr.bus.subscribe();
    let id = DeviceId { address: Address([0x66, 0x55, 0x44, 0x33, 0x22, 0x15]), address_type: AddressType::Bredr };
    let rt = mgr.runtime(0).unwrap();
    let handle = rt.connections.connect_acl(&id, Duration::from_secs(5)).unwrap();
    assert_eq!(handle, 0x0001);
    let info = rt.connections.get(&id).unwrap();
    assert_eq!(info.state, ConnectionState::Connected);
    assert!(!info.le);
    assert!(mgr.get_device(0, &id).unwrap().unwrap().connected);
    // device is reachable via L2CAP handle map
    assert_eq!(rt.l2.device(handle), Some(id));
    // disconnect: HCI-level + event
    mgr.disconnect(0, &id).unwrap();
    assert!(rt.connections.get(&id).is_none());
    assert!(wait_for(&rx, 3, |ev| matches!(ev, Event::DeviceDisconnected { id: d, .. } if *d == id)));
    assert!(!mgr.get_device(0, &id).unwrap().unwrap().connected);
}

#[test]
fn incoming_acl_from_device_publishes_reachable() {
    let (mgr, shared) = temp_mgr("incoming");
    let rx = mgr.bus.subscribe();
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x16];
    // Connection Request: [bdaddr][class][link_type=ACL]
    let mut p = addr.to_vec();
    p.extend_from_slice(&[0x40, 0x05, 0x00, 0x00]);
    let mut ev = vec![0x04, 0x04, p.len() as u8];
    ev.extend_from_slice(&p);
    shared.lock().unwrap().inject_event(ev);
    // we auto-accept (ACCEPT_CONNECTION_REQUEST), the mock completes it,
    // the dispatch thread registers the device and publishes DeviceAclConnected.
    assert!(wait_for(&rx, 3, |ev| matches!(ev, Event::DeviceAclConnected { id } if id.address.0 == addr)));
    // device table knows about it (class carried over from the request)
    let d = mgr.devices(0).unwrap().into_iter().find(|d| d.id.address.0 == addr).expect("device registered");
    assert!(d.properties.class.is_keyboard());
    assert!(d.connected);
}