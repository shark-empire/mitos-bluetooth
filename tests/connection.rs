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
    let mgr = BluetoothManager::new(&dir.to_string_lossy()).unwrap();
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}


fn wait_for(rx: &std::sync::mpsc::Receiver<Event>, secs: u64, mut f: impl FnMut(&Event) -> bool) -> bool {
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
    // 1. Don't ignore shared!
    let (mgr, shared) = temp_mgr("lifecycle");
    let rx = mgr.bus.subscribe();
    let id = DeviceId { address: Address([0x66, 0x55, 0x44, 0x33, 0x22, 0x15]), address_type: AddressType::Bredr };
    let rt = mgr.runtime(0).unwrap();

    // 2. Spawn a thread to simulate the Bluetooth Controller's response
    let shared_clone = shared.clone();
    let addr_clone = id.address.0;
    std::thread::spawn(move || {
        // Give `connect_acl` a tiny fraction of a second to send the command and start waiting
        std::thread::sleep(Duration::from_millis(50));
        
        // Construct an HCI Connection Complete Event
        // [0x04] HCI Event Packet
        // [0x03] Connection Complete Event Code
        // [0x0B] Parameter Total Length (11 bytes)
        // [0x00] Status: Success
        // [0x01, 0x00] Connection Handle: 0x0001 (Little Endian)
        let mut ev = vec![0x04, 0x03, 0x0B, 0x00, 0x01, 0x00];
        ev.extend_from_slice(&addr_clone); // 6 bytes BD_ADDR
        ev.extend_from_slice(&[0x01, 0x00]); // [0x01] Link Type: ACL, [0x00] Encryption Disabled
        
        shared_clone.lock().unwrap().inject_event(ev);
    });

    // 3. This will now successfully receive the injected event and stop timing out!
    let handle = rt.connections.connect_acl(&id, Duration::from_secs(5)).unwrap();
    assert_eq!(handle, 0x0001);
    
    let info = rt.connections.get(&id).unwrap();
    assert_eq!(info.state, ConnectionState::Connected);
    assert!(!info.le);
    assert!(mgr.get_device(0, &id).unwrap().unwrap().connected);
    assert_eq!(rt.l2.device(handle), Some(id));

    // Note for Disconnect:
    // If `mgr.disconnect()` ALSO blocks waiting for a "Disconnection Complete" event, 
    // you will need to spawn another thread to inject HCI Event Code 0x05 here before calling it!
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
