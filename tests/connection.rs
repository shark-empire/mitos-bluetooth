use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::connection::ConnectionState;
use mitos_bluetooth::device::{Address, AddressType, DeviceId};
use mitos_bluetooth::events::Event;
use mitos_bluetooth::hci::{op, MockState, MockTransport};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Shared = Arc<Mutex<MockState>>;

fn temp_mgr_with(tag: &str, trusted_only: bool) -> (Arc<BluetoothManager>, Shared) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-conn-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mgr = BluetoothManager::new(&dir.to_string_lossy()).unwrap();
    mgr.cfg.lock().unwrap().trusted_only_connect = trusted_only;
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}

fn temp_mgr(tag: &str) -> (Arc<BluetoothManager>, Shared) {
    temp_mgr_with(tag, false)
}

fn wait_for(rx: &std::sync::mpsc::Receiver<Event>, secs: u64, mut f: impl FnMut(&Event) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
            if f(&ev) {
                return true;
            }
        }
    }
    false
}

/// The first command with `opcode` the host has sent (the dispatch thread acts asynchronously, so poll).
fn wait_command(shared: &Shared, opcode: u16) -> Option<Vec<u8>> {
    for _ in 0..300 {
        let found = shared.lock().unwrap().sent_commands().into_iter().find(|c| c[1..3] == opcode.to_le_bytes());
        if found.is_some() {
            return found;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// HCI Connection Request event: [bdaddr][class of device][link type]
fn connection_request(addr: [u8; 6], link_type: u8) -> Vec<u8> {
    let mut p = addr.to_vec();
    p.extend_from_slice(&[0x40, 0x05, 0x00, link_type]);
    let mut ev = vec![0x04, 0x04, p.len() as u8];
    ev.extend_from_slice(&p);
    ev
}

#[test]
fn connect_and_disconnect_lifecycle() {
    let (mgr, shared) = temp_mgr("lifecycle");
    let rx = mgr.bus.subscribe();
    let id = DeviceId { address: Address([0x66, 0x55, 0x44, 0x33, 0x22, 0x15]), address_type: AddressType::Bredr };
    let rt = mgr.runtime(0).unwrap();

    // the mock controller answers Create Connection with Connection Complete (handle 1)
    let handle = rt.connections.connect_acl(&id, Duration::from_secs(5)).unwrap();
    assert_eq!(handle, 0x0001);

    let info = rt.connections.get(&id).unwrap();
    assert_eq!(info.state, ConnectionState::Connected);
    assert!(!info.le);
    assert!(mgr.get_device(0, &id).unwrap().unwrap().connected);
    assert_eq!(rt.l2.device(handle), Some(id));
    // connecting again reuses the link instead of paging the device a second time
    assert_eq!(rt.connections.connect_acl(&id, Duration::from_secs(5)).unwrap(), handle);

    mgr.disconnect(0, &id).unwrap();
    assert!(rt.connections.get(&id).is_none());
    assert!(wait_for(&rx, 3, |ev| matches!(ev, Event::DeviceDisconnected { id: d, .. } if *d == id)));
    assert!(!mgr.get_device(0, &id).unwrap().unwrap().connected);

    let sent = shared.lock().unwrap().sent_commands();
    let creates: Vec<&Vec<u8>> = sent.iter().filter(|c| c[1..3] == op::CREATE_CONNECTION.to_le_bytes()).collect();
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0][4..10], id.address.0);
    assert!(sent.iter().any(|c| c[1..3] == op::DISCONNECT.to_le_bytes() && c[4..6] == handle.to_le_bytes()));
}

#[test]
fn incoming_acl_from_device_publishes_reachable() {
    let (mgr, shared) = temp_mgr("incoming");
    let rx = mgr.bus.subscribe();
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x16];
    // link type 1 = ACL
    shared.lock().unwrap().inject_event(connection_request(addr, 0x01));
    // we accept (Accept Connection Request), the mock completes it, the dispatch thread
    // registers the device and publishes DeviceAclConnected.
    assert!(wait_for(&rx, 3, |ev| matches!(ev, Event::DeviceAclConnected { id } if id.address.0 == addr)));
    let accept = wait_command(&shared, op::ACCEPT_CONNECTION_REQUEST).expect("connection was not accepted");
    assert_eq!(accept[4..10], addr);
    // device table knows about it (class carried over from the request)
    let d = mgr.devices(0).unwrap().into_iter().find(|d| d.id.address.0 == addr).expect("device registered");
    assert!(d.properties.class.is_keyboard());
    assert!(d.connected);
}

#[test]
fn voice_link_requests_without_a_hands_free_session_are_refused() {
    let (_mgr, shared) = temp_mgr("sco");
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x17];
    shared.lock().unwrap().inject_event(connection_request(addr, 0x02)); // 2 = eSCO
    let reject = wait_command(&shared, op::REJECT_SYNCHRONOUS_CONNECTION).expect("eSCO request was not answered");
    assert_eq!(reject[4..10], addr);
    // and it must not have been mistaken for an ACL request
    assert!(shared
        .lock()
        .unwrap()
        .sent_commands()
        .iter()
        .all(|c| c[1..3] != op::ACCEPT_CONNECTION_REQUEST.to_le_bytes()));
}

#[test]
fn trusted_only_refuses_strangers_until_the_adapter_is_discoverable() {
    let (mgr, shared) = temp_mgr_with("trusted-only", true);
    let rx = mgr.bus.subscribe();
    let stranger = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x18];
    shared.lock().unwrap().inject_event(connection_request(stranger, 0x01));
    let reject = wait_command(&shared, op::REJECT_CONNECTION_REQUEST).expect("stranger was not refused");
    assert_eq!(reject[4..10], stranger);
    assert!(shared
        .lock()
        .unwrap()
        .sent_commands()
        .iter()
        .all(|c| c[1..3] != op::ACCEPT_CONNECTION_REQUEST.to_le_bytes()));

    // while discoverable, a new device is exactly who we are waiting for
    mgr.set_discoverable(0, true).unwrap();
    let newcomer = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x19];
    shared.lock().unwrap().inject_event(connection_request(newcomer, 0x01));
    assert!(wait_for(&rx, 3, |ev| matches!(ev, Event::DeviceAclConnected { id } if id.address.0 == newcomer)));
}
