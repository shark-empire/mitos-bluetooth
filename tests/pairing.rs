use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::device::{Address, AddressType, DeviceId};
use mitos_bluetooth::hci::{op, MockTransport};
use std::time::Duration;

fn temp_mgr(tag: &str) -> (std::sync::Arc<BluetoothManager>, std::sync::Arc<std::sync::Mutex<mitos_bluetooth::hci::MockState>>) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-pair-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mgr = BluetoothManager::new(dir.to_string_lossy().into_owned()).unwrap();
    mgr.pair_timeout = Duration::from_secs(10);
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}

#[test]
fn pair_via_ssp_just_works_and_bonds() {
    let (mgr, shared) = temp_mgr("ssp");
    let id = DeviceId { address: Address([0x66, 0x55, 0x44, 0x33, 0x22, 0x12]), address_type: AddressType::Bredr };
    mgr.pair(0, &id).unwrap();
    // bond stored with the mock's link key
    assert!(mgr.bonds.is_bonded(&id));
    assert_eq!(mgr.bonds.get(&id).unwrap().link_key, Some([0x11u8; 16]));
    // device state advanced
    assert!(mgr.get_device(0, &id).unwrap().map(|d| d.paired && d.connected).unwrap_or(false));
    // the pairing dialogue at HCI level
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::LINK_KEY_REQUEST_NEG_REPLY.to_le_bytes()));
    assert!(sent.iter().any(|c| c[1..3] == op::IO_CAPABILITY_REQUEST_REPLY.to_le_bytes()));
    assert!(sent.iter().any(|c| c[1..3] == op::USER_CONFIRMATION_REQUEST_REPLY.to_le_bytes()));
    // pairing again uses the stored key: Link Key Request Reply, no re-pair
    mgr.pair(0, &id).unwrap();
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::LINK_KEY_REQUEST_REPLY.to_le_bytes()));
}

#[test]
fn legacy_pin_request_is_auto_answered() {
    let (mgr, shared) = temp_mgr("pin");
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x14];
    let mut ev = vec![0x04, 0x16, 0x06]; // PIN Code Request
    ev.extend_from_slice(&addr);
    shared.lock().unwrap().inject_event(ev);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let hit = {
            let st = shared.lock().unwrap();
            st.sent_commands().iter().any(|c| {
                c.len() >= 27 && c[1..3] == op::PIN_CODE_REQUEST_REPLY.to_le_bytes()
                    && &c[4..10] == &addr && c[10] == 4 && &c[11..15] == b"0000"
            })
        };
        if hit { return; }
        assert!(std::time::Instant::now() < deadline, "PIN reply never sent");
        std::thread::sleep(Duration::from_millis(50));
    }
}