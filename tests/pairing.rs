use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::device::{Address, AddressType, DeviceId};
use mitos_bluetooth::events::{Event, PairingMethod};
use mitos_bluetooth::hci::{op, MockState, MockTransport};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Shared = Arc<Mutex<MockState>>;

fn temp_mgr(tag: &str) -> (Arc<BluetoothManager>, Shared) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-pair-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mgr = BluetoothManager::new(&dir.to_string_lossy()).unwrap();
    if let Some(mgr_ref) = Arc::get_mut(&mut mgr) {
        mgr_ref.pair_timeout = Duration::from_secs(10);
    }

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
    assert!(mgr.get_device(0, &id).unwrap().is_some_and(|d| d.paired && d.connected));
    // the pairing dialogue at HCI level
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::LINK_KEY_REQUEST_NEG_REPLY.to_le_bytes()));
    // IO capability reply: DisplayYesNo (0x01 - HCI only knows 0..=3), no OOB data, general bonding
    assert!(sent.iter().any(|c| c[1..3] == op::IO_CAPABILITY_REQUEST_REPLY.to_le_bytes()
        && c.len() == 13
        && c[10] == 0x01
        && c[11] == 0x00
        && c[12] == 0x04));
    assert!(sent.iter().any(|c| c[1..3] == op::USER_CONFIRMATION_REQUEST_REPLY.to_le_bytes()));
    // pairing again uses the stored key: Link Key Request Reply, no re-pair
    mgr.pair(0, &id).unwrap();
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::LINK_KEY_REQUEST_REPLY.to_le_bytes()));
}

#[test]
fn legacy_pin_request_is_auto_answered() {
    let (_mgr, shared) = temp_mgr("pin");
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x14];
    let mut ev = vec![0x04, 0x16, 0x06]; // PIN Code Request
    ev.extend_from_slice(&addr);
    shared.lock().unwrap().inject_event(ev);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let hit = {
            let st = shared.lock().unwrap();
            st.sent_commands().iter().any(|c| {
                c.len() >= 27
                    && c[1..3] == op::PIN_CODE_REQUEST_REPLY.to_le_bytes()
                    && c[4..10] == addr
                    && c[10] == 4
                    && c[11..15] == *b"0000"
            })
        };
        if hit {
            return;
        }
        assert!(Instant::now() < deadline, "PIN reply never sent");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The first command with `opcode` the host has sent (events are handled asynchronously, so poll).
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

/// IO Capability Response event: bd_addr, IO capability, OOB present, authentication requirements.
fn io_capability_response(addr: [u8; 6], io: u8, auth: u8) -> Vec<u8> {
    let mut p = addr.to_vec();
    p.extend_from_slice(&[io, 0x00, auth]);
    let mut ev = vec![0x04, 0x32, p.len() as u8];
    ev.extend_from_slice(&p);
    ev
}

/// User Confirmation Request event: bd_addr, numeric value.
fn user_confirmation_request(addr: [u8; 6], value: u32) -> Vec<u8> {
    let mut p = addr.to_vec();
    p.extend_from_slice(&value.to_le_bytes());
    let mut ev = vec![0x04, 0x33, p.len() as u8];
    ev.extend_from_slice(&p);
    ev
}

#[test]
fn peer_demanding_mitm_gets_a_numeric_comparison_prompt() {
    let (mgr, shared) = temp_mgr("numeric");
    let rx = mgr.bus.subscribe();
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x21];
    let id = DeviceId { address: Address(addr), address_type: AddressType::Bredr };
    // a phone: DisplayYesNo, MITM protection required, general bonding
    shared.lock().unwrap().inject_event(io_capability_response(addr, 0x01, 0x05));
    shared.lock().unwrap().inject_event(user_confirmation_request(addr, 123_456));
    let mut prompt = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while prompt.is_none() && Instant::now() < deadline {
        if let Ok(Event::PairingRequested { request }) = rx.recv_timeout(Duration::from_millis(100)) {
            prompt = Some(request);
        }
    }
    let request = prompt.expect("no pairing prompt for the user");
    assert!(matches!(request.method, PairingMethod::NumericComparison));
    assert_eq!(request.passkey, Some(123_456));
    // nothing may be confirmed on the user's behalf
    assert!(shared
        .lock()
        .unwrap()
        .sent_commands()
        .iter()
        .all(|c| c[1..3] != op::USER_CONFIRMATION_REQUEST_REPLY.to_le_bytes()));
    // the user says the numbers match
    mgr.pairing_confirm(0, &id, true).unwrap();
    let reply = wait_command(&shared, op::USER_CONFIRMATION_REQUEST_REPLY).expect("confirmation was not sent");
    assert_eq!(reply[4..10], addr);
}

#[test]
fn peer_without_mitm_requirement_is_confirmed_automatically() {
    let (_mgr, shared) = temp_mgr("justworks");
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x22];
    // a mouse: NoInputNoOutput, no MITM
    shared.lock().unwrap().inject_event(io_capability_response(addr, 0x03, 0x04));
    shared.lock().unwrap().inject_event(user_confirmation_request(addr, 1));
    let reply = wait_command(&shared, op::USER_CONFIRMATION_REQUEST_REPLY).expect("Just Works was not confirmed");
    assert_eq!(reply[4..10], addr);
}
