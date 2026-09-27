use mitos_bluetooth::adapter::BluetoothState;
use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::hci::{op, MockTransport};
use std::sync::Arc;

fn temp_mgr(tag: &str) -> (Arc<BluetoothManager>, std::sync::Arc<std::sync::Mutex<mitos_bluetooth::hci::MockState>>) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-adapter-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mgr = BluetoothManager::new(dir.to_string_lossy().into_owned()).unwrap();
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}

#[test]
fn adapter_init_reads_controller() {
    let (mgr, shared) = temp_mgr("init");
    let info = mgr.adapters().remove(0);
    assert_eq!(info.index, 0);
    assert_eq!(info.address.to_string(), "11:22:33:44:55:66");
    assert!(info.le_supported);
    assert_eq!(info.version, "5.3");
    assert_eq!(info.name, "mitos");
    assert_eq!(mgr.state(), BluetoothState::On);
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::RESET.to_le_bytes()));
    assert!(sent.iter().any(|c| c[1..3] == op::WRITE_SIMPLE_PAIRING_MODE.to_le_bytes() && c[4] == 0x01));
    assert!(sent.iter().any(|c| c[1..3] == op::WRITE_SCAN_ENABLE.to_le_bytes() && c[4] == 0x02));
}

#[test]
fn set_name_and_discoverable_write_controller() {
    let (mgr, shared) = temp_mgr("name");
    mgr.set_name(0, "mitos-box").unwrap();
    mgr.set_discoverable(0, true).unwrap();
    let sent = shared.lock().unwrap().sent_commands();
    assert!(sent.iter().any(|c| c[1..3] == op::WRITE_LOCAL_NAME.to_le_bytes()
        && &c[4..13] == "mitos-box".as_bytes()));
    assert!(sent.iter().any(|c| c[1..3] == op::WRITE_SCAN_ENABLE.to_le_bytes() && c[4] == 0x03));
    // persisted
    assert_eq!(mgr.store.load_config().name, "mitos-box");
    assert!(mgr.store.load_config().discoverable);
}