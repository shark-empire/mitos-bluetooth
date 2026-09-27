use mitos_bluetooth::bluetooth::BluetoothManager;
use mitos_bluetooth::events::Event;
use mitos_bluetooth::hci::MockTransport;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn temp_mgr(tag: &str) -> (Arc<BluetoothManager>, Arc<std::sync::Mutex<mitos_bluetooth::hci::MockState>>) {
    let mock = MockTransport::new();
    let shared = mock.shared();
    let dir = std::env::temp_dir().join(format!("mitos-bt-disc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mgr = BluetoothManager::new(dir.to_string_lossy().into_owned()).unwrap();
    mgr.power_on_with(0, Box::new(mock)).unwrap();
    (mgr, shared)
}

fn wait_event<T>(rx: &mitos_bluetooth::events::EventBus, secs: u64, mut f: impl FnMut(Event) -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
            if let Some(v) = f(ev) { return Some(v); }
        }
    }
    None
}

#[test]
fn inquiry_produces_device_found() {
    let (mgr, _shared) = temp_mgr("found");
    let rx = mgr.bus.subscribe();
    mgr.start_discovery(0, true, false, 3).unwrap();
    let d = wait_event(&rx, 5, |ev| match ev {
        Event::DeviceFound { device } => Some(device),
        _ => None,
    }).expect("no DeviceFound event");
    assert_eq!(d.properties.name.as_deref(), Some("Mock Keyboard"));
    assert!(d.properties.class.is_keyboard());
    assert_eq!(d.properties.rssi, Some(-60));
    assert_eq!(d.id.address.to_string(), "12:22:33:44:55:66");
    let id = d.id;
    assert!(mgr.devices(0).unwrap().iter().any(|d| d.id == id));
    // inquiry completes -> DiscoveryStopped
    assert!(wait_event(&rx, 5, |ev| matches!(ev, Event::DiscoveryStopped { .. })).is_some());
}

#[test]
fn inquiry_result_without_eir_resolves_name_in_background() {
    let (mgr, shared) = temp_mgr("name");
    let rx = mgr.bus.subscribe();
    let addr = [0x66u8, 0x55, 0x44, 0x33, 0x22, 0x13];
    // Inquiry Result with RSSI (no EIR => no name)
    let mut p = vec![0x01];
    p.extend_from_slice(&addr);
    p.push(0x02); p.push(0x00);
    p.extend_from_slice(&[0x40, 0x05, 0x00]);
    p.extend_from_slice(&0u16.to_le_bytes());
    p.push(0xC8);
    let mut ev = vec![0x04, 0x22, p.len() as u8];
    ev.extend_from_slice(&p);
    shared.lock().unwrap().inject_event(ev);
    let got = wait_event(&rx, 5, |ev| match ev {
        Event::DeviceUpdated { device } if device.id.address.0 == addr && device.properties.name.is_some() => Some(device),
        _ => None,
    }).expect("name never resolved");
    assert_eq!(got.properties.name.as_deref(), Some("Mock Keyboard"));
}