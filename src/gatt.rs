use crate::device::{DeviceId, DeviceTable};
use crate::error::Result;
use crate::events::EventBus;
use crate::l2cap::L2cap;
use std::sync::{Arc, Mutex};

/// GATT client. Next batch: ATT bearer on CID 0x0004 (register_fixed), MTU exchange,
/// service/characteristic discovery, read/write, CCC notifications.
pub struct GattManager {
    pub l2: Arc<L2cap>,
    pub bus: Arc<EventBus>,
    pub devices: Arc<DeviceTable>,
    attached: Mutex<Vec<u16>>,
}

impl GattManager {
    pub fn new(l2: Arc<L2cap>, bus: Arc<EventBus>, devices: Arc<DeviceTable>) -> Arc<Self> {
        Arc::new(GattManager { l2, bus, devices, attached: Mutex::new(Vec::new()) })
    }
    pub fn attach(&self, handle: u16, _device: DeviceId) -> Result<()> {
        self.attached.lock().unwrap().push(handle);
        Ok(())
    }
    pub fn detach(&self, handle: u16) { self.attached.lock().unwrap().retain(|&h| h != handle); }
}