use crate::device::{DeviceId, DeviceTable};
use crate::error::{Error, Result};
use crate::events::EventBus;
use crate::gatt::GattManager;
use crate::l2cap::L2cap;
use std::sync::Arc;

/// Classic HID host (L2CAP 0x11/0x13 + HIDP) and HID-over-GATT. Next batch:
/// SDP lookup, control/interrupt channels, report parsing -> mitos-input forwarding.
pub struct HidHost {
    pub l2: Arc<L2cap>,
    pub gatt: Arc<GattManager>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
}

impl HidHost {
    pub fn new(l2: Arc<L2cap>, gatt: Arc<GattManager>, devices: Arc<DeviceTable>, bus: Arc<EventBus>) -> Arc<Self> {
        Arc::new(HidHost { l2, gatt, devices, bus })
    }
    pub fn connect(&self, _device: &DeviceId, _handle: u16, _le: bool) -> Result<()> {
        Err(Error::NotSupported("HID host arrives in the next batch".into()))
    }
    pub fn disconnect(&self, _device: &DeviceId) -> Result<()> { Ok(()) }
}