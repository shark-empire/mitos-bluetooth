use crate::device::{DeviceId, DeviceTable};
use crate::error::{Error, Result};
use crate::events::EventBus;
use crate::hci::HciClient;
use crate::l2cap::L2cap;
use std::sync::Arc;

/// A2DP (AVDTP), AVRCP, HFP/HSP (RFCOMM + SCO). Arrives after the HID batch.
pub struct AudioManager {
    pub hci: Arc<HciClient>,
    pub l2: Arc<L2cap>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
}

impl AudioManager {
    pub fn new(hci: Arc<HciClient>, l2: Arc<L2cap>, devices: Arc<DeviceTable>, bus: Arc<EventBus>) -> Arc<Self> {
        Arc::new(AudioManager { hci, l2, devices, bus })
    }
    pub fn connect_a2dp(&self, _d: &DeviceId, _h: u16) -> Result<()> { Err(Error::NotSupported("A2DP arrives with the audio batch".into())) }
    pub fn connect_avrcp(&self, _d: &DeviceId, _h: u16) -> Result<()> { Err(Error::NotSupported("AVRCP arrives with the audio batch".into())) }
    pub fn connect_hfp(&self, _d: &DeviceId, _h: u16) -> Result<()> { Err(Error::NotSupported("HFP arrives with the audio batch".into())) }
    pub fn connect_hsp(&self, _d: &DeviceId, _h: u16) -> Result<()> { Err(Error::NotSupported("HSP arrives with the audio batch".into())) }
    pub fn disconnect(&self, _d: &DeviceId) -> Result<()> { Ok(()) }
}