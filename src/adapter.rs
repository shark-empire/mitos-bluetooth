use crate::device::Address;
use crate::error::{Error, Result};
use crate::hci::{op, HciClient, HciTransport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BluetoothState { Off, TurningOn, On, TurningOff, Error(String) }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterInfo {
    pub index: u32,
    pub address: Address,
    pub name: String,
    pub powered: bool,
    pub discoverable: bool,
    pub connectable: bool,
    pub discovering: bool,
    pub class: u32,
    pub version: String,
    pub manufacturer: String,
    pub le_supported: bool,
}

pub fn manufacturer_name(m: u16) -> String {
    match m {
        0x0001 => "Ericsson".into(), 0x0002 => "Nokia".into(), 0x0003 => "Intel".into(),
        0x000a => "CSR".into(), 0x000d => "Texas Instruments".into(), 0x000f => "Broadcom".into(),
        0x005d => "Realtek".into(), 0x0002 => "Nokia".into(), _ => format!("0x{m:04x}"),
    }
}
pub fn hci_version_text(v: u8) -> String {
    match v { 0x03 => "2.0".into(), 0x04 => "3.0".into(), 0x05 => "4.0".into(), 0x06 => "4.1".into(), 0x07 => "4.2".into(), 0x08 => "5.0".into(), 0x09 => "5.1".into(), 0x0a => "5.2".into(), 0x0b => "5.3".into(), 0x0c => "5.4".into(), _ => format!("0x{v:02x}") }
}

pub struct BluetoothAdapter { pub hci: Arc<HciClient> }

impl BluetoothAdapter {
    pub fn open(index: u32) -> Result<Self> {
        let tr = crate::hci::open_hci_user_channel(index)?;
        Ok(BluetoothAdapter { hci: Arc::new(HciClient::open(index, Box::new(tr))?) })
    }

    /// Full controller bring-up. Returns the discovered adapter info.
    pub fn init(&self, name: &str, discoverable: bool) -> Result<AdapterInfo> {
        self.hci.command(op::RESET, &[])?;
        let mask = u64::MAX.to_le_bytes();
        self.hci.command(op::SET_EVENT_MASK, &mask)?;
        let addr = { let r = self.hci.command(op::READ_BD_ADDR, &[])?; Address(r[1..7].try_into().unwrap()) };
        let (ver, mfr) = {
            let r = self.hci.command(op::READ_LOCAL_VERSION, &[])?;
            (r[1], u16::from_le_bytes([r[5], r[6]]))
        };
        let le = {
            let r = self.hci.command(op::READ_LOCAL_SUPPORTED_FEATURES, &[])?;
            r.len() >= 5 && r[4] & 0x02 != 0 // LMP feature bit 25 = LE supported (byte 3 of features)
        };
        let _ = self.hci.command(op::READ_BUFFER_SIZE, &[]);
        self.hci.command(op::WRITE_PAGE_TIMEOUT, &0x2000u16.to_le_bytes())?;
        let mut n = [0u8; 248];
        let nb = name.as_bytes();
        n[..nb.len().min(248)].copy_from_slice(&nb[..nb.len().min(248)]);
        self.hci.command(op::WRITE_LOCAL_NAME, &n)?;
        let cod = 0x0104u32; // Computer / Desktop
        self.hci.command(op::WRITE_CLASS_OF_DEVICE, &cod.to_le_bytes()[..3].to_vec())?;
        self.hci.command(op::WRITE_INQUIRY_MODE, &[0x02])?;
        self.hci.command(op::WRITE_SIMPLE_PAIRING_MODE, &[0x01])?;
        if le { let _ = self.hci.command(op::WRITE_LE_HOST_SUPPORT, &[0x01]); }
        // EIR: flags + complete local name
        let mut eir = vec![2, 0x01, 0x06];
        let namelen = nb.len().min(232) as u8;
        eir.push(namelen + 1); eir.push(0x09); eir.extend_from_slice(&nb[..namelen as usize]);
        eir.resize(1 + 240, 0);
        let mut e = vec![0x00]; e.extend_from_slice(&eir);
        self.hci.command(op::WRITE_EXTENDED_INQUIRY_RESPONSE, &e)?;
        let scan = if discoverable { 0x03 } else { 0x02 }; // page scan (+ inquiry scan)
        self.hci.command(op::WRITE_SCAN_ENABLE, &[scan])?;
        Ok(AdapterInfo {
            index: self.hci.index(), address: addr, name: name.to_string(),
            powered: true, discoverable, connectable: true, discovering: false,
            class: cod, version: hci_version_text(ver), manufacturer: manufacturer_name(mfr), le_supported: le,
        })
    }

    pub fn set_scan(&self, discoverable: bool, connectable: bool) -> Result<()> {
        let scan = (if discoverable { 1 } else { 0 }) | (if connectable { 2 } else { 0 });
        self.hci.command(op::WRITE_SCAN_ENABLE, &[scan])
    }
    pub fn set_name(&self, name: &str) -> Result<()> {
        let mut n = [0u8; 248];
        let nb = name.as_bytes();
        n[..nb.len().min(248)].copy_from_slice(&nb[..nb.len().min(248)]);
        self.hci.command(op::WRITE_LOCAL_NAME, &n)?;
        let mut eir = vec![2, 0x01, 0x06];
        let namelen = nb.len().min(232) as u8;
        eir.push(namelen + 1); eir.push(0x09); eir.extend_from_slice(&nb[..namelen as usize]);
        eir.resize(1 + 240, 0);
        let mut e = vec![0x00]; e.extend_from_slice(&eir);
        self.hci.command(op::WRITE_EXTENDED_INQUIRY_RESPONSE, &e)
    }
    pub fn off(&self) -> Result<()> {
        let _ = self.hci.command(op::WRITE_SCAN_ENABLE, &[0x00]);
        self.hci.shutdown();
        Ok(())
    }
}