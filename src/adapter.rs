use crate::device::Address;
use crate::error::{Error, Result};
use crate::hci::{op, HciClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BluetoothState {
    Off,
    TurningOn,
    On,
    TurningOff,
    Error(String),
}

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
        0x0001 => "Ericsson".into(),
        0x0002 => "Nokia".into(),
        0x0003 => "Intel".into(),
        0x000a => "CSR".into(),
        0x000d => "Texas Instruments".into(),
        0x000f => "Broadcom".into(),
        0x005d => "Realtek".into(),
        _ => format!("0x{m:04x}"),
    }
}

pub fn hci_version_text(v: u8) -> String {
    match v {
        0x03 => "2.0".into(),
        0x04 => "3.0".into(),
        0x05 => "4.0".into(),
        0x06 => "4.1".into(),
        0x07 => "4.2".into(),
        0x08 => "5.0".into(),
        0x09 => "5.1".into(),
        0x0a => "5.2".into(),
        0x0b => "5.3".into(),
        0x0c => "5.4".into(),
        _ => format!("0x{v:02x}"),
    }
}

/// Local name field: 248 bytes, NUL padded.
fn name_field(name: &str) -> [u8; 248] {
    let mut n = [0u8; 248];
    let nb = name.as_bytes();
    let len = nb.len().min(248);
    n[..len].copy_from_slice(&nb[..len]);
    n
}

/// Extended Inquiry Response: FEC_Required(1) + 240 bytes of data (flags + complete local name).
fn eir_payload(name: &str) -> Vec<u8> {
    let nb = name.as_bytes();
    let namelen = nb.len().min(232);
    let mut data = vec![2, 0x01, 0x06];
    data.push(namelen as u8 + 1);
    data.push(0x09);
    data.extend_from_slice(&nb[..namelen]);
    data.resize(240, 0);
    let mut payload = vec![0x00];
    payload.extend_from_slice(&data);
    payload
}

pub struct BluetoothAdapter {
    pub hci: Arc<HciClient>,
}

impl BluetoothAdapter {
    pub fn open(index: u32) -> Result<Self> {
        let tr = crate::hci::open_hci_user_channel(index)?;
        Ok(BluetoothAdapter { hci: Arc::new(HciClient::open(index, Box::new(tr))?) })
    }

    /// A command the controller may legitimately not implement: report, carry on.
    fn optional(&self, opcode: u16, params: &[u8]) {
        if let Err(e) = self.hci.command(opcode, params) {
            eprintln!("[adapter] optional command 0x{opcode:04x} failed: {e}");
        }
    }

    /// Full controller bring-up. Returns the discovered adapter info.
    pub fn init(&self, name: &str, discoverable: bool) -> Result<AdapterInfo> {
        self.hci.command(op::RESET, &[])?;
        self.optional(op::SET_EVENT_MASK, &u64::MAX.to_le_bytes());

        // Read BD_ADDR return: status(1) + address(6)
        let addr = {
            let r = self.hci.command(op::READ_BD_ADDR, &[])?;
            let b: [u8; 6] = r
                .get(1..7)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| Error::InvalidState("short Read BD_ADDR reply".into()))?;
            Address(b)
        };
        // Read Local Version return: status, hci_version, hci_revision(2), lmp_version, manufacturer(2), lmp_subversion(2)
        let (ver, mfr) = {
            let r = self.hci.command(op::READ_LOCAL_VERSION, &[])?;
            if r.len() < 7 {
                return Err(Error::InvalidState("short Read Local Version reply".into()));
            }
            (r[1], u16::from_le_bytes([r[5], r[6]]))
        };
        // Read Local Supported Features return: status + 8 LMP feature bytes. Features byte 4 holds
        // bit 5 "BR/EDR not supported" (0x20) and bit 6 "LE supported (controller)" (0x40).
        let (le, bredr) = {
            let r = self.hci.command(op::READ_LOCAL_SUPPORTED_FEATURES, &[])?;
            let byte4 = r.get(5).copied().unwrap_or(0);
            (byte4 & 0x40 != 0, byte4 & 0x20 == 0)
        };

        self.optional(op::READ_BUFFER_SIZE, &[]);
        if le {
            self.optional(op::LE_READ_BUFFER_SIZE, &[]);
        }
        let cod = 0x0104u32; // Computer / Desktop
        if bredr {
            self.optional(op::WRITE_PAGE_TIMEOUT, &0x2000u16.to_le_bytes());
            self.hci.command(op::WRITE_LOCAL_NAME, &name_field(name))?;
            self.hci.command(op::WRITE_CLASS_OF_DEVICE, &cod.to_le_bytes()[..3])?;
            self.optional(op::WRITE_INQUIRY_MODE, &[0x02]);
            self.hci.command(op::WRITE_SIMPLE_PAIRING_MODE, &[0x01])?;
            self.optional(op::WRITE_EXTENDED_INQUIRY_RESPONSE, &eir_payload(name));
        }
        if le && bredr {
            // Write LE Host Support: LE_Supported_Host, Simultaneous_LE_Host (two parameters)
            self.optional(op::WRITE_LE_HOST_SUPPORT, &[0x01, 0x00]);
        }
        if bredr {
            let scan = if discoverable { 0x03 } else { 0x02 }; // page scan (+ inquiry scan)
            self.hci.command(op::WRITE_SCAN_ENABLE, &[scan])?;
        }
        Ok(AdapterInfo {
            index: self.hci.index(),
            address: addr,
            name: name.to_string(),
            powered: true,
            discoverable,
            connectable: bredr,
            discovering: false,
            class: cod,
            version: hci_version_text(ver),
            manufacturer: manufacturer_name(mfr),
            le_supported: le,
        })
    }

    pub fn set_scan(&self, discoverable: bool, connectable: bool) -> Result<()> {
        let scan = u8::from(discoverable) | (u8::from(connectable) << 1);
        self.hci.command(op::WRITE_SCAN_ENABLE, &[scan])?;
        Ok(())
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        self.hci.command(op::WRITE_LOCAL_NAME, &name_field(name))?;
        self.hci.command(op::WRITE_EXTENDED_INQUIRY_RESPONSE, &eir_payload(name))?;
        Ok(())
    }

    /// Stop being visible/connectable and release the controller.
    pub fn off(&self) -> Result<()> {
        let _ = self.hci.command(op::WRITE_SCAN_ENABLE, &[0x00]);
        self.hci.shutdown();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eir_payload_is_fec_byte_plus_240_data_bytes() {
        let p = eir_payload("mitos");
        assert_eq!(p.len(), 241);
        assert_eq!(p[0], 0x00); // FEC not required
        assert_eq!(p[1..4], [2, 0x01, 0x06]); // flags: LE general discoverable + BR/EDR not supported
        assert_eq!(p[4], 6); // name AD: type + 5 bytes
        assert_eq!(p[5], 0x09);
        assert_eq!(&p[6..11], b"mitos");
        assert!(p[11..].iter().all(|&b| b == 0));
        assert_eq!(eir_payload(&"x".repeat(500)).len(), 241);
    }

    #[test]
    fn local_name_field_is_248_bytes() {
        let n = name_field("hello");
        assert_eq!(&n[..5], b"hello");
        assert!(n[5..].iter().all(|&b| b == 0));
        assert_eq!(name_field(&"y".repeat(400)).len(), 248);
    }
}
