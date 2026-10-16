use crate::error::{Error, Result};
use crate::l2cap::{L2Packet, L2cap, PSM_SDP};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default, Debug, Clone)]
pub struct SdpService {
    pub psm: Option<u16>,
    pub rfcomm_channel: Option<u8>,
    pub name: Option<String>,
    pub version: Option<u16>,
    pub hid_descriptor: Option<Vec<u8>>,
    pub service_classes: Vec<u16>,
}

#[derive(Debug, Clone)]
pub enum De {
    U(u128),
    Uuid(u128),
    Str(Vec<u8>),
    Bool(bool),
    Seq(Vec<De>),
}

/// Remote devices are untrusted: bound the nesting we are willing to follow.
const MAX_DEPTH: u32 = 8;

fn truncated() -> Error {
    Error::Sdp("truncated data element".into())
}

/// Parse one SDP data element (big-endian) starting at `*i`; advances `*i` past it.
/// Never panics, whatever the bytes.
pub fn parse_de(b: &[u8], i: &mut usize) -> Result<De> {
    parse_de_depth(b, i, 0)
}

fn parse_de_depth(b: &[u8], i: &mut usize, depth: u32) -> Result<De> {
    if depth > MAX_DEPTH {
        return Err(Error::Sdp("data elements nested too deeply".into()));
    }
    let h = *b.get(*i).ok_or_else(truncated)?;
    *i += 1;
    let ty = h >> 3;
    let size_index = h & 7;
    // size descriptor: 0..=4 are fixed sizes 1/2/4/8/16 bytes; 5/6/7 carry a 1/2/4 byte length
    let len: usize = if ty == 0 {
        0 // nil carries no data
    } else {
        match size_index {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            4 => 16,
            5 => {
                let l = *b.get(*i).ok_or_else(truncated)?;
                *i += 1;
                usize::from(l)
            }
            6 => {
                let hdr = b.get(*i..*i + 2).ok_or_else(truncated)?;
                *i += 2;
                usize::from(u16::from_be_bytes([hdr[0], hdr[1]]))
            }
            _ => {
                let hdr = b.get(*i..*i + 4).ok_or_else(truncated)?;
                *i += 4;
                u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize
            }
        }
    };
    let start = *i;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= b.len())
        .ok_or_else(|| Error::Sdp("data element overruns the buffer".into()))?;
    let body = &b[start..end];
    let val = match ty {
        0 => De::U(0),
        1..=3 => {
            if body.len() > 16 {
                return Err(Error::Sdp("integer wider than 128 bits".into()));
            }
            let v = body.iter().fold(0u128, |acc, x| (acc << 8) | u128::from(*x));
            if ty == 3 {
                De::Uuid(v)
            } else {
                De::U(v) // signed integers are never needed; the raw bits are kept
            }
        }
        4 | 8 => De::Str(body.to_vec()),
        5 => De::Bool(body.first().copied().unwrap_or(0) != 0),
        6 | 7 => {
            // children are parsed from a slice that stops at the end of this element
            let sub = &b[..end];
            let mut kids = Vec::new();
            while *i < end {
                kids.push(parse_de_depth(sub, i, depth + 1)?);
            }
            De::Seq(kids)
        }
        _ => De::U(0),
    };
    *i = end;
    Ok(val)
}

/// 16-bit alias of a UUID element (16-bit, 32-bit or 128-bit-on-the-Bluetooth-base-UUID).
fn short_uuid(u: u128) -> Option<u16> {
    const BASE_TAIL: u128 = 0x0000_1000_8000_0080_5F9B_34FB; // low 96 bits of 0000xxxx-0000-1000-8000-00805F9B34FB
    let v = if u >> 32 == 0 {
        u
    } else if u & ((1u128 << 96) - 1) == BASE_TAIL {
        u >> 96
    } else {
        return None;
    };
    u16::try_from(v).ok()
}

/// ServiceSearchAttributeRequest parameters (Core Vol 3 Part B 4.7.1) for one 16-bit service class:
/// pattern = DES{UUID16}, max attribute bytes = 0xFFFF (a plain 2-byte field), attribute IDs = DES{range 0x0000-0xFFFF},
/// then the continuation state.
fn build_ssa_request(uuid16: u16, cont: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(15 + cont.len());
    p.extend_from_slice(&[0x35, 0x03, 0x19]);
    p.extend_from_slice(&uuid16.to_be_bytes());
    p.extend_from_slice(&0xFFFFu16.to_be_bytes());
    p.extend_from_slice(&[0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff]);
    p.push(cont.len() as u8);
    p.extend_from_slice(cont);
    p
}

pub struct SdpClient {
    l2: Arc<L2cap>,
    cid: u16,
    tid: u16,
    rx: Receiver<L2Packet>,
}

impl SdpClient {
    pub fn connect(l2: Arc<L2cap>, handle: u16) -> Result<Self> {
        let cid = l2.connect(handle, PSM_SDP)?;
        let (tx, rx) = channel();
        l2.register_handler(cid, tx);
        Ok(SdpClient { l2, cid, tid: 1, rx })
    }

    /// Fetch every attribute of the first record matching `uuid16`, following continuation state.
    pub fn query(&mut self, uuid16: u16) -> Result<SdpService> {
        let mut attrs: Vec<u8> = Vec::new();
        let mut cont: Vec<u8> = Vec::new();
        for _ in 0..16 {
            let resp = self.transaction(0x06, &build_ssa_request(uuid16, &cont))?;
            if resp.len() < 3 {
                return Err(Error::Sdp("short attribute response".into()));
            }
            // AttributeListsByteCount(2) AttributeLists(n) ContinuationState(1 + m)
            let count = usize::from(u16::from_be_bytes([resp[0], resp[1]]));
            let body_end = (2 + count).min(resp.len());
            attrs.extend_from_slice(&resp[2..body_end]);
            let cont_len = usize::from(resp.get(body_end).copied().unwrap_or(0));
            if cont_len == 0 {
                break;
            }
            cont = resp.get(body_end + 1..body_end + 1 + cont_len).unwrap_or(&[]).to_vec();
            if cont.is_empty() {
                break;
            }
        }
        if attrs.is_empty() {
            return Err(Error::NotFound(format!("no sdp record for service 0x{uuid16:04x}")));
        }
        parse_attribute_lists(&attrs)
    }

    fn transaction(&mut self, pdu: u8, params: &[u8]) -> Result<Vec<u8>> {
        let tid = self.tid;
        self.tid = self.tid.wrapping_add(1);
        let mut pkt = vec![pdu];
        pkt.extend_from_slice(&tid.to_be_bytes());
        pkt.extend_from_slice(&(params.len() as u16).to_be_bytes());
        pkt.extend_from_slice(params);
        self.l2.send(self.cid, &pkt)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let p = self.rx.recv_timeout(left).map_err(|_| Error::Timeout("sdp"))?;
            if p.closed {
                return Err(Error::Sdp("sdp channel closed".into()));
            }
            let d = &p.data;
            if d.len() >= 5 && u16::from_be_bytes([d[1], d[2]]) == tid {
                if d[0] == pdu + 1 {
                    return Ok(d[5..].to_vec());
                }
                if d[0] == 0x01 {
                    // SDP_ErrorResponse: ErrorCode(2)
                    let code = u16::from_be_bytes([d.get(5).copied().unwrap_or(0), d.get(6).copied().unwrap_or(0)]);
                    return Err(Error::Sdp(format!("error response 0x{code:04x}")));
                }
            }
        }
    }
}

/// Decode the AttributeLists of a ServiceSearchAttributeResponse.
pub fn parse_attribute_lists(raw: &[u8]) -> Result<SdpService> {
    let mut svc = SdpService::default();
    let mut i = 0;
    // attributeLists = SEQ of attributeList; each attributeList = SEQ of (id, value) pairs
    let outer = parse_de(raw, &mut i)?;
    let De::Seq(lists) = outer else {
        return Err(Error::Sdp("attributeLists is not a sequence".into()));
    };
    for list in &lists {
        let De::Seq(pairs) = list else { continue };
        let mut k = 0;
        while k + 1 < pairs.len() {
            let id = match &pairs[k] {
                De::U(v) => *v as u16,
                _ => {
                    k += 1;
                    continue;
                }
            };
            let val = &pairs[k + 1];
            k += 2;
            match id {
                0x0001 => {
                    if let De::Seq(items) = val {
                        for it in items {
                            if let De::Uuid(u) = it {
                                if let Some(s) = short_uuid(*u) {
                                    svc.service_classes.push(s);
                                }
                            }
                        }
                    }
                }
                0x0004 => {
                    if let De::Seq(layers) = val {
                        for layer in layers {
                            let De::Seq(parts) = layer else { continue };
                            let mut it = parts.iter();
                            let uuid = match it.next() {
                                Some(De::Uuid(u)) => short_uuid(*u),
                                _ => continue,
                            };
                            match uuid {
                                Some(0x0100) => {
                                    if let Some(De::U(p)) = it.next() {
                                        if svc.psm.is_none() {
                                            svc.psm = Some(*p as u16);
                                        }
                                    }
                                }
                                Some(0x0003) => {
                                    if let Some(De::U(c)) = it.next() {
                                        if svc.rfcomm_channel.is_none() {
                                            svc.rfcomm_channel = Some(*c as u8);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                0x0009 => {
                    if let De::Seq(items) = val {
                        if let Some(De::Seq(pair)) = items.first() {
                            if let [De::Uuid(_), De::U(v)] = pair.as_slice() {
                                svc.version = Some(*v as u16);
                            }
                        }
                    }
                }
                0x0100 => {
                    if let De::Str(s) = val {
                        svc.name = Some(String::from_utf8_lossy(s).to_string());
                    }
                }
                0x0206 => {
                    if let De::Seq(items) = val {
                        for item in items {
                            if let De::Seq(pair) = item {
                                if let [De::U(t), De::Str(d)] = pair.as_slice() {
                                    if *t as u16 == 0x22 {
                                        svc.hid_descriptor = Some(d.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(svc)
}

impl Drop for SdpClient {
    fn drop(&mut self) {
        let _ = self.l2.disconnect(self.cid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_search_attribute_request_is_well_formed() {
        assert_eq!(
            build_ssa_request(0x1124, &[]),
            vec![0x35, 0x03, 0x19, 0x11, 0x24, 0xff, 0xff, 0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff, 0x00]
        );
        let with_cont = build_ssa_request(0x1124, &[0xaa, 0xbb]);
        assert_eq!(with_cont[14..], [0x02, 0xaa, 0xbb]);
    }

    #[test]
    fn protocol_descriptor_list_yields_the_l2cap_psm() {
        // SEQ{ SEQ{ id 0x0004, SEQ{ SEQ{UUID 0x0100, uint16 0x0011}, SEQ{UUID 0x0011} } } }
        let raw = [
            0x35, 0x14, 0x35, 0x12, 0x09, 0x00, 0x04, 0x35, 0x0d, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x11, 0x35,
            0x03, 0x19, 0x00, 0x11,
        ];
        let svc = parse_attribute_lists(&raw).unwrap();
        assert_eq!(svc.psm, Some(0x0011));
        assert_eq!(svc.rfcomm_channel, None);
    }

    #[test]
    fn rfcomm_channel_and_name_are_found() {
        // protocol list: L2CAP, RFCOMM channel 7; service name "AG"
        let raw = [
            0x35, 0x1a, 0x35, 0x18, 0x09, 0x00, 0x04, 0x35, 0x0c, 0x35, 0x03, 0x19, 0x01, 0x00, 0x35, 0x05, 0x19, 0x00,
            0x03, 0x08, 0x07, 0x09, 0x01, 0x00, 0x25, 0x02, 0x41, 0x47,
        ];
        let svc = parse_attribute_lists(&raw).unwrap();
        assert_eq!(svc.rfcomm_channel, Some(7));
        assert_eq!(svc.name.as_deref(), Some("AG"));
    }

    #[test]
    fn hostile_input_is_an_error_not_a_panic() {
        assert!(parse_attribute_lists(&[]).is_err());
        assert!(parse_attribute_lists(&[0x35, 0xff, 0x09]).is_err()); // length runs past the end
        assert!(parse_attribute_lists(&[0x36, 0xff, 0xff, 0x00]).is_err()); // 2-byte length runs past the end
        assert!(parse_attribute_lists(&[0x3f]).is_err()); // 4-byte length missing
                                                          // 21 properly sized, nested sequences: deeper than we are willing to follow
        let mut nested = vec![0x35, 0x00];
        for _ in 0..20 {
            let mut wrapped = vec![0x35, nested.len() as u8];
            wrapped.extend_from_slice(&nested);
            nested = wrapped;
        }
        assert!(parse_attribute_lists(&nested).is_err());
    }

    #[test]
    fn long_uuids_on_the_base_uuid_map_to_their_short_form() {
        assert_eq!(short_uuid(0x110b), Some(0x110b));
        assert_eq!(short_uuid(0x0000_110b_0000_1000_8000_0080_5f9b_34fb), Some(0x110b));
        assert_eq!(short_uuid(0x1234_5678_9abc_def0_1234_5678_9abc_def0), None);
    }
}
