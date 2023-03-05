use core::mem;

use crate::bindings::{ethhdr, iphdr};

/*
* Ethernet frame
*
*
*
*
*
*
*
*
* */

pub const IPPROTO_TCP: u8 = 0x0006; /* 6 decimal RFC 768 https://www.rfc-editor.org/rfc/rfc768#ref-5*/
pub const IPPROTO_UDP: u8 = 0x0011; /* 17 decimal RFC 768 https://www.rfc-editor.org/rfc/rfc768#ref-5*/
pub const ETHERNET_PROTOCOL_IP: u16 = 0x0800; /* RFC 894 https://www.rfc-editor.org/rfc/rfc894 */
pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
