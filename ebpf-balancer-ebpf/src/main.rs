#![no_std]
#![no_main]

mod bindings;
mod constants;

use core::mem;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use ebpf_balancer_common::UdpBackendPorts;

use crate::bindings::{ethhdr, iphdr, udphdr, tcphdr};
use crate::constants::{ETHERNET_PROTOCOL_IP, ETH_HDR_LEN, IPPROTO_UDP, IP_HDR_LEN};

#[map(name = "UDP_BACKEND_PORTS")]
static mut UDP_BACKEND_PORTS: HashMap<u16, UdpBackendPorts> =
    HashMap::<u16, UdpBackendPorts>::with_max_entries(10, 0);

#[inline(always)]
fn prt_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    };

    Some((start + offset) as *const T)
}

#[inline(always)]
fn prt_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let prt = prt_at::<T>(ctx, offset)?;
    Some(prt as *mut T)
}

#[xdp(name = "ebpf_balancer")]
pub fn ebpf_balancer(ctx: XdpContext) -> u32 {
    match try_ebpf_balancer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn balance_udp_packet(ctx: XdpContext) -> Result<u32, u32> {
    // by now we know that this is an IP packet inside an ethernet frame
    let ip_prt = prt_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let ip = unsafe { *ip_prt };

    let ip_addresses = unsafe /* both fields of this union in this case have the same layout */ {
        ip.__bindgen_anon_1.addrs
    };
    let source_addr: [u8; 4] = u32::to_le_bytes(ip_addresses.saddr);

    let udp_prt =
        prt_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let udp = unsafe { *udp_prt };
    let destination_port = u16::from_be(udp.dest);
    let source_port = udp.source;

    info!(
        &ctx,
        "Got UDP Packet on port {} from {}.{}.{}.{}:{}",
        destination_port,
        source_addr[0],
        source_addr[1],
        source_addr[2],
        source_addr[3],
        source_port
    );

    let backends = match unsafe { UDP_BACKEND_PORTS.get(&destination_port) } {
        Some(backends) => {
            info!(&ctx, "Backends found for port {}", destination_port);
            backends
        }
        None => {
            info!(&ctx, "No backends found for port {}", destination_port);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if backends.index > backends.ports.len() - 1 {
        return Ok(xdp_action::XDP_ABORTED);
    };

    let new_destination_port = backends.ports[backends.index];
    unsafe { (*udp_prt).dest = u16::from_be(new_destination_port) };

    info!(
        &ctx,
        "redirected port {} to {}", destination_port, new_destination_port
    );

    let mut new_backends = UdpBackendPorts {
        ports: backends.ports,
        index: backends.index + 1,
    };

    if new_backends.index > new_backends.ports.len() - 1
        || new_backends.ports[new_backends.index] == 0
    {
        new_backends.index = 0;
    };

    match unsafe { UDP_BACKEND_PORTS.insert(&destination_port, &new_backends, 0) } {
        Ok(_) => Ok(xdp_action::XDP_PASS),
        Err(err) => {
            info!(&ctx, "Failed to update udp backend: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}

fn balance_tcp_packet(ctx: XdpContext) -> Result<u32, u32> {
    // by now we know that this is an IP packet inside an ethernet frame
    let ip_prt = prt_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let ip = unsafe { *ip_prt };

    let ip_addresses = unsafe /* both fields of this union in this case have the same layout */ {
        ip.__bindgen_anon_1.addrs
    };
    let source_addr: [u8; 4] = u32::to_le_bytes(ip_addresses.saddr);

    let tcp_prt = prt_at::<tcphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let tcp = unsafe { *tcp_prt };

    let destination_port = u16::from_be(tcp.dest);
    let source_port = tcp.source;

    info!(
        &ctx,
        "Got TCP Packet on port {} from {}.{}.{}.{}:{}",
        destination_port,
        source_addr[0],
        source_addr[1],
        source_addr[2],
        source_addr[3],
        source_port
    );

    Ok(xdp_action::XDP_PASS)
}

fn try_ebpf_balancer(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    // The Ethernet header is at the beginning of the datagram
    let eth = prt_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    // Check if Ethernet header contains an IP payload
    // If not an IP packet, ignore it
    if u16::from_be(unsafe { *eth }.h_proto) != ETHERNET_PROTOCOL_IP {
        return Ok(xdp_action::XDP_PASS);
    };

    let ip_prt = prt_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let ip = unsafe { *ip_prt };
    // Check if IP header contains a valid payload
    match ip.protocol {
        IPPROTO_UDP => balance_udp_packet(ctx),
        IPPROTO_TCP => balance_tcp_packet(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
