#![no_std]
#![no_main]

use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::bindings::xdp_action;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
pub fn aincrad_xdp(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}
