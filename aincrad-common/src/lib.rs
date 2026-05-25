#![no_std] 

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilterEntry {
    pub ip_addr: u32,
    pub action: u8,
}
