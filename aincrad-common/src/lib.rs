#![no_std] 

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilterEntry {
    pub ip_addr: u32,
    pub action: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReputationRecord {
    pub balance: u32,
    pub ban_until: u64,
}

pub unsafe trait Pod {}
unsafe impl Pod for ReputationRecord {}
