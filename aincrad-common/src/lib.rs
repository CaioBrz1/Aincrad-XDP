#![no_std]


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterEntry {
    pub ip_addr: u32,
    pub action: u8,
}

impl FilterEntry {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        
        unsafe {
            Some(core::ptr::read_unaligned(bytes.as_ptr() as *const Self))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReputationRecord {
    pub balance: u32,
    pub _padding: u32,
    pub ban_until: u64,
    pub last_updated: u64,
}

