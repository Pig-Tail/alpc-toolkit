// alpc-core/src/types.rs
//
// Undocumented ALPC structures from ntdll.dll
// These are NOT stable across Windows versions — validated on Windows 10/11

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub type USHORT = u16;
pub type UCHAR = u8;
pub type SIZE_T = usize;
pub type BOOLEAN = u8;
pub type PLARGE_INTEGER = *mut i64;

pub const NULL_HANDLE: HANDLE = std::ptr::null_mut();

// NT Status codes
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;
pub const STATUS_NO_MORE_ENTRIES: NTSTATUS = 0x8000001Au32 as i32;

// ALPC Port flags
pub const ALPC_PORFLG_ALLOW_LPC_REQUESTS: ULONG = 0x20000;
pub const ALPC_PORFLG_WAITABLE_PORT: ULONG = 0x40000;
pub const ALPC_PORFLG_SYSTEM_PROCESS: ULONG = 0x100000;
pub const ALPC_PORTFLG_ALLOWIMPERSONATION: ULONG = 0x10000;

// ALPC Message flags
pub const ALPC_MSGFLG_SYNC_REQUEST: ULONG = 0x20000;
pub const ALPC_MSGFLG_WAIT_REPLY: ULONG = 0x20000;

// ALPC Message attribute flags
pub const ALPC_MESSAGE_SECURITY_ATTRIBUTE: ULONG = 0x80000000;
pub const ALPC_MESSAGE_VIEW_ATTRIBUTE: ULONG = 0x40000000;
pub const ALPC_MESSAGE_CONTEXT_ATTRIBUTE: ULONG = 0x20000000;
pub const ALPC_MESSAGE_HANDLE_ATTRIBUTE: ULONG = 0x10000000;
pub const ALPC_MESSAGE_TOKEN_ATTRIBUTE: ULONG = 0x08000000;
pub const ALPC_MESSAGE_DIRECT_ATTRIBUTE: ULONG = 0x04000000;
pub const ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE: ULONG = 0x02000000;
pub const ALPC_MESSAGE_ATTRIBUTE_ALL: ULONG = ALPC_MESSAGE_SECURITY_ATTRIBUTE
    | ALPC_MESSAGE_VIEW_ATTRIBUTE
    | ALPC_MESSAGE_CONTEXT_ATTRIBUTE
    | ALPC_MESSAGE_HANDLE_ATTRIBUTE
    | ALPC_MESSAGE_TOKEN_ATTRIBUTE
    | ALPC_MESSAGE_DIRECT_ATTRIBUTE
    | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE;

// Object information classes
pub const OBJECT_DIRECTORY_INFORMATION_CLASS: u32 = 0;

// System information classes
pub const SYSTEM_HANDLE_INFORMATION_EX: u32 = 64;

// Object types
pub const OB_TYPE_INDEX_ALPC_PORT: u8 = 46; // May vary by Windows version — verify with WinDbg

// Process access rights
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;

// Directory access
pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;

// ---------------------------------------------------------------------
// PORT_MESSAGE — The header for every ALPC message
// This is the documented LPC structure that ALPC inherited
// ---------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PORT_MESSAGE {
    pub DataLength: USHORT,    // Size of data following the header
    pub TotalLength: USHORT,   // Total message size including header
    pub Type: USHORT,          // Message type (LPC_REQUEST, LPC_REPLY, etc.)
    pub DataInfoOffset: USHORT,
    pub ClientId: CLIENT_ID,
    pub MessageId: ULONG,
    pub ClientViewSize: SIZE_T, // Also used as CallbackId in union
}

impl PORT_MESSAGE {
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }

    pub fn init_for_send(&mut self, data_len: usize) {
        self.DataLength = data_len as USHORT;
        self.TotalLength = (std::mem::size_of::<PORT_MESSAGE>() + data_len) as USHORT;
    }
}

// ---------------------------------------------------------------------
// CLIENT_ID — Identifies a process/thread pair
// ---------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

// ---------------------------------------------------------------------
// UNICODE_STRING — NT native string type
// ---------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: *mut u16,
}

impl UNICODE_STRING {
    pub fn new() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        }
    }

    pub fn from_slice(s: &mut Vec<u16>) -> Self {
        let byte_len = (s.len() * 2) as u16;
        Self {
            Length: byte_len - 2, // exclude null terminator
            MaximumLength: byte_len,
            Buffer: s.as_mut_ptr(),
        }
    }

    pub unsafe fn to_string(&self) -> String {
        if self.Buffer.is_null() || self.Length == 0 {
            return String::new();
        }
        let slice = std::slice::from_raw_parts(self.Buffer, (self.Length / 2) as usize);
        String::from_utf16_lossy(slice)
    }
}

impl std::fmt::Debug for UNICODE_STRING {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = unsafe { self.to_string() };
        f.debug_struct("UNICODE_STRING")
            .field("value", &s)
            .finish()
    }
}

// ---------------------------------------------------------------------
// OBJECT_ATTRIBUTES — Required for most Nt* calls
// ---------------------------------------------------------------------
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

impl OBJECT_ATTRIBUTES {
    pub fn new(name: *mut UNICODE_STRING) -> Self {
        Self {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
            RootDirectory: NULL_HANDLE,
            ObjectName: name,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        }
    }
}

// OBJ_CASE_INSENSITIVE
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x40;

// ---------------------------------------------------------------------
// ALPC_PORT_ATTRIBUTES — Configures the ALPC port on creation
// ---------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ALPC_PORT_ATTRIBUTES {
    pub Flags: ULONG,
    pub SecurityQos: SECURITY_QUALITY_OF_SERVICE,
    pub MaxMessageLength: SIZE_T,
    pub MemoryBandwidth: SIZE_T,
    pub MaxPoolUsage: SIZE_T,
    pub MaxSectionSize: SIZE_T,
    pub MaxViewSize: SIZE_T,
    pub MaxTotalSectionSize: SIZE_T,
    pub DupObjectTypes: ULONG,
    #[cfg(target_arch = "x86_64")]
    pub Reserved: ULONG,
}

impl ALPC_PORT_ATTRIBUTES {
    pub fn new() -> Self {
        let mut attrs: Self = unsafe { std::mem::zeroed() };
        attrs.MaxMessageLength = 0x1000; // 4KB default
        attrs.SecurityQos = SECURITY_QUALITY_OF_SERVICE::new();
        attrs
    }
}

// ---------------------------------------------------------------------
// SECURITY_QUALITY_OF_SERVICE — Security context for impersonation
// ---------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_QUALITY_OF_SERVICE {
    pub Length: ULONG,
    pub ImpersonationLevel: u32,
    pub ContextTrackingMode: BOOLEAN,
    pub EffectiveOnly: BOOLEAN,
}

impl SECURITY_QUALITY_OF_SERVICE {
    pub fn new() -> Self {
        Self {
            Length: std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as ULONG,
            ImpersonationLevel: 2, // SecurityImpersonation
            ContextTrackingMode: 1, // SECURITY_DYNAMIC_TRACKING
            EffectiveOnly: 0,
        }
    }
}

// ---------------------------------------------------------------------
// ALPC_MESSAGE_ATTRIBUTES — Container for optional message attributes
// ---------------------------------------------------------------------
#[repr(C)]
pub struct ALPC_MESSAGE_ATTRIBUTES {
    pub AllocatedAttributes: ULONG,
    pub ValidAttributes: ULONG,
}

// Individual attribute structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_SECURITY_ATTR {
    pub Flags: ULONG,
    pub QOS: *mut SECURITY_QUALITY_OF_SERVICE,
    pub ContextHandle: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_DATA_VIEW_ATTR {
    pub Flags: ULONG,
    pub SectionHandle: HANDLE,
    pub ViewBase: PVOID,
    pub ViewSize: SIZE_T,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_CONTEXT_ATTR {
    pub PortContext: PVOID,
    pub MessageContext: PVOID,
    pub Sequence: ULONG,
    pub MessageId: ULONG,
    pub CallbackId: ULONG,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_TOKEN_ATTR {
    pub TokenId: u64,
    pub AuthenticationId: u64,
    pub ModifiedId: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_DIRECT_ATTR {
    pub Event: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ALPC_WORK_ON_BEHALF_ATTR {
    pub Ticket: u64,
}

// ---------------------------------------------------------------------
// ALPC_MESSAGE — Complete message with header + body
// Maximum message body is 65535 - sizeof(PORT_MESSAGE) bytes
// ---------------------------------------------------------------------
pub const MAX_ALPC_MESSAGE_BODY: usize = 0x1000; // 4KB for practical use

#[repr(C)]
pub struct ALPC_MESSAGE {
    pub header: PORT_MESSAGE,
    pub body: [u8; MAX_ALPC_MESSAGE_BODY],
}

impl ALPC_MESSAGE {
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }

    pub fn set_body(&mut self, data: &[u8]) {
        let len = data.len().min(MAX_ALPC_MESSAGE_BODY);
        self.body[..len].copy_from_slice(&data[..len]);
        self.header.init_for_send(len);
    }

    pub fn get_body(&self) -> &[u8] {
        &self.body[..self.header.DataLength as usize]
    }

    pub fn get_body_str(&self) -> String {
        let bytes = self.get_body();
        // Try UTF-16 first (Windows default), then UTF-8
        if bytes.len() >= 2 && bytes.len() % 2 == 0 {
            let u16_slice: &[u16] = unsafe {
                std::slice::from_raw_parts(bytes.as_ptr() as *const u16, bytes.len() / 2)
            };
            if let Ok(s) = String::from_utf16(u16_slice) {
                if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
                    return s;
                }
            }
        }
        String::from_utf8_lossy(bytes).to_string()
    }
}

// ---------------------------------------------------------------------
// System handle information structures
// Used for enumerating ALPC port handles across all processes
// ---------------------------------------------------------------------
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION_EX_STRUCT {
    pub NumberOfHandles: usize,
    pub Reserved: usize,
    // Followed by SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub Object: PVOID,
    pub UniqueProcessId: usize,
    pub HandleValue: usize,
    pub GrantedAccess: ULONG,
    pub CreatorBackTraceIndex: USHORT,
    pub ObjectTypeIndex: USHORT,
    pub HandleAttributes: ULONG,
    pub Reserved: ULONG,
}

// ---------------------------------------------------------------------
// OBJECT_DIRECTORY_INFORMATION — For enumerating directory entries
// ---------------------------------------------------------------------
#[repr(C)]
pub struct OBJECT_DIRECTORY_INFORMATION {
    pub Name: UNICODE_STRING,
    pub TypeName: UNICODE_STRING,
}

// IO_STATUS_BLOCK
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status: NTSTATUS,
    pub Information: usize,
}

impl IO_STATUS_BLOCK {
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
