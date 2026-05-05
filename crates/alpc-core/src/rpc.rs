// alpc-core/src/rpc.rs
//
// RPC Interface structures for enumerating and parsing RPC servers
// Reference: MS-RPCE specification, RPCView source code

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use crate::types::*;

/// RPC Interface UUID (128-bit) — identifies an RPC interface
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RPC_IF_ID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

impl RPC_IF_ID {
    pub fn is_null(&self) -> bool {
        self.Data1 == 0 && self.Data2 == 0 && self.Data3 == 0 && self.Data4 == [0u8; 8]
    }
}

impl std::fmt::Display for RPC_IF_ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.Data1,
            self.Data2,
            self.Data3,
            self.Data4[0],
            self.Data4[1],
            self.Data4[2],
            self.Data4[3],
            self.Data4[4],
            self.Data4[5],
            self.Data4[6],
            self.Data4[7],
        )
    }
}

impl std::fmt::Debug for RPC_IF_ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

/// RPC_SYNTAX_IDENTIFIER — UUID + version
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RPC_SYNTAX_IDENTIFIER {
    pub SyntaxGUID: RPC_IF_ID,
    pub SyntaxVersion: RPC_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RPC_VERSION {
    pub MajorVersion: u16,
    pub MinorVersion: u16,
}

/// RPC_SERVER_INTERFACE — the interface specification registered by a server
/// This is what RpcServerRegisterIf receives
#[repr(C)]
pub struct RPC_SERVER_INTERFACE {
    pub Length: u32,
    pub InterfaceId: RPC_SYNTAX_IDENTIFIER,
    pub TransferSyntax: RPC_SYNTAX_IDENTIFIER,
    pub DispatchTable: *mut RPC_DISPATCH_TABLE,
    pub RpcProtseqEndpointCount: u32,
    pub RpcProtseqEndpoint: PVOID, // PRPC_PROTSEQ_ENDPOINT
    pub DefaultManagerEpv: PVOID,
    pub InterpreterInfo: PVOID, // *MIDL_SERVER_INFO
    pub Flags: u32,
}

#[repr(C)]
pub struct RPC_DISPATCH_TABLE {
    pub DispatchTableCount: u32,
    pub DispatchTable: PVOID, // RPC_DISPATCH_FUNCTION*
    pub Reserved: isize,
}

/// MIDL_SERVER_INFO — contains the dispatch table with actual function pointers
#[repr(C)]
pub struct MIDL_SERVER_INFO {
    pub pStubDesc: PVOID, // *MIDL_STUB_DESC
    pub DispatchTable: PVOID, // *SERVER_ROUTINE (array of function pointers)
    pub ProcString: PVOID, // PFORMAT_STRING
    pub FmtStringOffset: *const u16,
    pub ThunkTable: PVOID, // *STUB_THUNK
    pub pTransferSyntax: PVOID, // *RPC_SYNTAX_IDENTIFIER
    pub nCount: usize,
    pub pSyntaxInfo: PVOID, // *MIDL_SYNTAX_INFO
}

/// MIDL_STUB_DESC — describes the stub
#[repr(C)]
pub struct MIDL_STUB_DESC {
    pub RpcInterfaceInformation: PVOID, // back-pointer to RPC_SERVER_INTERFACE
    pub pfnAllocate: PVOID,
    pub pfnFree: PVOID,
    // ... more fields that we don't need for enumeration
}

/// Parsed RPC interface information — our friendly representation
#[derive(Clone, Debug)]
pub struct RpcInterfaceInfo {
    pub uuid: String,
    pub version: String,
    pub procedure_count: u32,
    pub server_dll: String,
    pub hosting_process: String,
    pub hosting_pid: u32,
    pub endpoint: String,
    pub has_security_callback: bool,
    pub base_address: usize,
}

impl std::fmt::Display for RpcInterfaceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UUID: {} v{}\n  Procedures: {}\n  Server DLL: {}\n  Process: {} (PID: {})\n  Endpoint: {}\n  Security Callback: {}",
            self.uuid,
            self.version,
            self.procedure_count,
            self.server_dll,
            self.hosting_process,
            self.hosting_pid,
            self.endpoint,
            if self.has_security_callback { "YES" } else { "NO (INTERESTING!)" }
        )
    }
}

/// Known RPC transport protocols
#[derive(Debug, Clone)]
pub enum RpcTransport {
    Alpc(String),      // ncalrpc — local, uses ALPC
    NamedPipe(String),  // ncacn_np — local/remote
    Tcp(u16),           // ncacn_ip_tcp — remote
    Unknown(String),
}

impl std::fmt::Display for RpcTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcTransport::Alpc(name) => write!(f, "ncalrpc [{}]", name),
            RpcTransport::NamedPipe(name) => write!(f, "ncacn_np [{}]", name),
            RpcTransport::Tcp(port) => write!(f, "ncacn_ip_tcp [{}]", port),
            RpcTransport::Unknown(s) => write!(f, "unknown [{}]", s),
        }
    }
}

/// Well-known RPC interfaces mapped to ATT&CK techniques
pub struct KnownRpcInterface {
    pub uuid: &'static str,
    pub name: &'static str,
    pub protocol: &'static str,
    pub attack_technique: &'static str,
    pub description: &'static str,
}

pub const KNOWN_INTERFACES: &[KnownRpcInterface] = &[
    KnownRpcInterface {
        uuid: "367ABB81-9844-35F1-AD32-98F038001003",
        name: "MS-SCMR",
        protocol: "Service Control Manager",
        attack_technique: "T1543.003 (Create/Modify System Service)",
        description: "Service creation, modification, remote execution",
    },
    KnownRpcInterface {
        uuid: "E3514235-4B06-11D1-AB04-00C04FC2DCD2",
        name: "MS-DRSR",
        protocol: "Directory Replication Service",
        attack_technique: "T1003.006 (DCSync)",
        description: "Domain replication — credential dumping via DCSync",
    },
    KnownRpcInterface {
        uuid: "86D35949-83C9-4044-B424-DB363231FD0C",
        name: "MS-TSCH",
        protocol: "Task Scheduler",
        attack_technique: "T1053.005 (Scheduled Task)",
        description: "Remote task creation for execution/persistence",
    },
    KnownRpcInterface {
        uuid: "C681D488-D850-11D0-8C52-00C04FD90F7E",
        name: "MS-EFSR",
        protocol: "Encrypting File System",
        attack_technique: "PetitPotam / Coerce Authentication",
        description: "EFS abuse for NTLM relay — PetitPotam",
    },
    KnownRpcInterface {
        uuid: "12345678-1234-ABCD-EF00-0123456789AB",
        name: "MS-RPRN",
        protocol: "Print Spooler",
        attack_technique: "PrintNightmare / T1547 (Boot/Logon Autostart)",
        description: "PrintNightmare — RCE/LPE via print spooler",
    },
    KnownRpcInterface {
        uuid: "12345778-1234-ABCD-EF00-0123456789AC",
        name: "MS-SAMR",
        protocol: "SAM Remote",
        attack_technique: "T1087 (Account Discovery)",
        description: "User/group enumeration, password policy",
    },
    KnownRpcInterface {
        uuid: "4FC742E0-4A10-11CF-8273-00AA004AE673",
        name: "MS-DFSNM",
        protocol: "DFS Namespace Management",
        attack_technique: "DFSCoerce / Coerce Authentication",
        description: "DFS abuse for NTLM relay",
    },
    KnownRpcInterface {
        uuid: "338CD001-2244-31F1-AAAA-900038001003",
        name: "MS-RRP",
        protocol: "Remote Registry",
        attack_technique: "T1012 (Query Registry)",
        description: "Remote registry read/write",
    },
    KnownRpcInterface {
        uuid: "1FF70682-0A51-30E8-076D-740BE8CEE98B",
        name: "MS-ATSVC",
        protocol: "AT Service (legacy scheduler)",
        attack_technique: "T1053.002 (At)",
        description: "Legacy task scheduling",
    },
    KnownRpcInterface {
        uuid: "76F03F96-CDFD-44FC-A22C-64950A001209",
        name: "MS-PAR",
        protocol: "Print Async Remote",
        attack_technique: "Coerce Authentication",
        description: "Async print remote protocol abuse",
    },
];

/// Look up a known interface by UUID
pub fn lookup_known_interface(uuid: &str) -> Option<&'static KnownRpcInterface> {
    let uuid_upper = uuid.to_uppercase();
    KNOWN_INTERFACES.iter().find(|i| i.uuid == uuid_upper)
}
