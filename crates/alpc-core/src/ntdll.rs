// alpc-core/src/ntdll.rs
//
// FFI bindings to undocumented ntdll.dll ALPC/RPC functions
// These are loaded dynamically to avoid linker issues

#![allow(non_snake_case)]

use crate::types::*;

// Link directly to ntdll for the functions we need
#[link(name = "ntdll")]
extern "system" {
    // ===================================================================
    // ALPC Port Functions
    // ===================================================================

    /// Create an ALPC port (server-side)
    pub fn NtAlpcCreatePort(
        PortHandle: *mut HANDLE,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        PortAttributes: *mut ALPC_PORT_ATTRIBUTES,
    ) -> NTSTATUS;

    /// Connect to an ALPC port (client-side)
    pub fn NtAlpcConnectPort(
        PortHandle: *mut HANDLE,
        PortName: *mut UNICODE_STRING,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        PortAttributes: *mut ALPC_PORT_ATTRIBUTES,
        Flags: ULONG,
        RequiredServerSid: PVOID, // PSID
        ConnectionMessage: *mut PORT_MESSAGE,
        BufferLength: *mut ULONG,
        OutMessageAttributes: *mut ALPC_MESSAGE_ATTRIBUTES,
        InMessageAttributes: *mut ALPC_MESSAGE_ATTRIBUTES,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;

    /// Accept or reject a connection (server-side)
    pub fn NtAlpcAcceptConnectPort(
        PortHandle: *mut HANDLE,
        ConnectionPortHandle: HANDLE,
        Flags: ULONG,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        PortAttributes: *mut ALPC_PORT_ATTRIBUTES,
        PortContext: PVOID,
        ConnectionRequest: *mut PORT_MESSAGE,
        ConnectionMessageAttributes: *mut ALPC_MESSAGE_ATTRIBUTES,
        AcceptConnection: BOOLEAN,
    ) -> NTSTATUS;

    /// Send/wait/receive on ALPC port — the single multipurpose function
    pub fn NtAlpcSendWaitReceivePort(
        PortHandle: HANDLE,
        Flags: ULONG,
        SendMessage: *mut PORT_MESSAGE,
        SendMessageAttributes: *mut ALPC_MESSAGE_ATTRIBUTES,
        ReceiveMessage: *mut PORT_MESSAGE,
        BufferLength: *mut SIZE_T,
        ReceiveMessageAttributes: *mut ALPC_MESSAGE_ATTRIBUTES,
        Timeout: PLARGE_INTEGER,
    ) -> NTSTATUS;

    /// Disconnect from ALPC port
    pub fn NtAlpcDisconnectPort(
        PortHandle: HANDLE,
        Flags: ULONG,
    ) -> NTSTATUS;

    /// Impersonate client (server-side, requires comm port handle)
    pub fn NtAlpcImpersonateClientOfPort(
        PortHandle: HANDLE,
        Message: *mut PORT_MESSAGE,
        Flags: PVOID,
    ) -> NTSTATUS;

    /// Query the maximum message length for ALPC
    pub fn AlpcMaxAllowedMessageLength() -> SIZE_T;

    /// Get required buffer size for message attributes
    pub fn AlpcGetHeaderSize(Flags: ULONG) -> SIZE_T;

    /// Initialize message attribute buffer
    pub fn AlpcInitializeMessageAttribute(
        AttributeFlags: ULONG,
        Buffer: *mut ALPC_MESSAGE_ATTRIBUTES,
        BufferSize: SIZE_T,
        RequiredBufferSize: *mut SIZE_T,
    ) -> NTSTATUS;

    // ===================================================================
    // Section/View functions (for shared memory messaging)
    // ===================================================================

    pub fn NtAlpcCreatePortSection(
        PortHandle: HANDLE,
        Flags: ULONG,
        SectionHandle: HANDLE,
        SectionSize: SIZE_T,
        AlpcSectionHandle: *mut HANDLE,
        ActualSectionSize: *mut SIZE_T,
    ) -> NTSTATUS;

    pub fn NtAlpcCreateSectionView(
        PortHandle: HANDLE,
        Flags: ULONG,
        ViewAttributes: *mut ALPC_DATA_VIEW_ATTR,
    ) -> NTSTATUS;

    pub fn NtAlpcDeleteSectionView(
        PortHandle: HANDLE,
        Flags: ULONG,
        ViewBase: PVOID,
    ) -> NTSTATUS;

    // ===================================================================
    // Object Manager / Directory enumeration
    // ===================================================================

    pub fn NtOpenDirectoryObject(
        DirectoryHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    pub fn NtQueryDirectoryObject(
        DirectoryHandle: HANDLE,
        Buffer: PVOID,
        Length: ULONG,
        ReturnSingleEntry: BOOLEAN,
        RestartScan: BOOLEAN,
        Context: *mut ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;

    pub fn NtOpenSymbolicLinkObject(
        LinkHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    pub fn NtQuerySymbolicLinkObject(
        LinkHandle: HANDLE,
        LinkTarget: *mut UNICODE_STRING,
        ReturnedLength: *mut ULONG,
    ) -> NTSTATUS;

    // ===================================================================
    // System information
    // ===================================================================

    pub fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;

    // ===================================================================
    // Process / Handle manipulation
    // ===================================================================

    pub fn NtQueryObject(
        Handle: HANDLE,
        ObjectInformationClass: u32,
        ObjectInformation: PVOID,
        ObjectInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;

    pub fn NtDuplicateObject(
        SourceProcessHandle: HANDLE,
        SourceHandle: HANDLE,
        TargetProcessHandle: HANDLE,
        TargetHandle: *mut HANDLE,
        DesiredAccess: u32,
        HandleAttributes: ULONG,
        Options: ULONG,
    ) -> NTSTATUS;

    pub fn NtClose(Handle: HANDLE) -> NTSTATUS;
}

// ===================================================================
// Safe wrappers
// ===================================================================

pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Encode a Rust string into a null-terminated UTF-16 Vec
pub fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Get the max allowed ALPC message length
pub fn alpc_max_message_length() -> usize {
    unsafe { AlpcMaxAllowedMessageLength() }
}

/// Allocate and initialize message attributes buffer
pub fn alloc_message_attributes(flags: ULONG) -> Option<Vec<u8>> {
    unsafe {
        let size = AlpcGetHeaderSize(flags);
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size];
        let mut required: SIZE_T = 0;
        let status = AlpcInitializeMessageAttribute(
            flags,
            buffer.as_mut_ptr() as *mut ALPC_MESSAGE_ATTRIBUTES,
            size,
            &mut required,
        );
        if nt_success(status) {
            Some(buffer)
        } else {
            None
        }
    }
}
