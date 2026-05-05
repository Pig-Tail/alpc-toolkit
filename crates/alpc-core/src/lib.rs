// alpc-core/src/lib.rs
//
// Core ALPC/RPC type definitions and FFI bindings
// These structures are UNDOCUMENTED by Microsoft — derived from reverse engineering
// References: Alex Ionescu (SyScan'14), csandker (Offensive Windows IPC 3: ALPC),
//             James Forshaw (NtObjectManager), ProcessHacker sources

pub mod types;
pub mod ntdll;
pub mod rpc;
pub mod helpers;
