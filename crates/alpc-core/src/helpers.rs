// alpc-core/src/helpers.rs
//
// Utility functions for the toolkit

use crate::types::*;
use crate::ntdll;
use std::ffi::c_void;

/// Get process name from PID
pub fn get_process_name(pid: u32) -> String {
    unsafe {
        let handle = windows_sys::Win32::System::Threading::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0, // FALSE
            pid,
        );
        if handle.is_null() {
            return format!("<PID {}>", pid);
        }
        let mut buffer = [0u16; 260];
        let mut size = buffer.len() as u32;
        let result = windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            0,
            buffer.as_mut_ptr(),
            &mut size,
        );
        windows_sys::Win32::Foundation::CloseHandle(handle);
        if result != 0 {
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            path.rsplit('\\').next().unwrap_or(&path).to_string()
        } else {
            format!("<PID {}>", pid)
        }
    }
}

/// Enable SeDebugPrivilege — needed for accessing other processes' handles
pub fn enable_debug_privilege() -> bool {
    unsafe {
        use windows_sys::Win32::Security::*;
        use windows_sys::Win32::System::Threading::*;

        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let priv_name: Vec<u16> = "SeDebugPrivilege\0"
            .encode_utf16()
            .collect();
        let mut luid: windows_sys::Win32::Foundation::LUID =
            std::mem::zeroed();

        if LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(token);
            return false;
        }

        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let result = AdjustTokenPrivileges(
            token,
            0, // FALSE
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        windows_sys::Win32::Foundation::CloseHandle(token);
        result != 0
    }
}

/// Enumerate all objects in an Object Manager directory
pub fn enumerate_directory(path: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    unsafe {
        let mut dir_name_buf = ntdll::to_utf16(path);
        let mut dir_name = UNICODE_STRING::from_slice(&mut dir_name_buf);
        let mut oa = OBJECT_ATTRIBUTES::new(&mut dir_name);
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        let mut dir_handle: HANDLE = NULL_HANDLE;
        let status = ntdll::NtOpenDirectoryObject(
            &mut dir_handle,
            DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
            &mut oa,
        );

        if !ntdll::nt_success(status) {
            eprintln!("[!] Failed to open directory '{}': 0x{:08X}", path, status as u32);
            return results;
        }

        let buf_size: ULONG = 0x10000;
        let buffer = vec![0u8; buf_size as usize];
        let mut context: ULONG = 0;
        let mut return_length: ULONG = 0;

        loop {
            let status = ntdll::NtQueryDirectoryObject(
                dir_handle,
                buffer.as_ptr() as PVOID,
                buf_size,
                0, // ReturnSingleEntry = FALSE, return multiple
                if context == 0 { 1 } else { 0 }, // RestartScan on first call
                &mut context,
                &mut return_length,
            );

            if !ntdll::nt_success(status) {
                break;
            }

            // Parse the buffer — array of OBJECT_DIRECTORY_INFORMATION terminated by null entry
            let mut ptr = buffer.as_ptr() as *const OBJECT_DIRECTORY_INFORMATION;
            loop {
                let entry = &*ptr;
                if entry.Name.Buffer.is_null() {
                    break;
                }
                let name = entry.Name.to_string();
                let type_name = entry.TypeName.to_string();
                results.push((name, type_name));
                ptr = ptr.add(1);
            }

            // STATUS_MORE_ENTRIES or STATUS_NO_MORE_ENTRIES
            if status != 0 {
                break;
            }
        }

        ntdll::NtClose(dir_handle);
    }
    results
}

/// Print a hex dump of a buffer (useful for inspecting ALPC messages)
pub fn hexdump(data: &[u8], offset: usize) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = offset + i * 16;
        print!("  {:08x}  ", addr);

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        // Padding for incomplete lines
        for j in chunk.len()..16 {
            print!("   ");
            if j == 7 {
                print!(" ");
            }
        }

        // ASCII
        print!(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

/// Format NTSTATUS as readable string
pub fn ntstatus_to_string(status: NTSTATUS) -> String {
    match status as u32 {
        0x00000000 => "STATUS_SUCCESS".to_string(),
        0xC0000022 => "STATUS_ACCESS_DENIED".to_string(),
        0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND".to_string(),
        0xC000009A => "STATUS_INSUFFICIENT_RESOURCES".to_string(),
        0xC0000004 => "STATUS_INFO_LENGTH_MISMATCH".to_string(),
        0xC0000023 => "STATUS_BUFFER_TOO_SMALL".to_string(),
        0xC0000005 => "STATUS_ACCESS_VIOLATION".to_string(),
        0xC00000BB => "STATUS_NOT_SUPPORTED".to_string(),
        0xC0000010 => "STATUS_INVALID_DEVICE_REQUEST".to_string(),
        0xC000003B => "STATUS_OBJECT_PATH_SYNTAX_BAD".to_string(),
        0x80000005 => "STATUS_BUFFER_OVERFLOW".to_string(),
        0x8000001A => "STATUS_NO_MORE_ENTRIES".to_string(),
        0xC00000EF => "STATUS_OBJECT_PATH_NOT_FOUND".to_string(),
        _ => format!("0x{:08X}", status as u32),
    }
}
