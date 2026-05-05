// alpc-enum — ALPC Port & RPC Endpoint Enumerator
//
// Phase 1 tool: Maps the ALPC/RPC attack surface on a Windows system
// Enumerates all ALPC connection ports visible in the Object Manager namespace,
// identifies owning processes, and cross-references with known RPC interfaces.
//
// Usage:
//   alpc-enum.exe                  — Full enumeration
//   alpc-enum.exe --rpc-control    — Only enumerate \RPC Control\ directory
//   alpc-enum.exe --handles        — Enumerate via system handle table (needs admin)
//   alpc-enum.exe --all            — All methods combined

use alpc_core::types::*;
use alpc_core::ntdll;
use alpc_core::helpers;
use alpc_core::rpc;

use std::collections::HashMap;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           ALPC/RPC Attack Surface Enumerator v0.1          ║");
    println!("║           Phase 1 — Reconnaissance & Mapping               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("--all");

    // Enable debug privilege for handle enumeration
    if helpers::enable_debug_privilege() {
        println!("[+] SeDebugPrivilege enabled");
    } else {
        println!("[!] SeDebugPrivilege not available — some features limited");
    }
    println!();

    let max_msg_len = ntdll::alpc_max_message_length();
    println!("[*] ALPC max message length: {} bytes (0x{:X})", max_msg_len, max_msg_len);
    println!();

    match mode {
        "--rpc-control" => enumerate_rpc_control(),
        "--handles" => enumerate_via_handles(),
        "--all" | _ => {
            enumerate_root_alpc_ports();
            println!("\n{}", "=".repeat(70));
            enumerate_rpc_control();
            println!("\n{}", "=".repeat(70));
            enumerate_via_handles();
            println!("\n{}", "=".repeat(70));
            print_summary();
        }
    }
}

/// Enumerate ALPC ports under the root namespace (\)
fn enumerate_root_alpc_ports() {
    println!("[*] Enumerating ALPC ports under root namespace (\\)...");
    println!("{}", "-".repeat(60));

    let entries = helpers::enumerate_directory("\\");
    let alpc_ports: Vec<_> = entries
        .iter()
        .filter(|(_, type_name)| type_name == "ALPC Port")
        .collect();

    if alpc_ports.is_empty() {
        println!("    No ALPC ports found under root");
        return;
    }

    println!("    Found {} ALPC port(s) under root:\n", alpc_ports.len());
    for (name, _) in &alpc_ports {
        println!("    \\{}", name);
    }
}

/// Enumerate all objects under \RPC Control\ — where most ALPC/RPC endpoints live
fn enumerate_rpc_control() {
    println!("[*] Enumerating \\RPC Control\\ directory...");
    println!("{}", "-".repeat(60));

    let entries = helpers::enumerate_directory("\\RPC Control");

    let mut alpc_ports = Vec::new();
    let mut other_objects = HashMap::new();

    for (name, type_name) in &entries {
        if type_name == "ALPC Port" {
            alpc_ports.push(name.clone());
        } else {
            *other_objects.entry(type_name.clone()).or_insert(0u32) += 1;
        }
    }

    println!("    Total objects: {}", entries.len());
    println!("    ALPC Ports: {}", alpc_ports.len());
    for (type_name, count) in &other_objects {
        println!("    {}: {}", type_name, count);
    }
    println!();

    // List all ALPC ports, grouped by naming pattern
    let mut by_prefix: HashMap<String, Vec<String>> = HashMap::new();
    for name in &alpc_ports {
        // Group by prefix — many ALPC ports follow patterns like "LRPC-XXXXXXXX"
        let prefix = if let Some(dash_pos) = name.find('-') {
            if name[..dash_pos].chars().all(|c| c.is_alphanumeric()) {
                name[..dash_pos].to_string()
            } else {
                name.clone()
            }
        } else {
            name.clone()
        };
        by_prefix.entry(prefix).or_default().push(name.clone());
    }

    println!("    ALPC Port patterns:");
    let mut sorted_prefixes: Vec<_> = by_prefix.iter().collect();
    sorted_prefixes.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    for (prefix, names) in &sorted_prefixes {
        if names.len() > 3 {
            println!("      {}-* ({} ports)", prefix, names.len());
        } else {
            for name in *names {
                // Check if this matches a known RPC interface name
                println!("      {}", name);
            }
        }
    }

    // Highlight non-standard / interesting ports
    println!("\n    [*] Potentially interesting (non-LRPC) ports:");
    for name in &alpc_ports {
        if !name.starts_with("LRPC-")
            && !name.starts_with("OLE")
            && !name.starts_with("DCOM")
        {
            println!("      ► {}", name);
        }
    }
}

/// Enumerate ALPC port handles across all processes using NtQuerySystemInformation
/// This finds ALL ALPC ports, including unnamed communication ports
fn enumerate_via_handles() {
    println!("[*] Enumerating ALPC handles via system handle table...");
    println!("    (Requires admin/SeDebugPrivilege)");
    println!("{}", "-".repeat(60));

    unsafe {
        // Query system handle information — requires iterative buffer growth
        let mut buf_size: u32 = 0x100000; // Start with 1MB
        let mut buffer: Vec<u8>;
        let mut return_length: u32 = 0;

        loop {
            buffer = vec![0u8; buf_size as usize];
            let status = ntdll::NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_EX,
                buffer.as_mut_ptr() as PVOID,
                buf_size,
                &mut return_length,
            );

            if ntdll::nt_success(status) {
                break;
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                buf_size = return_length + 0x10000;
                if buf_size > 0x10000000 {
                    // 256MB safety limit
                    println!("    [!] Handle buffer too large, aborting");
                    return;
                }
                continue;
            }

            println!(
                "    [!] NtQuerySystemInformation failed: {}",
                helpers::ntstatus_to_string(status)
            );
            return;
        }

        // Parse the handle table
        let info = &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX_STRUCT);
        let handle_count = info.NumberOfHandles;
        println!("    Total system handles: {}", handle_count);

        let entries_ptr = buffer
            .as_ptr()
            .add(std::mem::size_of::<SYSTEM_HANDLE_INFORMATION_EX_STRUCT>())
            as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

        // Count ALPC port handles per process
        let mut alpc_by_process: HashMap<usize, (String, u32)> = HashMap::new();
        let mut total_alpc_handles: u32 = 0;

        // The ALPC Port object type index can vary by Windows version
        // We detect it by finding handles that point to known ALPC port objects
        // Heuristic: Look for ObjectTypeIndex values that appear frequently
        // and correspond to the range where ALPC ports typically are (40-50)
        let mut type_counts: HashMap<u16, u32> = HashMap::new();

        for i in 0..handle_count {
            let entry = &*entries_ptr.add(i);
            *type_counts.entry(entry.ObjectTypeIndex).or_insert(0) += 1;
        }

        // ALPC Port type index detection:
        // On most Windows 10/11 systems it's between 44-47
        // We look for a type that has a reasonable count (100-50000)
        // In the range 40-55
        let mut candidate_type_index: Option<u16> = None;
        for idx in 40..=55 {
            if let Some(&count) = type_counts.get(&idx) {
                if count > 50 && count < 100000 {
                    // Likely candidate for ALPC Port
                    if candidate_type_index.is_none()
                        || type_counts.get(&candidate_type_index.unwrap()).unwrap_or(&0)
                            < &count
                    {
                        // We can't be 100% sure, but this is a good heuristic
                        // In practice you'd verify with NtQueryObject
                    }
                }
            }
        }

        // For reliability, enumerate using NtQueryObject on sampled handles
        // to find the actual ALPC Port type index
        let alpc_type_index = detect_alpc_type_index(entries_ptr, handle_count);

        if let Some(type_idx) = alpc_type_index {
            println!("    Detected ALPC Port type index: {}", type_idx);

            for i in 0..handle_count {
                let entry = &*entries_ptr.add(i);
                if entry.ObjectTypeIndex == type_idx {
                    total_alpc_handles += 1;
                    let pid = entry.UniqueProcessId;
                    let e = alpc_by_process
                        .entry(pid)
                        .or_insert_with(|| {
                            let name = helpers::get_process_name(pid as u32);
                            (name, 0)
                        });
                    e.1 += 1;
                }
            }

            println!("    Total ALPC port handles: {}", total_alpc_handles);
            println!("    Processes with ALPC ports: {}", alpc_by_process.len());

            if !alpc_by_process.is_empty() {
                let avg = total_alpc_handles as f64 / alpc_by_process.len() as f64;
                println!("    Average ALPC handles per process: {:.1}", avg);
            }
            println!();

            // Sort by handle count (descending) and show top processes
            let mut sorted: Vec<_> = alpc_by_process.iter().collect();
            sorted.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));

            println!("    Top 25 processes by ALPC handle count:");
            println!("    {:<8} {:<6} {}", "PID", "ALPC#", "Process");
            println!("    {}", "-".repeat(50));

            for (pid, (name, count)) in sorted.iter().take(25) {
                let marker = if *count > 20 { " ◄ HIGH" } else { "" };
                println!("    {:<8} {:<6} {}{}", pid, count, name, marker);
            }
        } else {
            println!("    [!] Could not detect ALPC Port type index");
            println!("    Tip: Run with admin privileges, or use WinDbg:");
            println!("         !object \\ObjectTypes\\ALPC Port");
        }
    }
}

/// Detect the ALPC Port object type index by sampling handles
unsafe fn detect_alpc_type_index(
    entries: *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    count: usize,
) -> Option<u16> {
    let my_pid = std::process::id() as usize;

    // Object type name query
    const OBJECT_TYPE_INFORMATION: u32 = 2;

    #[repr(C)]
    struct OBJECT_TYPE_INFORMATION_STRUCT {
        TypeName: UNICODE_STRING,
        // ... more fields we don't need
    }

    // Sample handles from our own process in the type index range 40-55
    for type_idx in 40u16..=55 {
        // Find a handle with this type index from ANY accessible process
        for i in 0..count.min(100000) {
            let entry = &*entries.add(i);
            if entry.ObjectTypeIndex != type_idx {
                continue;
            }

            // Try to duplicate the handle from the source process
            let src_pid = entry.UniqueProcessId as u32;
            let src_handle = windows_sys::Win32::System::Threading::OpenProcess(
                PROCESS_DUP_HANDLE,
                0,
                src_pid,
            );
            if src_handle.is_null() {
                continue;
            }

            let mut dup_handle: HANDLE = NULL_HANDLE;
            let status = ntdll::NtDuplicateObject(
                src_handle as HANDLE,
                entry.HandleValue as HANDLE,
                windows_sys::Win32::System::Threading::GetCurrentProcess() as HANDLE,
                &mut dup_handle,
                0,
                0,
                0x04, // DUPLICATE_SAME_ACCESS
            );

            windows_sys::Win32::Foundation::CloseHandle(src_handle);

            if !ntdll::nt_success(status) || dup_handle.is_null() {
                continue;
            }

            // Query object type
            let mut buf = vec![0u8; 1024];
            let mut ret_len: u32 = 0;
            let status = ntdll::NtQueryObject(
                dup_handle,
                OBJECT_TYPE_INFORMATION,
                buf.as_mut_ptr() as PVOID,
                buf.len() as u32,
                &mut ret_len,
            );

            ntdll::NtClose(dup_handle);

            if ntdll::nt_success(status) {
                let type_info = &*(buf.as_ptr() as *const OBJECT_TYPE_INFORMATION_STRUCT);
                let type_name = type_info.TypeName.to_string();
                if type_name == "ALPC Port" {
                    return Some(type_idx);
                }
            }

            break; // Only need one sample per type index
        }
    }
    None
}

fn print_summary() {
    println!("\n[*] Summary & Next Steps");
    println!("{}", "=".repeat(70));
    println!("    1. Use 'rpc-scan.exe' to enumerate RPC interfaces in DLLs");
    println!("    2. Cross-reference high-ALPC-count SYSTEM processes with RPC interfaces");
    println!("    3. Use 'alpc-client.exe' to probe interesting ALPC ports");
    println!("    4. Check interesting ports with: Get-AccessibleAlpcPort (NtObjectManager)");
    println!();
    println!("    Key targets for Fase 2:");
    println!("    - Services running as SYSTEM with many ALPC handles");
    println!("    - Non-standard ALPC port names (not LRPC-*, OLE*, DCOM*)");
    println!("    - RPC interfaces WITHOUT security callbacks");
}
