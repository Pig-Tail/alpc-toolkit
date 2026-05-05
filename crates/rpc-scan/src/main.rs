// rpc-scan — RPC Interface Scanner
//
// Phase 1 tool: Scans PE binaries to identify RPC server interfaces
// Two methods:
//   1. PE import analysis — finds DLLs that import RpcServerRegisterIf*
//   2. Binary pattern scan — finds NDR transfer syntax GUID in memory,
//      which precedes every RPC_SERVER_INTERFACE structure
//
// Usage:
//   rpc-scan.exe                           — Scan System32
//   rpc-scan.exe --path "C:\Program Files" — Scan custom path
//   rpc-scan.exe --deep                    — Deep scan with memory mapping
//   rpc-scan.exe --known                   — Show known abusable interfaces

use alpc_core::rpc;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;

// NDR Transfer Syntax GUID: 8A885D04-1CEB-11C9-9FE8-08002B104860
// This appears in EVERY RPC_SERVER_INTERFACE structure
const NDR_TRANSFER_SYNTAX: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, // Data1: 8A885D04 (little-endian)
    0xEB, 0x1C,             // Data2: 1CEB
    0xC9, 0x11,             // Data3: 11C9
    0x9F, 0xE8,             // Data4[0..2]
    0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, // Data4[2..8]
];

// NDR64 Transfer Syntax: 71710533-BEBA-4937-8319-B5DBEF9CCC36
const NDR64_TRANSFER_SYNTAX: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49,
    0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
];

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           RPC Interface Scanner v0.1                       ║");
    println!("║           Phase 1 — Interface Discovery                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--known") {
        print_known_interfaces();
        return;
    }

    let scan_path = if let Some(idx) = args.iter().position(|a| a == "--path") {
        args.get(idx + 1)
            .map(|s| s.as_str())
            .unwrap_or("C:\\Windows\\System32")
    } else {
        "C:\\Windows\\System32"
    };

    let deep = args.iter().any(|a| a == "--deep");

    println!("[*] Scanning: {}", scan_path);
    println!("[*] Mode: {}", if deep { "Deep (binary pattern)" } else { "Import analysis" });
    println!();

    // Collect target files
    let targets = collect_pe_files(scan_path);
    println!("[*] Found {} PE files to scan", targets.len());
    println!();

    if deep {
        scan_binary_patterns(&targets);
    } else {
        scan_imports(&targets);
    }
}

/// Collect all .dll and .exe files in a directory (non-recursive for System32)
fn collect_pe_files(path: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let dir = Path::new(path);

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "dll" || ext == "exe" {
                    files.push(path);
                }
            }
        }
    }

    files.sort();
    files
}

/// Method 1: Scan PE imports for RPC server registration functions
fn scan_imports(targets: &[PathBuf]) {
    println!("[*] === PE Import Analysis ===");
    println!("[*] Looking for binaries that import RPC server functions...\n");

    let rpc_server_functions = [
        "RpcServerRegisterIf",
        "RpcServerRegisterIf2",
        "RpcServerRegisterIf3",
        "RpcServerRegisterIfEx",
        "NdrServerCallAll",
        "NdrServerCall2",
        "NdrServerCallNdr64",
        "NdrAsyncServerCall",
    ];

    let mut found_count = 0;
    let mut results: Vec<(String, Vec<String>)> = Vec::new();

    for path in targets {
        match scan_pe_imports(path, &rpc_server_functions) {
            Ok(matches) if !matches.is_empty() => {
                found_count += 1;
                let filename = path.file_name().unwrap().to_string_lossy().to_string();
                results.push((filename, matches));
            }
            _ => {}
        }
    }

    println!("    Found {} RPC server binaries:\n", found_count);

    // Categorize: has RegisterIf = is an RPC server
    let mut servers = Vec::new();
    let mut stubs = Vec::new();

    for (name, imports) in &results {
        let has_register = imports.iter().any(|i| i.contains("RegisterIf"));
        if has_register {
            servers.push((name, imports));
        } else {
            stubs.push((name, imports));
        }
    }

    println!("    ── RPC Servers (register interfaces) ──");
    for (name, imports) in &servers {
        println!("    ► {}", name);
        for imp in imports.iter() {
            println!("        imports: {}", imp);
        }
    }

    println!("\n    ── RPC Stub Handlers (process calls) ──");
    for (name, imports) in &stubs {
        println!("      {}", name);
        for imp in imports.iter() {
            println!("        imports: {}", imp);
        }
    }

    println!("\n[*] Total: {} RPC servers, {} stub handlers", servers.len(), stubs.len());
    println!("[*] Next: Use --deep to find interface UUIDs in these binaries");
}

/// Parse PE file and check import table for specific function names
fn scan_pe_imports(path: &Path, functions: &[&str]) -> std::io::Result<Vec<String>> {
    let mut file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < 64 {
        return Ok(Vec::new());
    }

    // Quick check: DOS header magic
    if data[0] != b'M' || data[1] != b'Z' {
        return Ok(Vec::new());
    }

    // Find PE header offset
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 > data.len() {
        return Ok(Vec::new());
    }

    // Check PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(Vec::new());
    }

    // Simple heuristic: search for function name strings in the binary
    // This catches both import table entries and delay-load imports
    let mut matches = Vec::new();
    let data_str = String::from_utf8_lossy(&data);

    for func in functions {
        if data_str.contains(func) {
            matches.push(func.to_string());
        }
    }

    Ok(matches)
}

/// Method 2: Scan binary content for NDR Transfer Syntax GUID
/// This finds the actual RPC_SERVER_INTERFACE structures in the binary
fn scan_binary_patterns(targets: &[PathBuf]) {
    println!("[*] === Binary Pattern Scan ===");
    println!("[*] Searching for NDR Transfer Syntax GUID in PE files...");
    println!("[*] (This identifies embedded RPC_SERVER_INTERFACE structures)\n");

    let mut total_interfaces = 0;

    for path in targets {
        match scan_for_rpc_interfaces(path) {
            Ok(interfaces) if !interfaces.is_empty() => {
                let filename = path.file_name().unwrap().to_string_lossy();
                println!("    ► {} — {} interface(s)", filename, interfaces.len());

                for iface in &interfaces {
                    let known = rpc::lookup_known_interface(&iface.0);
                    let marker = if let Some(k) = known {
                        format!(" ⚠ KNOWN: {} ({})", k.name, k.attack_technique)
                    } else {
                        String::new()
                    };

                    println!(
                        "        UUID: {} v{}.{}  [{} procs]{}",
                        iface.0, iface.1, iface.2, iface.3, marker
                    );
                }
                total_interfaces += interfaces.len();
                println!();
            }
            _ => {}
        }
    }

    println!("[*] Total interfaces found: {}", total_interfaces);
}

/// Scan a PE file for RPC interface structures by finding NDR transfer syntax
/// Returns Vec of (UUID, major_version, minor_version, procedure_count_estimate)
fn scan_for_rpc_interfaces(path: &Path) -> std::io::Result<Vec<(String, u16, u16, u32)>> {
    let mut file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut results = Vec::new();

    // Search for NDR Transfer Syntax GUID pattern
    // In RPC_SERVER_INTERFACE layout:
    //   offset 0x00: Length (4 bytes)
    //   offset 0x04: InterfaceId (RPC_SYNTAX_IDENTIFIER = 20 bytes)
    //     offset 0x04: UUID (16 bytes)
    //     offset 0x14: Version (4 bytes: major u16, minor u16)
    //   offset 0x18: TransferSyntax (RPC_SYNTAX_IDENTIFIER = 20 bytes)
    //     offset 0x18: NDR_TRANSFER_SYNTAX UUID (16 bytes) ← we search for this
    //     offset 0x28: NDR Version (4 bytes)

    for i in 0..data.len().saturating_sub(NDR_TRANSFER_SYNTAX.len()) {
        if data[i..i + NDR_TRANSFER_SYNTAX.len()] == NDR_TRANSFER_SYNTAX
            || data[i..i + NDR64_TRANSFER_SYNTAX.len()] == NDR64_TRANSFER_SYNTAX
        {
            // Found NDR transfer syntax — now look backwards for the interface UUID
            // TransferSyntax is at offset 0x18 from start of RPC_SERVER_INTERFACE
            // So InterfaceId UUID is at offset -0x14 from the NDR UUID

            let iface_uuid_offset = i.wrapping_sub(0x14);
            if iface_uuid_offset + 16 <= data.len() && iface_uuid_offset < i {
                // Read interface UUID
                let uuid_bytes = &data[iface_uuid_offset..iface_uuid_offset + 16];
                let uuid = format_uuid(uuid_bytes);

                // Read version (right after UUID)
                let ver_offset = iface_uuid_offset + 16;
                if ver_offset + 4 <= data.len() {
                    let major = u16::from_le_bytes([data[ver_offset], data[ver_offset + 1]]);
                    let minor = u16::from_le_bytes([data[ver_offset + 2], data[ver_offset + 3]]);

                    // Basic validation: reject null UUIDs and improbable versions
                    if uuid != "00000000-0000-0000-0000-000000000000"
                        && major < 100
                        && minor < 100
                    {
                        // Estimate procedure count from MIDL_SERVER_INFO
                        // This is a heuristic — the real count requires following pointers
                        let proc_estimate = 0u32; // We'd need runtime analysis for this

                        // Avoid duplicates
                        if !results.iter().any(|(u, _, _, _): &(String, u16, u16, u32)| u == &uuid) {
                            results.push((uuid, major, minor, proc_estimate));
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Format UUID bytes (little-endian) into standard UUID string
fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "INVALID".to_string();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3,
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Print known abusable RPC interfaces
fn print_known_interfaces() {
    println!("[*] Known abusable RPC interfaces (from MSRPC-to-ATT&CK):\n");
    for iface in rpc::KNOWN_INTERFACES {
        println!("    {} — {}", iface.uuid, iface.name);
        println!("        Protocol: {}", iface.protocol);
        println!("        ATT&CK: {}", iface.attack_technique);
        println!("        Description: {}", iface.description);
        println!();
    }
}
