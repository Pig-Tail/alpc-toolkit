// alpc-client — ALPC Port Client & Probe Tool
//
// Phase 1 tool: Connects to ALPC ports and inspects responses
// Essential for understanding how servers respond and what attributes they expose
//
// Usage:
//   alpc-client.exe --port "\\RPC Control\\PortName"     — Connect and probe
//   alpc-client.exe --port "\\RPC Control\\PortName" --msg "Hello"  — Send message
//   alpc-client.exe --probe-all                            — Probe all accessible ports
//   alpc-client.exe --server --name "TestPort"             — Start a test server

use alpc_core::types::*;
use alpc_core::ntdll;
use alpc_core::helpers;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           ALPC Client/Server Probe v0.1                    ║");
    println!("║           Phase 1 — Port Interaction & Testing             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--server") {
        let name = get_arg_value(&args, "--name").unwrap_or("ALPCResearchPort".to_string());
        run_server(&name);
    } else if args.iter().any(|a| a == "--probe-all") {
        probe_all_ports();
    } else if let Some(port) = get_arg_value(&args, "--port") {
        let msg = get_arg_value(&args, "--msg");
        connect_to_port(&port, msg.as_deref());
    } else {
        println!("Usage:");
        println!("  alpc-client.exe --port \"\\\\RPC Control\\\\PortName\"");
        println!("  alpc-client.exe --port \"\\\\RPC Control\\\\PortName\" --msg \"Hello\"");
        println!("  alpc-client.exe --probe-all");
        println!("  alpc-client.exe --server --name MyPort");
    }
}

fn get_arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// =====================================================================
// CLIENT: Connect to an ALPC port and probe it
// =====================================================================

fn connect_to_port(port_path: &str, message: Option<&str>) {
    println!("[*] Connecting to ALPC port: {}", port_path);
    println!();

    unsafe {
        // Prepare port name
        let mut name_buf = ntdll::to_utf16(port_path);
        let mut port_name = UNICODE_STRING::from_slice(&mut name_buf);

        // Port attributes
        let mut port_attrs = ALPC_PORT_ATTRIBUTES::new();
        port_attrs.Flags = ALPC_PORTFLG_ALLOWIMPERSONATION;
        port_attrs.MaxMessageLength = MAX_ALPC_MESSAGE_BODY;

        // Connection message (optional)
        let mut conn_msg = ALPC_MESSAGE::new();
        let mut msg_size: ULONG = std::mem::size_of::<PORT_MESSAGE>() as ULONG;

        if let Some(text) = message {
            let msg_bytes: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let byte_slice = std::slice::from_raw_parts(
                msg_bytes.as_ptr() as *const u8,
                msg_bytes.len() * 2,
            );
            conn_msg.set_body(byte_slice);
            msg_size = conn_msg.header.TotalLength as ULONG;
            println!("[*] Connection message: \"{}\" ({} bytes)", text, byte_slice.len());
        }

        // Allocate receive message attributes (request ALL)
        let recv_attrs = ntdll::alloc_message_attributes(ALPC_MESSAGE_ATTRIBUTE_ALL);
        let recv_attrs_ptr = recv_attrs
            .as_ref()
            .map(|v| v.as_ptr() as *mut ALPC_MESSAGE_ATTRIBUTES)
            .unwrap_or(std::ptr::null_mut());

        // Connect
        let mut port_handle: HANDLE = NULL_HANDLE;
        let status = ntdll::NtAlpcConnectPort(
            &mut port_handle,
            &mut port_name,
            std::ptr::null_mut(), // ObjectAttributes
            &mut port_attrs,
            0, // Flags
            std::ptr::null_mut(), // RequiredServerSid
            &mut conn_msg.header as *mut PORT_MESSAGE,
            &mut msg_size,
            std::ptr::null_mut(), // OutMessageAttributes (sent with connection)
            recv_attrs_ptr,       // InMessageAttributes (received from server)
            std::ptr::null_mut(), // Timeout
        );

        if !ntdll::nt_success(status) {
            println!("[!] Connection FAILED: {}", helpers::ntstatus_to_string(status));
            match status as u32 {
                0xC0000022 => println!("    → ACCESS_DENIED: Port has restrictive security descriptor"),
                0xC0000034 => println!("    → OBJECT_NAME_NOT_FOUND: Port doesn't exist"),
                0xC00000EF => println!("    → Server rejected the connection"),
                _ => {}
            }
            return;
        }

        println!("[+] Connected! Handle: {:?}", port_handle);
        println!();

        // Analyze connection response
        println!("[*] Server response analysis:");
        println!("    Message ID: {}", conn_msg.header.MessageId);
        println!("    Data length: {} bytes", conn_msg.header.DataLength);
        println!("    Total length: {} bytes", conn_msg.header.TotalLength);
        println!(
            "    Server PID: {:?} TID: {:?}",
            conn_msg.header.ClientId.UniqueProcess,
            conn_msg.header.ClientId.UniqueThread,
        );

        let server_pid = conn_msg.header.ClientId.UniqueProcess as u32;
        if server_pid != 0 {
            println!("    Server process: {}", helpers::get_process_name(server_pid));
        }

        // Show response body if any
        if conn_msg.header.DataLength > 0 {
            println!("\n[*] Response body ({} bytes):", conn_msg.header.DataLength);
            let body = conn_msg.get_body();
            helpers::hexdump(body, 0);

            // Try to interpret as string
            let body_str = conn_msg.get_body_str();
            if !body_str.is_empty() && body_str.len() > 1 {
                println!("    As string: \"{}\"", body_str);
            }
        }

        // Analyze received message attributes
        if let Some(ref attrs_buf) = recv_attrs {
            let attrs = &*(attrs_buf.as_ptr() as *const ALPC_MESSAGE_ATTRIBUTES);
            println!("\n[*] Received message attributes:");
            println!("    Allocated: 0x{:08X}", attrs.AllocatedAttributes);
            println!("    Valid:     0x{:08X}", attrs.ValidAttributes);

            if attrs.ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE != 0 {
                println!("    ✓ CONTEXT attribute present");
            }
            if attrs.ValidAttributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE != 0 {
                println!("    ✓ SECURITY attribute present (impersonation may be possible!)");
            }
            if attrs.ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE != 0 {
                println!("    ✓ VIEW attribute present (shared memory section)");
            }
            if attrs.ValidAttributes & ALPC_MESSAGE_HANDLE_ATTRIBUTE != 0 {
                println!("    ✓ HANDLE attribute present");
            }
            if attrs.ValidAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE != 0 {
                println!("    ✓ TOKEN attribute present");
            }
        }

        // Now try to send a message and receive a reply
        if port_handle != NULL_HANDLE {
            println!("\n[*] Sending probe message...");
            probe_with_message(port_handle);
        }

        // Cleanup
        println!("\n[*] Disconnecting...");
        ntdll::NtAlpcDisconnectPort(port_handle, 0);
        ntdll::NtClose(port_handle);
        println!("[+] Done");
    }
}

/// Send a probe message after connection to see how the server responds
unsafe fn probe_with_message(port_handle: HANDLE) {
    let mut send_msg = ALPC_MESSAGE::new();
    let probe = b"PROBE\x00";
    send_msg.set_body(probe);

    let mut recv_msg = ALPC_MESSAGE::new();
    let mut recv_size: SIZE_T = std::mem::size_of::<ALPC_MESSAGE>();

    // Allocate receive attributes
    let recv_attrs = ntdll::alloc_message_attributes(ALPC_MESSAGE_ATTRIBUTE_ALL);
    let recv_attrs_ptr = recv_attrs
        .as_ref()
        .map(|v| v.as_ptr() as *mut ALPC_MESSAGE_ATTRIBUTES)
        .unwrap_or(std::ptr::null_mut());

    // Set a short timeout (2 seconds)
    let mut timeout: i64 = -20_000_000; // 2 seconds in 100ns units (negative = relative)

    let status = ntdll::NtAlpcSendWaitReceivePort(
        port_handle,
        ALPC_MSGFLG_SYNC_REQUEST,
        &mut send_msg.header as *mut PORT_MESSAGE,
        std::ptr::null_mut(), // Send attributes
        &mut recv_msg.header as *mut PORT_MESSAGE,
        &mut recv_size,
        recv_attrs_ptr,
        &mut timeout,
    );

    if ntdll::nt_success(status) {
        println!("    [+] Server replied! ({} bytes)", recv_msg.header.DataLength);
        if recv_msg.header.DataLength > 0 {
            let body = recv_msg.get_body();
            helpers::hexdump(body, 0);
        }
    } else {
        let err = helpers::ntstatus_to_string(status);
        println!("    [!] No reply or error: {}", err);
        if status as u32 == 0x00000102 {
            println!("    → TIMEOUT: Server didn't reply in 2s (may process asynchronously)");
        }
    }
}

// =====================================================================
// PROBE ALL: Try connecting to all discovered ALPC ports
// =====================================================================

fn probe_all_ports() {
    println!("[*] Probing all accessible ALPC ports in \\RPC Control\\...\n");

    let entries = helpers::enumerate_directory("\\RPC Control");
    let alpc_ports: Vec<_> = entries
        .iter()
        .filter(|(_, t)| t == "ALPC Port")
        .map(|(n, _)| n.clone())
        .collect();

    println!("[*] Found {} ALPC ports. Testing connectivity...\n", alpc_ports.len());

    let mut accessible = 0;
    let mut denied = 0;
    let mut errors = 0;
    let mut accessible_ports = Vec::new();

    for name in &alpc_ports {
        let full_path = format!("\\RPC Control\\{}", name);

        unsafe {
            let mut name_buf = ntdll::to_utf16(&full_path);
            let mut port_name = UNICODE_STRING::from_slice(&mut name_buf);

            let mut port_attrs = ALPC_PORT_ATTRIBUTES::new();
            port_attrs.MaxMessageLength = MAX_ALPC_MESSAGE_BODY;

            let mut conn_msg = ALPC_MESSAGE::new();
            let msg_size_val = std::mem::size_of::<PORT_MESSAGE>() as ULONG;
            let mut msg_size = msg_size_val;

            let mut port_handle: HANDLE = NULL_HANDLE;

            // Short timeout for probing
            let mut timeout: i64 = -10_000_000; // 1 second

            let status = ntdll::NtAlpcConnectPort(
                &mut port_handle,
                &mut port_name,
                std::ptr::null_mut(),
                &mut port_attrs,
                0,
                std::ptr::null_mut(),
                &mut conn_msg.header as *mut PORT_MESSAGE,
                &mut msg_size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            );

            if ntdll::nt_success(status) {
                accessible += 1;
                let server_pid = conn_msg.header.ClientId.UniqueProcess as u32;
                let proc_name = if server_pid != 0 {
                    helpers::get_process_name(server_pid)
                } else {
                    "unknown".to_string()
                };
                accessible_ports.push((name.clone(), server_pid, proc_name.clone()));

                ntdll::NtAlpcDisconnectPort(port_handle, 0);
                ntdll::NtClose(port_handle);
            } else if status as u32 == 0xC0000022 {
                denied += 1;
            } else {
                errors += 1;
            }
        }
    }

    println!("\n[*] Results:");
    println!("    Accessible: {}", accessible);
    println!("    Access denied: {}", denied);
    println!("    Other errors: {}", errors);
    println!();

    if !accessible_ports.is_empty() {
        println!("[*] Accessible ALPC ports ({}):", accessible_ports.len());
        println!("    {:<45} {:<8} {}", "Port Name", "PID", "Process");
        println!("    {}", "-".repeat(70));

        for (name, pid, proc_name) in &accessible_ports {
            // Highlight non-standard ports
            let marker = if !name.starts_with("LRPC-")
                && !name.starts_with("OLE")
                && !name.contains("DCOM")
            {
                " ◄ INTERESTING"
            } else {
                ""
            };

            println!("    {:<45} {:<8} {}{}", name, pid, proc_name, marker);
        }
    }
}

// =====================================================================
// SERVER: Run a test ALPC server for learning/testing
// =====================================================================

fn run_server(name: &str) {
    let port_path = format!("\\RPC Control\\{}", name);
    println!("[*] Starting ALPC server on: {}", port_path);

    unsafe {
        let mut name_buf = ntdll::to_utf16(&port_path);
        let mut port_name = UNICODE_STRING::from_slice(&mut name_buf);

        let mut oa = OBJECT_ATTRIBUTES::new(&mut port_name);
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        let mut port_attrs = ALPC_PORT_ATTRIBUTES::new();
        port_attrs.Flags = ALPC_PORTFLG_ALLOWIMPERSONATION;
        port_attrs.MaxMessageLength = MAX_ALPC_MESSAGE_BODY;

        let mut port_handle: HANDLE = NULL_HANDLE;

        let status = ntdll::NtAlpcCreatePort(&mut port_handle, &mut oa, &mut port_attrs);

        if !ntdll::nt_success(status) {
            println!("[!] Failed to create port: {}", helpers::ntstatus_to_string(status));
            return;
        }

        println!("[+] Port created! Handle: {:?}", port_handle);
        println!("[*] Waiting for connections... (Ctrl+C to stop)\n");

        // Message loop
        loop {
            let mut recv_msg = ALPC_MESSAGE::new();
            let mut recv_size: SIZE_T = std::mem::size_of::<ALPC_MESSAGE>();

            let recv_attrs = ntdll::alloc_message_attributes(ALPC_MESSAGE_ATTRIBUTE_ALL);
            let recv_attrs_ptr = recv_attrs
                .as_ref()
                .map(|v| v.as_ptr() as *mut ALPC_MESSAGE_ATTRIBUTES)
                .unwrap_or(std::ptr::null_mut());

            let status = ntdll::NtAlpcSendWaitReceivePort(
                port_handle,
                0, // No send, just receive
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut recv_msg.header as *mut PORT_MESSAGE,
                &mut recv_size,
                recv_attrs_ptr,
                std::ptr::null_mut(), // No timeout — block forever
            );

            if !ntdll::nt_success(status) {
                println!("[!] Receive error: {}", helpers::ntstatus_to_string(status));
                continue;
            }

            let msg_type = recv_msg.header.Type & 0xFF;
            let client_pid = recv_msg.header.ClientId.UniqueProcess as u32;
            let client_proc = helpers::get_process_name(client_pid);

            println!("[←] Message received!");
            println!("    Type: 0x{:04X} ({})", msg_type, msg_type_name(msg_type));
            println!("    From: {} (PID {})", client_proc, client_pid);
            println!("    Message ID: {}", recv_msg.header.MessageId);
            println!("    Data: {} bytes", recv_msg.header.DataLength);

            if recv_msg.header.DataLength > 0 {
                helpers::hexdump(recv_msg.get_body(), 0);
            }

            // Handle connection request
            if msg_type == 1 {
                // LPC_CONNECTION_REQUEST
                println!("    → Accepting connection...");

                let mut comm_handle: HANDLE = NULL_HANDLE;
                let status = ntdll::NtAlpcAcceptConnectPort(
                    &mut comm_handle,
                    port_handle,
                    0,
                    std::ptr::null_mut(),
                    &mut port_attrs,
                    std::ptr::null_mut(), // PortContext
                    &mut recv_msg.header as *mut PORT_MESSAGE,
                    std::ptr::null_mut(),
                    1, // Accept = TRUE
                );

                if ntdll::nt_success(status) {
                    println!("    → Client accepted! Comm handle: {:?}", comm_handle);
                } else {
                    println!("    → Accept failed: {}", helpers::ntstatus_to_string(status));
                }
            } else if msg_type == 2 {
                // LPC_REQUEST — send a reply
                println!("    → Sending reply...");

                let mut reply = ALPC_MESSAGE::new();
                reply.header = recv_msg.header;
                let reply_data = b"ACK\x00";
                reply.set_body(reply_data);
                // Keep the original MessageId for the reply
                reply.header.MessageId = recv_msg.header.MessageId;

                let status = ntdll::NtAlpcSendWaitReceivePort(
                    port_handle,
                    0,
                    &mut reply.header as *mut PORT_MESSAGE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                if ntdll::nt_success(status) {
                    println!("    → Reply sent!");
                } else {
                    println!("    → Reply failed: {}", helpers::ntstatus_to_string(status));
                }
            }

            // Analyze received attributes
            if let Some(ref attrs_buf) = recv_attrs {
                let attrs = &*(attrs_buf.as_ptr() as *const ALPC_MESSAGE_ATTRIBUTES);
                if attrs.ValidAttributes != 0 {
                    println!("    Attributes: 0x{:08X}", attrs.ValidAttributes);
                }
            }
            println!();
        }
    }
}

fn msg_type_name(t: u16) -> &'static str {
    match t {
        1 => "LPC_CONNECTION_REQUEST",
        2 => "LPC_REQUEST",
        3 => "LPC_REPLY",
        4 => "LPC_DATAGRAM",
        5 => "LPC_LOST_REPLY",
        6 => "LPC_PORT_CLOSED",
        7 => "LPC_CLIENT_DIED",
        8 => "LPC_EXCEPTION",
        9 => "LPC_DEBUG_EVENT",
        10 => "LPC_ERROR_EVENT",
        11 => "LPC_CONNECTION_REFUSED",
        _ => "UNKNOWN",
    }
}
