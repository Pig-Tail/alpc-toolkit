# ALPC Toolkit — Phase 1: Reconnaissance & Fundamentals

> Toolkit en Rust para investigación ofensiva de la superficie de ataque ALPC/RPC en Windows.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Research](https://img.shields.io/badge/purpose-security%20research-red)

---

## ¿Qué es esto?

Windows utiliza **ALPC (Advanced Local Procedure Call)** como mecanismo de IPC de bajo nivel. RPC sobre Windows lo usa internamente — casi todos los servicios del sistema exponen endpoints RPC que viven sobre puertos ALPC. Esta superficie está en gran parte **indocumentada** y es rica en vulnerabilidades históricas (EternalBlue, PrintSpooler, etc.).

Este toolkit cubre la **Fase 1** de investigación: mapear, enumerar y sondear esa superficie antes de pasar a fuzzing y explotación.

### Herramientas incluidas

| Herramienta | Función |
|---|---|
| `alpc-enum.exe` | Enumera todos los puertos ALPC y endpoints RPC del sistema |
| `rpc-scan.exe` | Escanea binarios PE para identificar interfaces RPC embebidas |
| `alpc-client.exe` | Cliente/servidor ALPC interactivo para probing y análisis de respuestas |

---

## Requisitos

- Windows 10 / 11 (x86_64) — usar en VM de investigación
- [Rust toolchain](https://rustup.rs/) con target `x86_64-pc-windows-msvc`
- Visual Studio Build Tools (linker MSVC)
- Privilegios de administrador (para enumeration completa)

---

## Build

```powershell
git clone https://github.com/Pig-Tail/alpc-toolkit.git
cd alpc-toolkit

cargo build --release
```

Binarios en `target\release\`:
- `alpc-enum.exe`
- `rpc-scan.exe`
- `alpc-client.exe`

---

## Uso

### `alpc-enum` — Enumerador de superficie de ataque

Mapea todos los puertos ALPC visibles y los correlaciona con sus procesos propietarios.

```powershell
# Enumeración completa (punto de partida recomendado)
.\alpc-enum.exe

# Solo \RPC Control\ (donde viven los endpoints RPC)
.\alpc-enum.exe --rpc-control

# Via tabla de handles del sistema (requiere admin + SeDebugPrivilege)
.\alpc-enum.exe --handles
```

**Qué buscar:**
- Procesos SYSTEM con muchos handles ALPC → mayor superficie de ataque
- Puertos con nombres no estándar (no `LRPC-*`, `OLE*`, `DCOM*`) → servicios custom
- Puertos accesibles sin restricción → candidatos para probing

---

### `rpc-scan` — Scanner de interfaces RPC

Escanea binarios PE (DLLs / EXEs) para identificar interfaces RPC embebidas. Incluye base de datos de interfaces conocidas con mapeo a MITRE ATT&CK.

```powershell
# Escanear System32 (por imports)
.\rpc-scan.exe

# Escanear directorio custom — útil para EDRs, software de terceros
.\rpc-scan.exe --path "C:\Program Files\CrowdStrike"
.\rpc-scan.exe --path "C:\Program Files\SentinelOne"

# Deep scan — busca el GUID NDR Transfer Syntax en los binarios directamente
.\rpc-scan.exe --deep

# Mostrar base de datos de interfaces conocidas/abusables
.\rpc-scan.exe --known
```

**Qué buscar:**
- DLLs que importan `RpcServerRegisterIf` pero **no** `RpcServerRegisterIf3` → sin security callback (versiones vulnerables)
- UUIDs desconocidos en software de terceros → interfaces no auditadas
- Servidores RPC en `Program Files` → superficie de vendors

---

### `alpc-client` — Cliente ALPC interactivo

Conecta a puertos ALPC, envía mensajes y analiza atributos de respuesta (SECURITY, VIEW, CONTEXT).

```powershell
# Conectar a un puerto específico
.\alpc-client.exe --port "\\RPC Control\\SomePort"

# Conectar con mensaje de conexión custom
.\alpc-client.exe --port "\\RPC Control\\SomePort" --msg "Hello"

# Probar TODOS los puertos accesibles del sistema
.\alpc-client.exe --probe-all

# Levantar un servidor ALPC de prueba (para entender el protocolo)
.\alpc-client.exe --server --name "TestResearchPort"
```

**Qué buscar:**
- Respuestas con `SECURITY` attribute → posible impersonation del cliente
- Respuestas con `VIEW` attribute → shared memory, posible heap spray si no liberan
- Servidores SYSTEM que aceptan conexiones de cualquier usuario
- Respuestas con datos inesperados → lógica del servidor expuesta

---

## Arquitectura

```
alpc-toolkit/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── alpc-core/              # Librería compartida (tipos + FFI)
│   │   └── src/
│   │       ├── lib.rs          # Módulo raíz
│   │       ├── types.rs        # Estructuras ALPC undocumented (PORT_MESSAGE, etc.)
│   │       ├── ntdll.rs        # FFI bindings a ntdll.dll (NtAlpc*)
│   │       ├── rpc.rs          # Tipos RPC + BD de interfaces conocidas
│   │       └── helpers.rs      # Utilidades: hexdump, privileges, process info
│   ├── alpc-enum/              # Herramienta de enumeración
│   ├── rpc-scan/               # Scanner de interfaces RPC
│   └── alpc-client/            # Cliente/servidor ALPC
```

### Bindings FFI implementados (`ntdll.rs`)

- `NtAlpcCreatePort` / `NtAlpcConnectPort`
- `NtAlpcSendWaitReceivePort` / `NtAlpcAcceptConnectPort`
- `NtAlpcImpersonateClientOfPort`
- `NtQuerySystemInformation` / `NtQueryDirectoryObject`
- `NtOpenDirectoryObject` / `NtOpenFile`

---

## Ejercicios de laboratorio

### Ejercicio 1: Mapear la superficie completa
```powershell
.\alpc-enum.exe > surface_map.txt
.\rpc-scan.exe --deep > rpc_interfaces.txt
.\alpc-client.exe --probe-all > accessible_ports.txt
```

### Ejercicio 2: Entender el flujo ALPC (cliente ↔ servidor)
```powershell
# Terminal 1 — servidor
.\alpc-client.exe --server --name "Lab01"

# Terminal 2 — cliente
.\alpc-client.exe --port "\\RPC Control\\Lab01" --msg "Hello from client"
```
Observa: tipo de mensaje, PID del cliente, atributos recibidos.

### Ejercicio 3: Identificar targets para Fase 2
1. `rpc-scan.exe --path "C:\Program Files"` con EDR instalado en la VM
2. Identifica interfaces RPC en binarios del EDR
3. Cruza con `alpc-enum.exe --handles` para ver qué puertos usa
4. Prueba conectar con `alpc-client.exe --port`

### Ejercicio 4: Análisis con WinDbg (complementario)
```
# Kernel debugger
!object \RPC Control
!alpc /lpc <dirección_del_puerto>
!alpc /p <dirección_del_puerto>

# Breakpoint en creación de conexión ALPC
bp nt!AlpcpCreateClientPort
```

---

## Notas técnicas

- Las estructuras ALPC son **undocumented** y pueden cambiar entre versiones de Windows. `OB_TYPE_INDEX_ALPC_PORT` (usado en handle enumeration) varía por build.
- El proyecto usa `windows-sys 0.59` para los bindings Win32/WDK.
- NDR Transfer Syntax GUID usado en deep scan: `8A885D04-1CEB-11C9-9FE8-08002B104860`
- Referencias: Alex Ionescu, csandker, James Forshaw, ProcessHacker sources.

---

## Roadmap — Fase 2

- [ ] RPC interface fuzzer
- [ ] ALPC message attribute manipulator
- [ ] Automated security callback detector
- [ ] Symlink race condition tester

---

## Disclaimer

Este toolkit está diseñado para investigación de seguridad en entornos controlados (VMs de lab). **Nunca lo uses en sistemas de producción o sin autorización explícita.**

---

## Licencia

MIT
