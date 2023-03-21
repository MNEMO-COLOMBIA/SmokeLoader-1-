rule smoke_loader
{
    meta:
        Author: Fevar54
        description = "Detects SmokeLoader behavior in an executable file"
        date: 20-03-2023
    strings:
        $str1 = "SmoKeloader" wide ascii
        $str2 = "advapi32.dll" wide ascii
        $str3 = "kernel32.dll" wide ascii
        $str4 = "VirtualAlloc" wide ascii
        $str5 = "GetProcAddress" wide ascii
        $str6 = "LoadLibraryA" wide ascii
    condition:
        $str1 and all of ($str2, $str3, $str4, $str5, $str6)
}
