# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-7.4
Add-Type @'
public enum Encoding {
    ascii,
    ansi,
    bigendianunicode,
    bigendianutf32,
    oem,
    unicode,
    utf7,
    utf8,
    utf8BOM,
    utf8NoBOM,
    utf32
}
'@
