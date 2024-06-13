# Helper Function: Test-SectionExist
function Test-SectionExist {
    param (
        [string]$IniContent,
        [string]$Section
    )
    if (-not $IniContent -match "^\[$Section\]") {
        $IniContent += "`n[$Section]`n"
    }
    return $IniContent
}
