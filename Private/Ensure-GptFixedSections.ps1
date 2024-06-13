Ensure-GptFixedSections

# Helper Function: Ensure-GptFixedSections
function Ensure-GptFixedSections {
    param (
        [string]$IniContent
    )
    $fixedSections = @"
[Unicode]
Unicode=yes
[Version]
signature="\$CHICAGO\$"
Revision=1
"@
    Write-Verbose 'Ensuring fixed sections [Unicode] and [Version] are present'
    if (-not $IniContent -match '\[Unicode\]') {
        $IniContent = $fixedSections + $IniContent
    }
    return $IniContent
}
