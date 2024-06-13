# Helper Function: Set-IniFileSectionNEW
function Set-IniFileSectionNEW {
    param (
        [string]$IniContent,
        [string]$Section,
        [string[]]$Members
    )
    Write-Verbose "Setting INI file section [$Section] with members: $($Members -join ', ')"
    $sectionContent = "[$Section]`n" + ($Members -join ',')
    if ($IniContent -match "^\[$Section\][^\[]*") {
        $IniContent = $IniContent -replace "^\[$Section\][^\[]*", $sectionContent
    } else {
        $IniContent += "`n" + $sectionContent
    }
    return $IniContent
}
