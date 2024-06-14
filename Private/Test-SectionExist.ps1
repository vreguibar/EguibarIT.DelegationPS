# Helper Function: Test-SectionExist
function Test-SectionExist {
    <#
        .SYNOPSIS
            Checks if a section exists in an INI file content and adds it if it does not exist.

        .DESCRIPTION
            This function takes the content of an INI file and a section name as inputs. It checks if the specified section exists in the INI content. If the section does not exist, it adds the section at the end of the INI content. The function returns the modified INI content.

        .PARAMETER IniContent
            The content of the INI file as a string.

        .PARAMETER Section
            The name of the section to check for existence in the INI content.

        .EXAMPLE
            $content = Get-Content -Path 'C:\path\to\file.ini' -Raw
            $modifiedContent = Test-SectionExist -IniContent $content -Section 'NewSection'

        .INPUTS
            [string] - The content of the INI file.
            [string] - The section name to check.

        .OUTPUTS
            [string] - The modified INI content with the section added if it did not exist.

        .NOTES
            Version:         1.0
                DateModified:    14/Jun/2024
                LasModifiedBy:   Vicente Rodriguez Eguibar
                    vicente@eguibar.com
                    Eguibar Information Technology S.L.
                    http://www.eguibarit.com
    #>
    param (
        [string]$IniContent,
        [string]$Section
    )
    if (-not ($IniContent -match ('[{0}]' -f $Section))) {
        $IniContent += ('{0}[{1}]' -f $Constants.NL, $Section)
    }
    return $IniContent
}
