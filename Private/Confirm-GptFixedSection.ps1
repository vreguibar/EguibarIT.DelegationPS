# Helper Function: Ensure-GptFixedSections
function Confirm-GptFixedSection {
    <#
        .SYNOPSIS
            Ensures that the fixed sections [Unicode] and [Version] are present in the provided INI content.

        .DESCRIPTION
            This function checks if the provided INI content includes the sections [Unicode] and [Version]. If not, it prepends these sections to the content.

        .PARAMETER IniContent
            The content of the INI file as a string.

        .EXAMPLE
            $content = Get-Content -Path 'C:\Path\To\Your\File.ini' -Raw
            $updatedContent = Confirm-GptFixedSection -IniContent $content
            Set-Content -Path 'C:\Path\To\Your\File.ini' -Value $updatedContent

        .INPUTS
            System.String. The content of an INI file.

        .OUTPUTS
            System.String. The updated content of the INI file.

        .NOTES
            Version:         1.0
                DateModified:    14/Jun/2024
                LasModifiedBy:   Vicente Rodriguez Eguibar
                    vicente@eguibar.com
                    Eguibar Information Technology S.L.
                    http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]
        $IniContent
    )

    Begin {

        $fixedSections = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
'@

    } #end Begin

    Process {
        Write-Verbose 'Ensuring fixed sections [Unicode] and [Version] are present'
        if (-not $IniContent -match ('[Unicode]' -and '[Version]')) {
            $IniContent = $fixedSections + $IniContent
        }
    } #end Process

    End {
        return $IniContent
    } #end End
}
