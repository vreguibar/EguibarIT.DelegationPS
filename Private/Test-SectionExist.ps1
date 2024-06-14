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
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$IniContent,

        [Parameter(Mandatory = $true)]
        [string]$Section
    )

    Begin {
        Write-Verbose -Message 'Starting the section existence check process.'
    } #end Begin

    Process {
        Write-Verbose -Message ('Checking if the section {0} exists in the INI content.' -f $Section)

        try {
            if ($IniContent -match ('[{0}]' -f [regex]::Escape($Section))) {

                Write-Verbose -Message ('Section [{0}] already exists.' -f $Section)

            } else {
                Write-Verbose -Message ('Section [{0}] does not exist. Adding section.' -f $Section)

                if ($PSCmdlet.ShouldProcess('INI Content', "Add section [$Section]")) {
                    $IniContent += ('{0}[{1}]' -f $Constants.NL, $Section)
                } #end if

            } #end if
        } catch {
            Write-Error -Message ('An error occurred while checking or adding the section: {0}' -f $_)
        } #end try

    } #end Process

    End {
        Write-Verbose -Message 'Section existence check process completed.'
        return $IniContent
    } #end End
}


