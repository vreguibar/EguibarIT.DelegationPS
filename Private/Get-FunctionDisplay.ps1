Function Get-FunctionDisplay {
    <#
        .Synopsis
            Formats and displays the PsBoundParameters hashtable in a visually appealing way.

        .DESCRIPTION
            Get-FunctionDisplay formats a hashtable (typically $PsBoundParameters) into a readable
            table format suitable for verbose output or logging. It provides customizable indentation
            through the TabCount parameter and handles empty hashtables gracefully.

            This function is particularly useful for debugging or providing verbose output in complex
            PowerShell functions to show what parameters were passed to the function.

        .EXAMPLE
            Get-FunctionDisplay -HashTable $PsBoundParameters

            Formats the $PsBoundParameters from the calling function with default indentation (2 tabs).

        .EXAMPLE
            Get-FunctionDisplay -HashTable $PsBoundParameters -TabCount 4

            Formats the $PsBoundParameters with 4 tabs of indentation for deeper nesting.

        .EXAMPLE
            $MyParams = @{
                Server = 'DC01'
                Credential = $Credential
                Force = $true
            }
            Get-FunctionDisplay -HashTable $MyParams

            Formats a custom hashtable with the default indentation.

        .PARAMETER HashTable
            Hashtable variable from calling function containing parameters to format accordingly.
            Typically this will be $PsBoundParameters from the calling function.

        .PARAMETER TabCount
            Number of tab characters to use for indentation in the formatted output.
            Default value is 2.

         .OUTPUTS
            [System.String]
            Returns a formatted string representation of the provided hashtable.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Format-Table                               ║ Microsoft.PowerShell.Utility
                Out-String                                 ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    19/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://www.eguibarit.com/powershell-formatting-functions/
            https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-table
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Default',
        PositionalBinding = $true
    )]
    [OutputType([String])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Hashtable variable from calling function containing PsBoundParameters to format accordingly',
            ParameterSetName = 'Default',
            Position = 0)]
        [ValidateNotNull()]
        [Alias('Parameters', 'Params', 'BoundParameters')]
        [Hashtable]
        $HashTable,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Number of tab characters to use for indentation in the formatted output.',
            ParameterSetName = 'Default',
            Position = 1)]
        [ValidateNotNull()]
        [ValidateRange(0, 10)]
        [PSDefaultValue(Help = 'Default Value is "2"')]
        [Alias('Tabs', 'Indentation')]
        [int]
        $TabCount = 2
    )

    Begin {
        Set-StrictMode -Version Latest

        ##############################
        # Variables Definition
        [string]$FormattedOutput = [string]::Empty
        [int]$TotalHashtableCount = 0

    } # end Begin

    Process {

        # Display PSBoundparameters formatted nicely for Verbose output

        $display = $Constants.NL

        # Validate if HashTable is not empty
        if ($HashTable.Count -gt 0) {
            # Get hashtable formatted properly
            $pb = $HashTable | Format-Table -AutoSize | Out-String

            # Add corresponding tabs and new lines to each table member
            $display += $pb -split $Constants.NL | ForEach-Object { "$($Constants.HTab * $TabCount)$_" } | Out-String
        } else {
            $display = 'No PsBoundParameters to display.'
        } #end If
        $display += $Constants.NL

    } # end Process

    End {
        Return $display
    } #end END

} #end Function
