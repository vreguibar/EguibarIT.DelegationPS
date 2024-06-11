Function Set-IniContent {
    <#
        .SYNOPSIS
            Modifies the content of an INI file stored as a Hashtable.

        .DESCRIPTION
            This function allows you to update or add key/value pairs within specified sections of an INI file, represented as a Hashtable.

        .PARAMETER InputObject
            The Hashtable representing the INI file content to be modified.

        .PARAMETER Key
            The key to be added or modified within the specified sections.

        .PARAMETER Value
            The value to be associated with the key. If not provided, the key will be removed.

        .PARAMETER Sections
            An array of section names to limit the changes to. If not provided, changes apply to all sections.

        .EXAMPLE
            $iniContent = @{
                'Section1' = @{
                    'Key1' = 'Value1'
                }
                'Section2' = @{
                    'Key2' = 'Value2'
                }
            }
            Set-IniContent -InputObject $iniContent -Key 'Key3' -Value 'Value3' -Sections 'Section1'

        .INPUTS
            System.Collections.Hashtable

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------

        .NOTES
            Version:         1.4
            DateModified:    11/Jun/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([Hashtable])]

    Param (
        # Specifies the Hashtable to be modified.
        # Enter a variable that contains the objects or type a command or expression that gets the objects.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True,
            HelpMessage = 'The Hashtable representing the INI file content to be modified.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $InputObject,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True,
            HelpMessage = 'The key to be added or modified within the specified sections.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True,
            HelpMessage = 'The value to be associated with the key. If not provided, the key will be removed.',
            Position = 2)]
        [String]
        $Value,

        # String array of one or more sections to limit the changes to, separated by a comma.
        # Surrounding section names with square brackets is not necessary but is supported.
        # Ini keys that do not have a defined section can be modified by specifying '_' (underscore) for the section.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True,
            HelpMessage = 'An array of section names to limit the changes to.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Sections
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition


        # Update or add the name/value pairs to the section.
        Function Update-IniEntry {
            [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]

            param (
                [Parameter(Mandatory = $true)]
                [System.Collections.Hashtable]
                $InputObject,

                [Parameter(Mandatory = $true)]
                [String]
                $Section
            )

            if (-Not ($InputObject[$section])) {
                Write-Verbose -Message ("Creating new section '{0}'." -f $Section)
                $InputObject.add($Section, @{})
            }

            Write-Verbose ('Setting {0} key in section {1} to {2}' -f $key, $section, $value)
            $InputObject[$section].add($key, $value)

        } #end Function
    } #end Begin

    # Update the specified keys in the list, either in the specified section or in all sections.
    Process {

        try {
            # Specific section(s) were requested.
            if ($Sections) {
                foreach ($section in $Sections) {
                    # Get rid of whitespace and section brackets.
                    $section = $section.Trim() -replace '[][]', ''

                    if ($Force -or $PSCmdlet.ShouldProcess("Section: $section", "Update key '$Key' with value '$Value'")) {

                        Write-Verbose -Message ('Processing {0} section.' -f $section)
                        Update-IniEntry $InputObject $section

                    } #end If
                } #end ForEach
            } else {
                # No section supplied, go through the entire ini since changes apply to all sections.
                foreach ($item in $InputObject.GetEnumerator()) {
                    $section = $item.key

                    if ($Force -or $PSCmdlet.ShouldProcess("Section: $section", "Update key '$Key' with value '$Value'")) {

                        Write-Verbose -Message ('Processing {0} section.' -f $section)
                        Update-IniEntry $InputObject $section

                    } #end If
                } #end ForEach
            } #end If-Else
        } Catch {
            Write-Error -Message ('An error occurred: {0}' -f $_)
            throw
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Privileged Rights."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $InputObject
    } #end END
}
