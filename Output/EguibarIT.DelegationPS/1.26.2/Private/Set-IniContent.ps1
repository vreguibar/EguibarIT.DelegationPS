Function Set-IniContent {
    [CmdletBinding(DefaultParameterSetName = "Object")]

    Param (
        # Specifies the Hashtable to be modified.
        # Enter a variable that contains the objects or type a command or expression that gets the objects.
        [Parameter( Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Object")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $InputObject,

        [Parameter( Mandatory = $true, ParameterSetName = "Object")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,

        [Parameter( Mandatory = $true, ParameterSetName = "Object")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Value,

        # String array of one or more sections to limit the changes to, separated by a comma.
        # Surrounding section names with square brackets is not necessary but is supported.
        # Ini keys that do not have a defined section can be modified by specifying '_' (underscore) for the section.
        [Parameter( ParameterSetName = "Object" )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Sections
    )

    Begin {
        # Update or add the name/value pairs to the section.
        Function Update-IniEntry {
            param ($InputObject, $section)

                if (-Not ($InputObject[$section])) {
                    Write-Verbose ("$($MyInvocation.MyCommand.Name):: '{0}' section does not exist, creating it." -f $section)
                    $InputObject.add($Section, @{})
                }

                Write-Verbose ("$($MyInvocation.MyCommand.Name):: Setting '{0}' key in section {1} to '{2}'." -f $key, $section, $value)
                $InputObject[$section].add($key, $value)

        } #end Function
    } #end Begin

    # Update the specified keys in the list, either in the specified section or in all sections.
    Process {

        # Specific section(s) were requested.
        if ($Sections) {
            foreach ($section in $Sections) {
                # Get rid of whitespace and section brackets.
                $section = $section.Trim() -replace '[][]', ''

                Write-Debug ("Processing '{0}' section." -f $section)

                Update-IniEntry $InputObject $section
            }
        } else {
            # No section supplied, go through the entire ini since changes apply to all sections.
            foreach ($item in $InputObject.GetEnumerator()) {
                $section = $item.key

                Write-Debug ("Processing '{0}' section." -f $section)

                Update-IniEntry $InputObject $section
            }
        }

    } #end Process

    End {
        return $InputObject
    } #end END
}
