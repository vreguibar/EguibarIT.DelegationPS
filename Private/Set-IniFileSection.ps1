Function Set-IniFileSection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([System.Collections.Hashtable])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Hashtable containing the values from IniHashtable.inf file',
            Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $IniData,

        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'String representing the section to configure/Change on the file',
            Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Section,

        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'String representing the KEY to configure/Change on the file',
            Position = 2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Key,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'ArrayList of members to be configured as a value for the KEY.',
            Position = 3)]
        [System.String[]]
        $Members
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $NewMembers = New-Object System.Collections.ArrayList
        $UserSIDs = New-Object System.Collections.ArrayList

    } #end Begin

    Process {
        If (-not $IniData.Contains($Section)) {
            $IniData.add($Section, [ordered]@{})
        }

        If ($IniData[$Section].Contains($Key)) {
            Write-Verbose -Message ('Key "{0}" found. Getting existing values.' -f $Key)

            # Get existing value and split it into a list
            $TempMembers = ($IniData.$Section.$Key).Split(',')

            # Get all existing members (From GptTmpl.inf)
            # Check that existing values are still valid (Sid is valid)
            foreach ($ExistingMember in $TempMembers) {

                # Check if is a WellKnownSid
                if ($Variables.WellKnownSIDs[$ExistingMember.TrimStart('*')]) {
                    $CurrentMember = New-Object System.Security.Principal.SecurityIdentifier($ExistingMember.TrimStart('*'))
                } else {

                    try {
                        # Translate the SID to a SamAccountName string. If SID is not resolved, CurrentMember will be null
                        $ObjMember = New-Object System.Security.Principal.SecurityIdentifier($ExistingMember.TrimStart('*'))
                        $CurrentMember = $ObjMember.Translate([System.Security.Principal.NTAccount]).ToString()
                    } catch {
                        $CurrentMember = $null;
                    }
                }

                # If SID is not resolved, CurrentMember will be null
                # If not null, then add it to the new list
                if ($null -ne $CurrentMember) {
                    # Only add the CurrentMember if not present on NewMembers
                    if (-Not $NewMembers.Contains($CurrentMember)) {
                        $NewMembers.Add($ExistingMember);
                    } #end If
                } #end If

                # Set null to the variable for the next use.
                $CurrentMember = $null;
            } #end Foreach

            # Add new members from parameter
            # Iterate through all members
            foreach ($item in $members) {

                Try {
                    # Retrieve current SID
                    $principal = New-Object System.Security.Principal.NTAccount($Item)
                    $identity = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } Catch {
                    throw
                }

                If ( -Not (($null -eq $NewMembers) -and
                           ($NewMembers -ne 0) -and
                           ($NewMembers -ne '') -and
                           ($NewMembers -ne $false))) {
                    # Check if new sid is already defined on value. Add it if NOT.
                    if (-Not $NewMembers.Contains('*{0}' -f $identity.ToString())) {
                        $NewMembers.Add('*{0}' -f $identity.ToString());
                    }
                } else {
                    $NewMembers.Add('*{0}' -f $identity.ToString());
                } #end If
            } #end Foreach

            # Remove existing Key to avoid error Item has already been added
            $IniData[$Section].Remove($key)

            # Add content to INI hashtable
            Set-IniContent -InputObject $IniData -Sections $Section -Key $Key -value ($NewMembers -join ',')

        } else {
            Write-Verbose -Message ('Key "{0}" not existing. Proceeding to create it.' -f $Key)

            # Iterate through all members from parameter
            foreach ($item in $members) {

                # WellKnownSid function will return null if SID is not well known.
                if ($null -eq $identity) {
                    # Retrieve current SID
                    $principal = New-Object System.Security.Principal.NTAccount($Item)
                    $identity = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } #end If

                If ( -Not (($null -eq $UserSIDs) -and
                           ($UserSIDs -ne 0) -and
                           ($UserSIDs -ne '') -and
                           ($UserSIDs -ne $false))) {
                    # Check the current SID is not already on list
                    if (-Not $UserSIDs.Contains('*{0}' -f $identity.ToString())) {
                        # Add the new member to the List, adding * prefix
                        $UserSIDs.Add('*{0}' -f $identity.ToString())
                    } #end If
                } else {
                    $UserSIDs.Add('*{0}' -f $identity.ToString())
                } #end If
            } #end Foreach

            # Add content to INI hashtable
            Set-IniContent -InputObject $IniData -Sections $Section -Key $Key -Value ($UserSIDs -join ',')
        } #end If-Else

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Privileged Rights."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        Write-Output $IniData
    } #end END
}
