Function Set-IniFileSection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([System.Collections.Hashtable])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Hashtable containing the values from IniHashtable.inf file',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $IniData,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'String representing the section to configure/Change on the file',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Section,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'String representing the KEY to configure/Change on the file',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Key,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'ArrayList of members to be configured as a value for the KEY.',
            Position = 3)]
        [System.Collections.Generic.List[object]]
        $Members
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $NewMembers = [System.Collections.Generic.List[object]]::New()
        $UserSIDs = [System.Collections.Generic.List[object]]::New()

    } #end Begin

    Process {
        If (-not $IniData.Contains($Section)) {
            Write-Verbose -Message ('Section "{0}" does not exist. Creating it!.' -f $Section)
            $IniData.add($Section, [ordered]@{})
        }

        If ($IniData[$Section].Contains($Key)) {
            Write-Verbose -Message ('Key "{0}" found. Getting existing values.' -f $Key)

            # Get existing value and split it into a list
            $TempMembers = ($IniData.$Section.$Key).Split(',')

            # Get all existing members (From GptTmpl.inf)
            # Check that existing values are still valid (Sid is valid)
            foreach ($ExistingMember in $TempMembers) {
                try {
                    # Check if is a WellKnownSid
                    if ($Variables.WellKnownSIDs[$ExistingMember.TrimStart('*')]) {
                        # SID is effectively a WellKnownSid.
                        $CurrentMember = [System.Security.Principal.SecurityIdentifier]::New($ExistingMember.TrimStart('*'))
                    } else {
                        if ( [string]::Empty -ne $item ) {
                            # Translate the SID to a SamAccountName string. If SID is not resolved, CurrentMember will be null
                            $ObjMember = [System.Security.Principal.SecurityIdentifier]::New($ExistingMember.TrimStart('*'))
                            $CurrentMember = $ObjMember.Translate([System.Security.Principal.NTAccount]).ToString()
                        } else {
                            $CurrentMember = [string]::Empty
                        }
                    } #end If-Else

                    # If SID is not resolved, CurrentMember will be null
                    # If not null, then add it to the new list
                    if ($null -ne $CurrentMember -and -not $NewMembers.Contains($CurrentMember)) {
                        # Only add the CurrentMember if not present on NewMembers
                        $NewMembers.Add($CurrentMember)
                    } #end If
                } catch {
                    Write-Error -Message ('Error when trying to translate to SID. {0}' -f $_)
                    throw
                } #end Try-Catch

                # Set null to the variable for the next use.
                $CurrentMember = $null;
            } #end Foreach

            # Add new members from $Members parameter.
            # Iterate through all members.
            foreach ($item in $members) {

                # Check if current item is string. If item is other, then try to get the object and its SID
                If ($item -isnot [string]) {
                    $CurrentItem = Get-AdObjectType -Identity $item -ErrorAction SilentlyContinue

                    If ($currentItem) {
                        $item = $CurrentItem.SID.Value
                    }
                }

                Try {
                    # Check if is a WellKnownSid
                    if ($Variables.WellKnownSIDs[$item]) {
                        # SID is effectively a WellKnownSid.
                        $CurrentMember = [System.Security.Principal.SecurityIdentifier]::New($item)
                    } else {
                        # Check for empty members
                        if ( [string]::Empty -eq $item ) {
                            $identity = [string]::Empty
                        } else {
                            # Retrieve current SID
                            $principal = [System.Security.Principal.NTAccount]::New($Item)
                            $identity = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        }
                    } #end If-Else

                    If ( [string]::Empty -eq $item ) {
                        # Add empty member
                        $NewMembers.Add([string]::Empty)
                    } else {
                        # Check if new sid is already defined on value. Add it if NOT.
                        if (-Not $NewMembers.Contains('*{0}' -f $identity.ToString())) {
                            $NewMembers.Add('*{0}' -f $identity.ToString());

                        } #end If
                    }#end If-Else
                } Catch {
                    Write-Error -Message ('Error processing member {0}: {1}' -f $item, $_)
                    throw
                } #end Try-Catch
            } #end Foreach

            # Remove existing Key to avoid error Item has already been added
            $IniData[$Section].Remove($key)

            # Add content to INI hashtable
            Set-IniContent -InputObject $IniData -Sections $Section -Key $Key -value ($NewMembers -join ',')

        } else {
            Write-Verbose -Message ('Key "{0}" not existing. Proceeding to create it.' -f $Key)

            # Add new members from $Members parameter
            # Iterate through all members
            foreach ($item in $members) {

                # Check if current item is string. If item is other, then try to get the object and its SID
                If ($item -isnot [string]) {
                    $CurrentItem = Get-AdObjectType -Identity $item -ErrorAction SilentlyContinue

                    If ($currentItem) {
                        $item = $CurrentItem.SamAccountName
                    }
                }

                Try {
                    # Check if is a WellKnownSid
                    if ($Variables.WellKnownSIDs[$item]) {
                        # SID is effectively a WellKnownSid.
                        $CurrentMember = [System.Security.Principal.SecurityIdentifier]::New($item)
                    } else {
                        # Check for empty members
                        if ( [string]::Empty -eq $item ) {
                            $identity = [string]::Empty
                        } else {
                            # Retrieve current SID
                            $principal = [System.Security.Principal.NTAccount]::New($Item)
                            $identity = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        }
                    } #end If-Else

                    If ( [string]::Empty -eq $item ) {
                        # Add empty member
                        $NewMembers.Add([string]::Empty)
                    } else {
                        # Check if new sid is already defined on value. Add it if NOT.
                        if (-Not $NewMembers.Contains('*{0}' -f $identity.ToString())) {
                            $NewMembers.Add('*{0}' -f $identity.ToString());

                        } #end If
                    }#end If-Else
                } Catch {
                    Write-Error -Message ('Error processing member {0}: {1}' -f $item, $_)
                    throw
                } #end Try-Catch
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
