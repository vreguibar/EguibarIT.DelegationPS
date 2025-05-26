function Set-GPOConfigSection {

    <#
        .SYNOPSIS
            Configures a specific section and key in a GPT template (GptTmpl.inf) file with specified members.

        .DESCRIPTION
            This function creates a new key or updates an existing key within a specified section of a GPT template
            (GptTmpl.inf represented by [IniFileHandler.IniFile] class) file. It processes and merges existing values
            (if the key exists) with new members, ensuring correct resolution of SIDs and avoiding duplicates.
            A single Null-string is considered a valid value.

            1.- Check if the provided section (Parameter CurrentSection) exist on the [IniFileHandler.IniFile]$GptTmpl variable (Parameter GptTmpl)
            2.- Section exists (GptTmpl does contains the section)
            3.- Check if Key exist. If key does not exist, just create it and continue with step 4
                A.- If key exist, get the values contained.
                    Value can be a single $null string
                    comma delimited string being each item a member represented by its SID and * prefix

                    (for example,
                        Administrators would be *S-1-5-32-544,
                        Event Log Readers would be *S-1-5-32-573,
                        Server Operators would be *S-1-5-32-549...
                        full string value would be *S-1-5-32-544,*S-1-5-32-573,*S-1-5-32-549 ).

                E.- Get value as array and strip prefix '*', just having pure SID.
                F.- Iterate through all members, except if just 1 value and this is null.
                G.- Each member or iteration has to be resolved (first remove * prefix, otherwise will throw an error), either a Well-Known SID or a "normal" SID. Excluding WellKnownSids, have SID translated to an account to ensure that it continues to exist on ActiveDirectory. If the account is successfully translated, meaning it does exist in AD, and it can be added to the OK list with an * prefix. Skip duplicated. WellKnownSids can be added directly with * prefix.
                H.- If the account does not exist, it should be skipped and a warning should be displayed.
            4.- Key did not exist, so no values exist either. Key was created earlier.
                A.- Get new members from Parameter Members (This parameter can accept $null and should be treated as a single null string)
                B.- Each member or iteration has to be resolved, either a Well-Known SID or a "normal" SID. Having SID translated to an account to ensure that it continues to exist on ActiveDirectory. If the account is successfully translated, meaning it does exist in AD, it can be added to the OK list with an * prefix. Skip duplicated. WellKnownSids can be added directly with * prefix.
            5.- Convert the arrayList to a comma-delimited string (except if nullString single instance). trim end comma, period or space.
            6. Add key and value the $GptTmpl
            7.- Return updated $GptTmpl

        .PARAMETER CurrentSection
             The section in the GPT template file to be configured (e.g., "Privilege Rights" or "Registry Values").
             This section is assumed to exist.

        .PARAMETER CurrentKey
             The key within the given section (e.g., "SeAuditPrivilege" or "SeBatchLogonRight").

        .PARAMETER Members
            An array of members to be added to the key. Can be null, which will be treated as a single null string.

        .PARAMETER GptTmpl
            The GPT template object representing the GptTmpl.inf file of type [IniFileHandler.IniFile].

        .OUTPUTS
            [IniFileHandler.IniFile]

        .EXAMPLE
            Set-GPOConfigSection -CurrentSection "User Rights Assignment" -CurrentKey "SeDenyNetworkLogonRight" -Members @("TheUgly", "SG_AdAdmins") -GptTmpl $GptTmpl

        .EXAMPLE
            Set-GPOConfigSection -CurrentSection "Privilege Rights" -CurrentKey "SeAuditPrivilege" -Members @("TheGood", "SG_InfraAdmins") -GptTmpl $GptTmpl

        .NOTES
            Required modules/prerequisites:
                - ActiveDirectory
                - GroupPolicy
                - EguibarIT
                - EguibarIT.DelegationPS

            Used Functions:
                Name                                        ║ Module/Namespace
                ════════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                               ║ Microsoft.PowerShell.Utility
                Write-Warning                               ║ Microsoft.PowerShell.Utility
                Write-Error                                 ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                         ║ EguibarIT.DelegationPS
                Convert-SidToName                           ║ EguibarIT.DelegationPS
                Get-AdObjectType                            ║ EguibarIT.DelegationPS
                IniFileHandler.IniFile                      ║ EguibarIT.DelegationPS

        .NOTES
            Version:         1.2
            DateModified:    2025-03-13
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([IniFileHandler.IniFile])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The section in the GPT template file to be configured (ex. [Privilege Rights] or [Registry Values]).',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CurrentSection,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The KEY within given section (ex. SeAuditPrivilege or SeBatchLogonRight).',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CurrentKey,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Member of given KEY. This value can be Empty or Null',
            Position = 2)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]
        $Members,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Object representing the INI file values.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [IniFileHandler.IniFile]
        $GptTmpl
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $resolvedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {

        try {
            # Ensure Members is a collection (array or List), not a hashtable or other type
            if ($null -eq $Members -or $Members -is [hashtable]) {
                $Members = [System.Collections.Generic.List[object]]::new()
                $Members.Add([string]::Empty)
            } elseif ($Members -isnot [System.Collections.IEnumerable] -or $Members -is [string]) {
                # If Members is a single string or not enumerable, wrap in a list
                $tmpList = [System.Collections.Generic.List[object]]::new()
                $tmpList.Add($Members)
                $Members = $tmpList
            }

            # Ensure Members is an array with at least an empty string if null
            $membersCount = ($Members | Measure-Object).Count
            if (-not $Members -or ($membersCount -eq 1 -and [string]::IsNullOrEmpty($Members[0]))) {

                $Members = [System.Collections.Generic.List[object]]::new()
                $Members.Add([string]::Empty)
            } #end if

            # Ensure section exists
            if (-not $GptTmpl.SectionExists($CurrentSection)) {

                Write-Debug -Message ('Creating missing section: {0}' -f $CurrentSection)
                $GptTmpl.AddSection($CurrentSection)

            } #end if

            # Retrieve existing key value
            Write-Debug -Message 'Retrieve existing key value'
            $currentValue = $GptTmpl.GetKeyValue($CurrentSection, $CurrentKey)

            $existingMembers = if ($currentValue) {
                $currentValue.TrimEnd(',').Split(',', [StringSplitOptions]::RemoveEmptyEntries)
            } else {
                @()
            } #end if

            # Process existing members
            if ($existingMembers -and $existingMembers.Count -gt 0) {

                Write-Debug -Message ('Processing {0} existing members' -f ($existingMembers | Measure-Object).Count)

                foreach ($member in $existingMembers) {

                    # remove heading '*'
                    $sid = $member.TrimStart('*')

                    try {
                        # Check account SID
                        $resolvedAccount = Convert-SidToName -SID $sid

                        if ($resolvedAccount) {

                            [void]$resolvedMembers.Add('*{0}' -f $sid)

                            Write-Debug -Message ('
                                Existing member resolved: {0}
                                SID: {1}
                                ' -f $resolvedAccount[0], $sid
                            )

                        } else {
                            Write-Warning -Message ('
                                Could not resolve existing SID: {0}.
                                It may not exist anymore.' -f $sid
                            )
                        } #end if-else

                    } catch {
                        Write-Error -Message ('
                            Failed to resolve SID: {0}.
                            Error: {1}' -f $sid, $_.Exception.Message
                        )

                    } #end foreach
                } #end if

                # Process new members
                $membersCount = ($Members | Measure-Object).Count
                Write-Debug -Message ('Processing {0} new members' -f $membersCount)
                foreach ($member in $Members) {

                    if (-not [string]::IsNullOrWhiteSpace($member)) {

                        try {
                            # check AD object type and retrieve object SID
                            $CurrentMember = Get-AdObjectType -Identity $member

                            # Extract SID based on type
                            $sid = $null

                            if ($null -eq $CurrentMember) {

                                Write-Warning -Message ('Could not resolve member: {0}' -f $member)
                                continue

                            } elseif ($CurrentMember -is [string]) {

                                # Already a SID string
                                $sid = $CurrentMember
                                Write-Debug -Message ('Member {0} is a SID string: {1}' -f $member, $sid)

                            } elseif ($CurrentMember -is [System.Security.Principal.SecurityIdentifier]) {

                                # SecurityIdentifier object
                                $sid = $CurrentMember.Value
                                Write-Debug -Message ('Member {0} is a SecurityIdentifier object with value: {1}' -f $member, $sid)

                            } elseif ($CurrentMember -is [Microsoft.ActiveDirectory.Management.ADObject] -or
                                $CurrentMember -is [Microsoft.ActiveDirectory.Management.ADAccount] -or
                                $CurrentMember -is [Microsoft.ActiveDirectory.Management.ADComputer] -or
                                $CurrentMember -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                                $CurrentMember -is [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit] -or
                                $CurrentMember -is [Microsoft.ActiveDirectory.Management.ADServiceAccount]) {

                                # Any AD object type
                                $sid = $CurrentMember.SID.Value
                                Write-Debug -Message ('Member {0} is an AD object with SID: {1}' -f $member, $sid)

                            } else {

                                # Try to extract value property if it exists
                                if ($CurrentMember.PSObject.Properties['SID']) {

                                    if ($CurrentMember.SID -is [System.Security.Principal.SecurityIdentifier]) {

                                        $sid = $CurrentMember.SID.Value

                                    } else {

                                        $sid = $CurrentMember.SID
                                    }

                                    Write-Debug -Message ('Member {0} has SID property: {1}' -f $member, $sid)

                                } elseif ($CurrentMember.PSObject.Properties['Value']) {
                                    $sid = $CurrentMember.Value

                                    Write-Debug -Message ('Member {0} has Value property: {1}' -f $member, $sid)

                                } else {

                                    Write-Warning -Message ('
                                    Unexpected return type from Get-AdObjectType: {0}, cannot extract SID
                                    ' -f $CurrentMember.GetType().FullName
                                    )
                                    continue

                                } #end If-ElseIf-Else

                            } #end If-ElseIf-ElseIf-ElseIf-Else

                            if ($sid) {

                                [void]$resolvedMembers.Add('*{0}' -f $sid)

                                Write-Debug -Message ('
                                New member resolved: {0}
                                SID: {1}
                                ' -f $member, $sid
                                )

                            } else {

                                Write-Warning -Message ('Could not extract SID for member: {0}' -f $member)

                            } #end If-else

                        } catch {
                            Write-Error -Message ('
                            Failed to resolve new member: {0}, Error: {1}' -f $member, $_.Exception.Message
                            )
                            Write-Verbose -Message ('Stack trace: {0}' -f $_.Exception.StackTrace)
                        } #end try-catch

                    } #end if

                } #end Foreach

                # Prepare the final string for GptTmpl
                $finalValue = if ($resolvedMembers.Count -eq 1 -and [string]::IsNullOrEmpty($resolvedMembers[0])) {
                    [string]::Empty
                } else {
                ($resolvedMembers -join ',').TrimEnd(',')
                } #end if

                # Update the GPO template

                if ($PSCmdlet.ShouldProcess("$CurrentSection -> $CurrentKey", 'Updating GptTmpl')) {

                    $GptTmpl.SetKeyValue($CurrentSection, $CurrentKey, $finalValue)

                    $sb = [System.Text.StringBuilder]::new()
                    [void]$sb.AppendFormat( 'GPO section updated.{0}', $Constants.NL )
                    [void]$sb.AppendFormat( '    Section: {0}{1}', $CurrentSection, $Constants.NL )
                    [void]$sb.AppendFormat( '    Key:     {0}{1}', $CurrentKey, $Constants.NL)
                    [void]$sb.AppendFormat( '    Members: {0}{1}', $finalValue, $Constants.NL )

                    Write-Verbose -Message $sb.ToString()

                } #end if
            } catch {

                Write-Error -Message ('An error occurred while processing {0}: {1}' -f $CurrentKey, $_.Exception.Message)
                Write-Verbose -Message ('Stack trace: {0}' -f $_.Exception.StackTrace)

            } #end try-catch

        } #end Process

        End {
            if ($null -ne $Variables -and $null -ne $Variables.FooterDelegation) {
                $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                    'configuration of GptTmpl object section (Private Function).')
                Write-Verbose -Message $txt
            }
            return $GptTmpl
        } #end End
    } #end function Set-GPOConfigSection
