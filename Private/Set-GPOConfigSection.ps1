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
                G.- Each member or iteration has to be resolved (first remove * prefix, otherwise will throw an error), either a "normal" SID or a Well-Known SID. Having SID translated to an account to ensure that it continues to exist on ActiveDirectory. If the account is successfully translated, meaning it does exist in AD, and it can be added to the OK list with an * prefix. Skip duplicated.
            4.- Key did not exist, so no values exist either. Key was created earlier.
                A.- Get new members from Parameter Members (Tis parameter can accept $null and should be treated as a single null string)
                B.- Each member or iteration has to be resolved, either a "normal" SID or a Well-Known SID. Having SID translated to an account to ensure that it continues to exist on ActiveDirectory. If the account is successfully translated, meaning it does exist in AD, it can be added to the OK list with an * prefix. Skip duplicated.
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
            Set-GPOConfigSection -CurrentSection "User Rights Assignment" -CurrentKey "SeDenyNetworkLogonRight" -Members @("User1", "Group1") -GptTmpl $GptTmpl

    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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
            HelpMessage = 'TheKEY within given section (ex. SeAuditPrivilege or SeBatchLogonRight).',
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
        [string[]]
        $Members,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = '.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [IniFileHandler.IniFile]
        $GptTmpl
    )

    Begin {
        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $resolvedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {

        try {
            # Ensure Members is an array with at least an empty string if null
            if (-not $Members -or ($Members.Count -eq 1 -and [string]::IsNullOrEmpty($Members[0]))) {
                $Members = @([string]::Empty)
            } #end if

            # Ensure section exists
            if (-not $GptTmpl.SectionExists($CurrentSection)) {

                Write-Verbose -Message ('
                    Creating missing section: {0}
                    ' -f $CurrentSection
                )
                $GptTmpl.AddSection($CurrentSection)
            } #end if

            # Retrieve existing key value
            $currentValue = $GptTmpl.GetKeyValue($CurrentSection, $CurrentKey)

            $existingMembers = if ($currentValue) {
                $currentValue.TrimEnd(',').Split(',', [StringSplitOptions]::RemoveEmptyEntries)
            } else {
                @()
            } #end if

            # Process existing members
            foreach ($member in $existingMembers) {

                # remove heading '*'
                $sid = $member.TrimStart('*')

                try {
                    # Check account SID
                    $resolvedAccount = Convert-SidToName -SID $sid

                    if ($resolvedAccount) {

                        [void]$resolvedMembers.Add('*{0}' -f $sid)
                        Write-Verbose -Message ('
                            Existing member resolved: {0}
                            SID: {1}
                            ' -f $resolvedAccount[0], $sid
                        )

                    } #end if

                } catch {
                    Write-Warning -Message ('Failed to resolve SID: {0}. It may not exist anymore.' -f $sid)
                } #end try-catch

            } #end foreach

            # Process new members
            foreach ($member in $Members) {

                if (-not [string]::IsNullOrWhiteSpace($member)) {

                    try {
                        # check AD object type and retrieve object SID
                        $CurrentMember = Get-AdObjectType -Identity $member

                        if ($CurrentMember -is [string]) {

                            # Already a SID
                            $sid = $CurrentMember

                        } elseif ($CurrentMember.PSObject.Properties['Value']) {

                            # Extract SID from object
                            $sid = $CurrentMember.Value

                        } else {

                            Write-Error -Message ('
                                Unexpected return type from Get-AdObjectType: {0}
                                ' -f $CurrentMember.GetType().Name
                            )

                        } #end if-elseif-else

                        if ($sid) {

                            [void]$resolvedMembers.Add('*{0}' -f $sid)
                            Write-Verbose -Message ('
                                New member resolved: {0}
                                SID: {1}
                                ' -f $member, $sid
                            )

                        } #end If
                    } catch {
                        Write-Warning -Message ('Failed to resolve new member: {0}' -f $member)
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
            } #end if

            Write-Verbose -Message ('
                GPO section updated
                Current Section: {0}
                Current Key: {1}
                Value: {2}
                ' -f $CurrentSection, $CurrentKey, $finalValue
            )

        } catch {

            Write-Error -Message ('An error occurred while processing {0}: {1}' -f $CurrentKey, $_)

        } #end try-catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'configuration of GptTmpl object section (Private Function).'
        )
        Write-Verbose -Message $txt

        return $GptTmpl
    }
} #end Set-GPOConfigSection
