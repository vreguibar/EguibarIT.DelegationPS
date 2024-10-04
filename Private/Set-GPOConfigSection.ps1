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

            # Check if the key exists
            $currentValue = $GptTmpl.GetKeyValue($CurrentSection, $CurrentKey)

            if ([string]::IsNullOrEmpty($currentValue)) {

                Write-Verbose -Message ('
                    Key {0} not found in
                    section {1}.
                    Creating new key.' -f
                    $CurrentKey, $CurrentSection
                )

            } else {
                Write-Verbose -Message ('
                    Key {0} found in
                    section {1}.
                    Processing existing members.' -f
                    $CurrentKey, $CurrentSection
                )

                # Process existing members

                # get value, separate it by comma and remove empty
                $existingMembers = $currentValue.TrimEnd(',').Split(',', [StringSplitOptions]::RemoveEmptyEntries)

                if (
                    ($existingMembers.Count -eq 1) -and
                    [string]::IsNullOrEmpty($existingMembers[0])
                ) {

                    Write-Verbose -Message 'Existing value is a single null string.'

                } else {

                    # Iterate all existing members
                    foreach ($member in $existingMembers) {

                        $resolvedAccount = $null

                        #remove * prefix from member
                        $sid = $member.TrimStart('*')

                        try {
                            # Call function to resolve SID
                            $resolvedAccount = ConvertTo-AccountName -SID $sid
                        } catch {
                            Write-Error -Message ('
                                Failed to resolve existing member with SID: {0}
                                This item will not be added to the Rights Assignment section.' -f
                                $sid
                            )
                            Get-ErrorDetail -ErrorRecord $_
                        } #end Try-Catch

                        if ($resolvedAccount) {
                            [void]$resolvedMembers.Add('*{0}' -f $sid)
                            Write-Verbose ('
                                Resolved existing member: {0}
                                                     SID: {1}' -f
                                $resolvedAccount[0], $sid
                            )
                        } #end If
                    } #end Foreach
                } #end If-Else
            } #end If-Else

            # Process new members
            if (
                ($null -eq $Members) -or
                (($Members.Count -eq 1) -and [string]::IsNullOrEmpty($Members[0]))
            ) {
                Write-Verbose -Message 'New members parameter is null or a single null string.'

                $resolvedMembers.Clear()
                [void]$resolvedMembers.Add( [string]::Empty )

            } else {

                #iterate all new members
                foreach ($member in $Members) {

                    if (-not [string]::IsNullOrWhiteSpace($member)) {

                        # Resolve SID to AD Identity
                        #$sid = Resolve-MemberIdentity -Member $member
                        $ReturnedMember = Get-AdObjectType -Identity $member

                        If ($ReturnedMember) {
                            $Sid = $ReturnedMember.SID.Value
                        } else {
                            $Sid = Test-NameIsWellKnownSid -Name $member
                        } #end If-Else

                        if ($sid) {

                            [void]$resolvedMembers.Add('*{0}' -f $sid)
                            Write-Verbose ('
                                Resolved new member: {0}
                                                SID: {1}' -f
                                $member, $sid
                            )

                        } else {
                            Write-Error -Message ('
                                Failed to resolve new member: {0}
                                Item will not be added to the corresponding section.' -f
                                $member
                            )
                        } #end If-Else

                    } #end If

                } #end Foreach

            } #end If-Else

            # Convert resolved members to string
            $updatedValue = if (
                ($resolvedMembers.Count -eq 1) -and
                ($null -eq $resolvedMembers[0])
            ) {

                # add empty string
                [string]::Empty

            } else {

                # Join all members to a comma limited string
                ($resolvedMembers | Sort-Object) -join ','

            } #end If-Else

            # remove unwanted characters from the end.
            $updatedValue = $updatedValue.TrimEnd(',. ')

            if ($PSCmdlet.ShouldProcess("$CurrentKey in section $CurrentSection", 'Updating key value')) {
                # Update the GPT template
                $GptTmpl.SetKeyValue($CurrentSection, $CurrentKey, $updatedValue)
                Write-Verbose -Message ('
                Updated key {0}
                in section {1}
                with value: {2}' -f
                    $CurrentKey, $CurrentSection, $updatedValue
                )
            } else {
                Write-Verbose -Message 'Skipping update due to WhatIf condition'
            }

        } catch {
            Write-Error -Message ('
                Failed to update key {0} in section {1}.
                {2}' -f
                $CurrentKey, $CurrentSection, $_
            )
            Get-ErrorDetail -ErrorRecord $_
        } #end Try-Catch
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'configuration of GptTmpl object section (Private Function).'
        )
        Write-Verbose -Message $txt

        return $GptTmpl
    }
} #end Set-GPOConfigSection
