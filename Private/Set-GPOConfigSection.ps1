# ConfigRestrictionsOnSection on file GpoPrivilegeRights.cs

function Set-GPOConfigSection {
    <#
        .SYNOPSIS
            Configures a specific section and key in a GPT template (GptTmpl.inf) file with specified members.

        .DESCRIPTION
            This function updates or creates a section and key within a GPT template (GptTmpl.inf) file, adding the specified members to it.
            It ensures that members are correctly resolved and avoids duplicates.

        .PARAMETER CurrentSection
            The section in the GPT template file to be configured.

        .PARAMETER CurrentKey
            The key within the section to be configured.

        .PARAMETER Members
            An array of members to be added to the key in the GPT template file.

        .PARAMETER GptTmpl
            The GPT template object representing the GptTmpl.inf file.

        .EXAMPLE
            Set-GPOConfigSection -CurrentSection "User Rights Assignment" -CurrentKey "SeDenyNetworkLogonRight" -Members @("User1", "Group1") -GptTmpl $GptTmpl

        .INPUTS
            [string], [string], [string[]], [IniFileHandler.IniFile]

        .OUTPUTS
            [IniFileHandler.IniFile]
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

        [bool]$status = $false
        $UserSIDs = [System.Collections.Generic.List[string]]::new()
        $TempMembers = [System.Collections.Generic.List[string]]::new()
        $NewMembers = [System.Collections.Generic.List[string]]::new()
        $CurrentMember = $null
        $section = $null
    } #end Begin

    Process {
        try {
            if ($PSCmdlet.ShouldProcess("Configuring section [$CurrentSection] with key [$CurrentKey] in GptTmpl.inf file")) {

                Write-Verbose -Message ('Processing configuration for section [{0}] and key [{1}]...' -f $CurrentSection, $CurrentKey)

                if ($GptTmpl.Sections.TryGetValue($CurrentSection, [ref]$section) -and $section.KeyValuePair.KeyValues.ContainsKey($CurrentKey)) {

                    Write-Verbose -Message ('Key [{0}] exists. Updating values.' -f $CurrentKey)

                    $directValue = ($GptTmpl.GetKeyValue($CurrentSection, $CurrentKey)).TrimEnd(',')
                    $TempMembers.AddRange($directValue.Split(','))

                    foreach ($ExistingMember in $TempMembers) {

                        if (-Not [string]::IsNullOrEmpty($ExistingMember)) {
                            Write-Verbose -Message ('Processing existing member: {0}' -f $ExistingMember)

                            $CurrentMember = ConvertTo-AccountName -SID $ExistingMember.TrimStart('*')

                            if (($null -ne $CurrentMember) -and -not
                                $NewMembers.Contains($ExistingMember)) {
                                $NewMembers.Add($ExistingMember)
                            } #end If
                            $CurrentMember = $null
                        } #end If
                    } #end Foreach

                    # Ensure members has values. If ONLY one and this is NULL or EMPTY,
                    # then just skip foreach and add EMPTY
                    If (-Not (($Members.Count -eq 1) -and ([string]::IsNullOrEmpty($Members[0])))) {

                        #iterate all members
                        foreach ($item in $Members) {

                            Write-Verbose -Message ('Processing new member: {0}' -f $item)

                            if ($item -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                                $item -is [Microsoft.ActiveDirectory.Management.ADAccount]) {
                                $identity = $item.SID
                            } else {
                                $identity = Test-NameIsWellKnownSid -Name $item
                            } #end If-Else

                            if ((-not $NewMembers.Contains('*{0}' -f $identity.Value)) -and
                                $null -ne $identity) {

                                $NewMembers.Add('*{0}' -f $identity.Value)
                            } #end If
                        } #end Foreach

                        # Add empty to array
                        $NewMembers.Add([string]::Empty)
                    } #end If

                    $GptTmpl.SetKeyValue($CurrentSection, $CurrentKey, ($NewMembers -join ',').TrimEnd(','))
                } else {

                    Write-Verbose -Message ('Key [{0}] does not exist. Creating new key...' -f $CurrentKey)

                    # Ensure members has values. If ONLY one and this is NULL or EMPTY,
                    # then just skip foreach and add EMPTY
                    If (-Not (($Members.Count -eq 1) -and ([string]::IsNullOrEmpty($Members[0])))) {

                        #iterate all members
                        foreach ($item in $Members) {

                            Write-Verbose -Message ('Processing new member: {0}' -f $item)

                            if ($item -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                                $item -is [Microsoft.ActiveDirectory.Management.ADAccount]) {
                                $identity = $item.SID
                            } else {
                                $identity = Test-NameIsWellKnownSid -Name $item
                            } #end If-Else

                            if ($null -eq $identity) {
                                $identity = ConvertTo-SID -AccountName $item
                            } #end If

                            if ((-not $UserSIDs.Contains('*{0}' -f $identity.Value)) -and
                                $null -ne $identity) {
                                $UserSIDs.Add('*{0}' -f $identity.Value)
                            } #end If
                        } #end Foreach

                        # Add empty to array
                        $UserSIDs.Add([string]::Empty)
                    } #end If

                    $GptTmpl.SetKeyValue($CurrentSection, $CurrentKey, ($UserSIDs -join ',').TrimEnd(','))
                } #end If-Else

                $status = $true
            } #end If
        } catch {
            Write-Error -Message "An error occurred: $_.Exception.Message"
            $status = $false
        } finally {
            $status = $true
        } #end Try-Catch-Finally
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'setting GPO section (Private Function).'
        )
        Write-Verbose -Message $txt

        return $GptTmpl
    } #end End
}
