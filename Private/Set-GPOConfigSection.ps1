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
            [string], [string], [string[]], [IniFile]

        .OUTPUTS
            [IniFile]
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([IniFile])]

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
            HelpMessage = '.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CurrentKey,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = '.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Members,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = '.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [IniFile]
        $GptTmpl
    )

    Begin {
        # Initialize variables
        [bool]$status = $false
        $UserSIDs = [System.Collections.Generic.List[string]]::new()
        $TempMembers = [System.Collections.Generic.List[string]]::new()
        $NewMembers = [System.Collections.Generic.List[string]]::new()
        $CurrentMember = $null
    } #end Begin

    Process {
        try {
            if ($PSCmdlet.ShouldProcess("Configuring section [$CurrentSection] with key [$CurrentKey] in GptTmpl.inf file")) {

                Write-Verbose -Message ('Processing configuration for section [{0}] and key [{1}]...' -f $CurrentSection, $CurrentKey)

                if ($GptTmpl.Sections.GetSection($CurrentSection).KeyValuePair.ContainsKey($CurrentKey)) {

                    Write-Verbose -Message ('Key [{0}] exists. Updating values.' -f $CurrentKey)

                    $directValue = $GptTmpl.Sections.GetSection($CurrentSection).KeyValuePair.KeyValues[$CurrentKey]
                    $TempMembers.AddRange($directValue.Split(','))

                    foreach ($ExistingMember in $TempMembers) {

                        Write-Verbose -Message ('Processing existing member: {0}' -f $ExistingMember)

                        $CurrentMember = ConvertTo-AccountName -SID $ExistingMember.TrimStart('*')

                        if (($null -ne $CurrentMember) -and -not
                            $NewMembers.Contains($ExistingMember)) {
                            $NewMembers.Add($ExistingMember)
                        } #end If
                        $CurrentMember = $null
                    } #end Foreach

                    foreach ($item in $Members) {

                        Write-Verbose -Message ('Processing new member: {0}' -f $item)

                        $identity = Test-NameIsWellKnownSid -Name $item

                        if (-not $NewMembers.Contains('*{0}' -f $identity.Value)) {

                            $NewMembers.Add('*{0}' -f $identity.Value)
                        } #end If
                    } #end Foreach

                    $GptTmpl.Sections[$CurrentSection].KeyValuePair[$CurrentKey] = $NewMembers -join ','
                } else {

                    Write-Verbose -Message ('Key [{0}] does not exist. Creating new key...' -f $CurrentKey)

                    foreach ($item in $Members) {

                        Write-Verbose -Message ('Processing new member: {0}' -f $item)

                        $identity = Test-NameIsWellKnownSid -Name $item

                        if ($null -eq $identity) {
                            $identity = ConvertTo-SID -AccountName $item
                        } #end If

                        if (-not $UserSIDs.Contains('*{0}' -f $identity.Value)) {
                            $UserSIDs.Add('*{0}' -f $identity.Value)
                        } #end If
                    } #end Foreach
                    $GptTmpl.Sections[$CurrentSection].KeyValuePair.Add($CurrentKey, $UserSIDs -join ',')
                } #end If-Else

                #Write-Verbose -Message 'Writing changes to GptTmpl...'

                #$GptTmpl.WriteAllText()

                $status = $true
            } #end If
        } catch {
            Write-Error -Message "An error occurred: $_.Exception.Message"
            $status = $false
            throw [System.ApplicationException]::new("Either you are trying to add a group that does not exist, or the identity provided does not correspond to a Group object class: '$_'. Message is $_.Message")
        } finally {
            $status = $true
        } #end Try-Catch-Finally
    } #end Process

    End {
        return $GptTmpl
    } #end End
}
