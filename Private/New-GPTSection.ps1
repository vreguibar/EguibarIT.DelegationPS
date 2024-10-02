function New-GPTSection {
    <#
        .SYNOPSIS
            Creates a new section and key in the GPT template file.

        .DESCRIPTION
            This function creates a new section and key in the GPT template, adding the specified members.
            It ensures that only unique members are added to the section and handles SID resolution.

        .PARAMETER Section
            The section to be created in the GPT template file (e.g., "Privilege Rights" or "Registry Values").

        .PARAMETER Key
            The key to be created within the specified section (e.g., "SeAuditPrivilege" or "SeBatchLogonRight").

        .PARAMETER Members
            An array of members to be added to the key. Can be empty or null.

        .PARAMETER GptTmpl
            The GPT template object of type [IniFileHandler.IniFile].

        .OUTPUTS
            [IniFileHandler.IniFile]

        .EXAMPLE
            $gptTmpl = New-Object IniFileHandler.IniFile
            $updatedGptTmpl = New-GPTSection -Section "Privilege Rights" -Key "SeAuditPrivilege" -Members "Administrator", "SYSTEM" -GptTmpl $gptTmpl

        .NOTES
            Ensure that the IniFileHandler module is imported before using this function.
            The function will overwrite existing keys if they already exist in the specified section.
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([IniFileHandler.IniFile])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The section in the GPT template file to be configured (ex. [Privilege Rights] or [Registry Values]).',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Section,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'TheKEY within given section (ex. SeAuditPrivilege or SeBatchLogonRight).',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key,

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

        $userSIDs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {

        try {
            Write-Verbose -Message ('Creating key [{0}] in section [{1}].' -f $Key, $Section)

            # Ensure the section exists
            if (-not $GptTmpl.Sections.ContainsKey($Section)) {
                $GptTmpl.Sections.Add($Section, (New-Object IniFileHandler.IniSection))
                Write-Verbose "Created new section '$Section'."
            }

            # Process members
            foreach ($member in $Members) {

                if (-not [string]::IsNullOrWhiteSpace($member)) {

                    $sid = Resolve-MemberIdentity -Member $member

                    if ($sid) {
                        [void]$userSIDs.Add("*$sid")
                    } else {
                        Write-Warning -Message ('Unable to resolve member: {0}' -f $member)
                    } #end If-Else

                } #end If

            } #end Foreach

            # Create or update the key
            $updatedValue = ($userSIDs | Sort-Object) -join ','
            $GptTmpl.SetKeyValue($Section, $Key, $updatedValue)

            Write-Verbose -Message ('Successfully created/updated key {0} in section {1}.' -f $Key, $Section)

        } catch {
            Write-Error -Message ('Failed to create key [{0}] in section [{1}]: {2}' -f $Key, $Section, $_)
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'creating GptTmpl object section (Private Function).'
        )
        Write-Verbose -Message $txt

        return $GptTmpl
    } #end End
} #end Create-GPTSection
