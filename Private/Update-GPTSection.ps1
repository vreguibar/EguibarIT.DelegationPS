function Update-GPTSection {
    <#
        .SYNOPSIS
            Updates an existing section and key in the GPT template file.

        .DESCRIPTION
            This function updates the values of an existing key in a specific section of a GPT template file.
            It handles duplicates and ensures all members are correctly resolved.

        .PARAMETER Section
            The section of the template being updated (e.g., "[Privilege Rights]" or "[Registry Values]").

        .PARAMETER Key
            The key within the section being updated (e.g., "SeAuditPrivilege" or "SeBatchLogonRight").

        .PARAMETER Members
            The array of members to be added. Can be empty or null.

        .PARAMETER GptTmpl
            The GPT template object of type [IniFileHandler.IniFile].

        .OUTPUTS
            [IniFileHandler.IniFile]

        .EXAMPLE
            $gptTmpl = Get-GptTemplateObject -Path "C:\path\to\GptTmpl.inf"
            $updatedGptTmpl = Update-GPTSection -Section "Privilege Rights" -Key "SeAuditPrivilege" -Members "Administrator", "SYSTEM" -GptTmpl $gptTmpl

        .NOTES
            Ensure that the IniFileHandler module is imported before using this function.
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


        $newMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {

        try {

            # Check if the section exists
            if (-not $GptTmpl.Sections.ContainsKey($Section)) {
                throw ('Section {0} not found in the GPT template.' -f $Section)
            }

            # Check if the key exists in the section
            if (-not $GptTmpl.GetKeyValue($Section, $Key)) {
                throw ('Key {0} not found in section {1}.' -f $Key, $Section)
            }

            Write-Verbose -Message ('Updating key [{0}] in section [{1}].' -f $Key, $Section)

            # Process existing members
            $existingMembers = $GptTmpl.GetKeyValue($Section, $Key).TrimEnd(',').Split(',', [StringSplitOptions]::RemoveEmptyEntries)
            foreach ($existingMember in $existingMembers) {
                $resolvedSID = ConvertTo-AccountName -SID $existingMember.TrimStart('*')
                if ($resolvedSID) {
                    [void]$newMembers.Add($existingMember)
                }
            }

            # Process new members
            foreach ($member in $Members) {
                if (-not [string]::IsNullOrWhiteSpace($member)) {
                    $sid = Resolve-MemberIdentity -Member $member
                    if ($sid) {
                        [void]$newMembers.Add("*$sid")
                    } else {
                        Write-Warning "Unable to resolve member: $member"
                    }
                }
            }

            # Update the GPT template
            $updatedValue = ($newMembers | Sort-Object) -join ','
            $GptTmpl.SetKeyValue($Section, $Key, $updatedValue)

            Write-Verbose -Message ('Successfully updated key {0} in section {1}.' -f $Key, $Section)


        } catch {
            Write-Error -Message ('Failed to update key [{0}] in section [{1}]: {2}' -f $Key, $Section, $_)
        }
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'updating GptTmpl object section (Private Function).'
        )
        Write-Verbose -Message $txt

        return $GptTmpl
    } #end End

} #end Update-GPTSection
