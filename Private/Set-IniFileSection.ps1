Function Set-IniFileSection {
    <#
        .SYNOPSIS
            Updates or creates a section in an INI file hashtable with specified key and members.

        .DESCRIPTION
            This function takes an INI file hashtable, a section, a key, and an array of members. It updates the
            INI file hashtable with the provided section, key, and members.
            If the section or key does not exist, it creates them.
            The function supports verbose output and can be run with WhatIf and Confirm parameters for safety.

        .PARAMETER IniData
            Hashtable containing the values from the INI file.

        .PARAMETER Section
            String representing the section to configure/change in the INI file.

        .PARAMETER Key
            String representing the key to configure/change in the INI file.

        .PARAMETER Members
            ArrayList of members to be configured as a value for the key.

        .EXAMPLE
            $iniData = @{}
            Set-IniFileSection -IniData $iniData -Section "Settings" -Key "Admins" -Members @("User1", "User2")

        .INPUTS
            System.Collections.Hashtable, System.String[], System.String

        .OUTPUTS
            System.Collections.Hashtable
    #>

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

        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $NewMembers = [System.Collections.Generic.List[object]]::New()
        $TempMembers = [System.Collections.Generic.List[object]]::New()


        ##############################
        # Helper Function: Resolve-MemberIdentity
        function Resolve-MemberIdentity {
            Param (
                [Parameter(Mandatory = $true)]
                [string]
                $Member
            )

            # Empty string might be valid.
            # Check for it and return it accordingly
            if ($Member -eq [string]::Empty) {
                return [string]::Empty
            } #end If

            # Ensure no leading asterisk
            $Member = $Member.TrimStart('*')

            # return the value accordingly
            if ($Variables.WellKnownSIDs[$Member]) {
                # Check for WellKnownSids
                return ([System.Security.Principal.SecurityIdentifier]::New($Member)).value
            } else {
                # Translate to corresponding SID
                try {
                    $principal = [System.Security.Principal.NTAccount]::New($Member)
                    return $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch {
                    Write-Error -Message ('Error resolving member identity: {0}' -f $_)
                    throw
                } #end Try-Catch
            } #end If-Else
        } #end Function Resolve-MemberIdentity

    } #end Begin

    Process {
        # Block: Ensure Section Exists
        If (-not $IniData.Contains($Section)) {
            Write-Verbose -Message ('Section "{0}" does not exist. Creating it!.' -f $Section)
            $IniData.add($Section, [ordered]@{})
        } #end If



        # Block: Process Existing Members
        if ($IniData[$Section].Contains($Key)) {
            Write-Verbose -Message ('Key "{0}" found. Getting existing values.' -f $Key)
            $TempMembers = ($IniData[$Section][$Key]).Split(',')

            # iterate all existing members (From GptTmpl.inf)
            foreach ($ExistingMember in $TempMembers) {
                try {
                    # Resolve current member
                    $CurrentMember = Resolve-MemberIdentity -Member $ExistingMember.TrimStart('*')

                    if ($null -ne $CurrentMember -and -not $NewMembers.Contains($CurrentMember)) {
                        # Add member to list
                        $NewMembers.Add('*{0}' -f $ExistingMember)
                    }
                } catch {
                    Write-Error -Message ('Error when trying to translate to SID. {0}' -f $_)
                    throw
                } #end Try-Catch
            } #end Foreach
        } #end If



        # Block: Add New Members. Iterate all $Members
        foreach ($item in $Members) {
            try {
                # Resolve current member
                $identity = Resolve-MemberIdentity -Member $item

                if (-not $NewMembers.Contains('*{0}' -f $identity)) {
                    # Add member to list
                    $NewMembers.Add('*{0}' -f $identity)
                }
            } catch {
                Write-Error -Message ('Error processing member {0}: {1}' -f $item, $_)
                throw
            } #end Try-Catch
        } #end Foreach



        # Block: Update INI Data
        $Splat = @{
            InputObject = $IniData
            Key         = $Key
            Value       = ($NewMembers -join ',')
            Sections    = $Section
        }
        Set-IniContent @Splat

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Privileged Rights."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        Write-Output $IniData
    } #end END
}
