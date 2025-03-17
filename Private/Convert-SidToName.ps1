Function Convert-SidToName {
    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to its corresponding Account Name.

        .DESCRIPTION
            This function translates a given Security Identifier (SID) to the corresponding NT Account Name
            using .NET classes. It accepts both string representations of SIDs and SID objects.
            It first checks against a comprehensive list of Well-Known SIDs before attempting dynamic resolution.
            The function is optimized for performance in large Active Directory environments.

        .PARAMETER SID
            The Security Identifier (SID) to convert. Can be either a string representation of a SID
            or a System.Security.Principal.SecurityIdentifier object.

        .EXAMPLE
            Convert-SidToName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'
            EguibarIT\davade

            Converts the specified SID string to its corresponding NT Account Name.

        .EXAMPLE
            Get-ADUser -Identity davade | Select-Object SID | Convert-SidToAccountName

            Retrieves the SID for user davade and converts it to the corresponding NT Account Name.

        .EXAMPLE
            "S-1-5-32-544" | Convert-SidToAccountName

            Converts the Well-Known SID for the Administrators group to "BUILTIN\Administrators".

        .EXAMPLE
            $SidObj = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
            Convert-SidToAccountName -SID $SidObj

            Creates a SecurityIdentifier object for the Local System account and converts it to "NT AUTHORITY\SYSTEM".

        .OUTPUTS
             System.Security.Principal.NTAccount

        .NOTES
            Required modules/prerequisites:
            - Windows PowerShell 5.1 or PowerShell 7+
            - Active Directory module (for AD-related operations)

            Used Functions:
                Name                                         ║ Module/Namespace
                ═════════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                                ║ Microsoft.PowerShell.Utility
                Write-Warning                                ║ Microsoft.PowerShell.Utility
                Write-Error                                  ║ Microsoft.PowerShell.Utility
                System.Security.Principal.NTAccount          ║ .NET Framework
                System.Security.Principal.SecurityIdentifier ║ .NET Framework

            Version:         1.4
            DateModified:    13/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .LINK
            https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.securityidentifier.translate

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Convert-SidToName.ps1
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Security.Principal.NTAccount])]

    param (
        # PARAM1 STRING representing the GUID
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Enter a Security Identifier (SID) string or object to convert to an account name.',
            Position = 0)]
        [Alias('SecurityIdentifier')]
        [ValidateScript(
            { Test-IsValidSID -ObjectSID $_ },
            ErrorMessage = '[PARAMETER] Provided SID is not valid! Function will not continue. Please check.'
        )]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    Begin {

        Set-StrictMode -Version Latest

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

        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier = $null
        [System.Security.Principal.NTAccount]$NTAccount = $null
        [System.Collections.Hashtable]$Cache = @{}

    } #end Begin

    Process {

        Write-Verbose -Message ('Attempting to convert SID: {0} to account name' -f $PSBoundParameters['SID'])

        try {
            # First, validate if input is a valid SID
            [bool]$isValid = $false

            # Check if it's a SecurityIdentifier object
            if ($SID -is [System.Security.Principal.SecurityIdentifier]) {

                $SecurityIdentifier = $SID
                $isValid = $true
                Write-Verbose -Message 'Input is already a SecurityIdentifier object'

            } elseif ($SID.PSObject.Properties.Name -contains 'SID' -and
                  ($SID.SID -is [System.Security.Principal.SecurityIdentifier] -or
                   ($SID.SID -is [string] -and
                   ((Test-IsValidSID -ObjectSID $SID.SID) -or
                $Variables.WellKnownSIDs.Contains($SID.SID))))) {
                # Check if it's a pipeline object with SID property

                if ($SID.SID -is [System.Security.Principal.SecurityIdentifier]) {

                    $SecurityIdentifier = $SID.SID
                    $isValid = $true
                    Write-Verbose -Message 'Extracted SecurityIdentifier from input object property'

                } else {

                    if ($Variables.WellKnownSIDs.Contains($SID.SID)) {

                        $isValid = $true
                        Write-Verbose -Message 'SID from property is a Well-Known SID'

                    } elseif (Test-IsValidSID -ObjectSID $SID.SID) {

                        $isValid = $true
                        Write-Verbose -Message 'SID from property matches valid SID pattern'

                    } #end If-ElseIf

                    $SID = $SID.SID  # Continue processing with the string SID
                } #end If-ElseIf

            } elseif ($SID -is [string]) {
                # Check if it's a string SID

                if ($Variables.WellKnownSIDs.Contains($SID)) {

                    $isValid = $true
                    Write-Verbose -Message 'Input is a Well-Known SID string'

                } elseif (Test-IsValidSID -ObjectSID $SID) {

                    $isValid = $true
                    Write-Verbose -Message 'Input matches valid SID pattern'

                } #end If-ElseIf
            } #end If-ElseIf

            if (-not $isValid) {

                Write-Error -Message ('Invalid SID format: {0}' -f $SID)
                return

            } #end If

            # Check cache first
            if ($Cache.Contains($SID)) {

                Write-Verbose -Message ('SID found in cache: {0}' -f $SID)
                $NTAccount = $Cache[$SID]

            } else {

                # Proceed with conversion based on validation result
                # First check if it's a Well-Known SID in our hashtable
                if ($Variables.WellKnownSIDs.Contains($SID)) {

                    Write-Verbose -Message ('Resolving Well-Known SID: {0} from predefined list' -f $SID)
                    $NTAccount = $Variables.WellKnownSIDs[$SID]

                } else {

                    # If it's not a well-known SID, proceed with translation
                    if ($SID -is [string] -and -not $SecurityIdentifier) {

                        Write-Verbose -Message ('Converting string SID to SecurityIdentifier object: {0}' -f $SID)
                        $SecurityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($SID)

                    } #end If

                    # Translate SID to NTAccount if ShouldProcess passes
                    $ShouldProcessMessage = 'Translate SID {0} to NT Account Name' -f $SecurityIdentifier
                    if ($PSCmdlet.ShouldProcess($SecurityIdentifier, $ShouldProcessMessage)) {

                        Write-Verbose -Message 'Translating SID to NTAccount'
                        $NTAccount = $SecurityIdentifier.Translate([System.Security.Principal.NTAccount])

                    }
                }
                # Cache the result
                $Cache[$SID] = $NTAccount
                Write-Verbose -Message ('Successfully translated to: {0}' -f $NTAccount)
            } #end If-Else

            $NTAccount

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Error -Message ('Identity Not Mapped Exception. The SID could not be translated to an account name: {0}' -f $SID)

        } catch [System.ArgumentException] {

            Write-Error -Message ('Invalid SID format: {0}' -f $SID)

        } catch {

            Write-Error -Message ('An unexpected error occurred while converting SID {0}: {1}"' -f $SID, $_)

        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'translating SID to Name (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
}
