Function Convert-SidToName {
    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to its corresponding NT Account Name.

        .DESCRIPTION
            This function translates a given Security Identifier (SID) to the corresponding NT Account Name
            using .NET Framework classes. It accepts both string representations of SIDs and SID objects.

            The function first checks against a comprehensive list of Well-Known SIDs before attempting
            dynamic resolution through the Windows API. It implements caching to optimize performance in large
            Active Directory environments where the same SIDs may be repeatedly resolved.

            For improved security and reliability, the function performs thorough validation of input SIDs
            before processing and handles various error conditions that might occur during translation.

            The function supports pipeline input, making it suitable for batch processing of SIDs.

        .PARAMETER SID
            The Security Identifier (SID) to convert. This parameter accepts:
            - String representation of a SID (e.g., "S-1-5-32-544")
            - System.Security.Principal.SecurityIdentifier object
            - Any object with a SID property containing either of the above

            This parameter supports pipeline input by value and by property name.

        .EXAMPLE
            Convert-SidToName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'

            # Output: EguibarIT\davade

            Converts the specified domain SID string to its corresponding NT Account Name.

        .EXAMPLE
            Get-ADUser -Identity davade | Select-Object SID | Convert-SidToName

            Retrieves the SID for user davade from Active Directory and converts it to the corresponding NT Account Name.

        .EXAMPLE
            "S-1-5-32-544" | Convert-SidToName

            # Output: BUILTIN\Administrators

            Converts the Well-Known SID for the Administrators group using pipeline input.

        .EXAMPLE
            $SidObj = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
            Convert-SidToName -SID $SidObj

            # Output: NT AUTHORITY\SYSTEM

            Creates a SecurityIdentifier object for the Local System account and converts it to the NT account name.

        .OUTPUTS
            System.Security.Principal.NTAccount

            Returns an NTAccount object representing the account name corresponding to the provided SID.
            The string representation follows the format "DOMAIN\Username" or "BUILTIN\GroupName".

        .NOTES
            Required modules/prerequisites:
            - Windows PowerShell 5.1 or PowerShell 7+
            - .NET Framework Security Principal classes

            Performance considerations:
            - The function implements caching to improve performance with repeated SID lookups
            - Well-Known SIDs are resolved using a predefined lookup table without API calls

            Error handling:
            - Returns detailed error messages for invalid SIDs
            - Handles IdentityNotMappedException for SIDs that cannot be resolved

            Used Functions:
                Name                                         ║ Module/Namespace
                ═════════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                                ║ Microsoft.PowerShell.Utility
                Write-Warning                                ║ Microsoft.PowerShell.Utility
                Write-Error                                  ║ Microsoft.PowerShell.Utility
                Test-IsValidSID                              ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                          ║ EguibarIT.DelegationPS
                System.Security.Principal.NTAccount          ║ .NET Framework
                System.Security.Principal.SecurityIdentifier ║ .NET Framework

            Version:         1.5
            DateModified:    14/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.securityidentifier.translate
            https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Convert-SidToName.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Identity Management

        .FUNCTIONALITY
            SID translation, Security principal resolution, Identity management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Security.Principal.NTAccount])]

    param (
        # Security Identifier to convert to an account name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Enter a Security Identifier (SID) string or object to convert to an account name.',
            Position = 0)]
        [Alias('SecurityIdentifier', 'Identity')]
        [ValidateScript(
            { Test-IsValidSID -ObjectSID $_ },
            ErrorMessage = '[PARAMETER] Provided SID is not valid! Function will not continue. Please check.'
        )]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    Begin {
        # Set strict mode to catch potential issues
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

        # Initialize variables for SID and account objects
        [System.Security.Principal.SecurityIdentifier]$SecurityIdentifier = $null
        [System.Security.Principal.NTAccount]$NTAccount = $null

        # Create a cache hashtable to optimize performance with repeated lookups
        [System.Collections.Hashtable]$Cache = @{}

        # Define pattern to identify privilege right keys
        $privilegeRightPattern = '^Se[A-Z][a-zA-Z]+Privilege$'

        Write-Debug -Message 'Function initialized and ready to process SIDs'

    } #end Begin

    Process {
        # Log the input SID for debugging purposes
        Write-Debug -Message ('Attempting to convert SID: {0} to account name' -f $PSBoundParameters['SID'])

        try {
            # Check if input is a privilege right key
            if ($SID -is [string] -and $SID -match $privilegeRightPattern) {

                Write-Debug -Message ('Skipping privilege right key: {0}' -f $SID)
                return $null

            } #end If

            # Initialize validation flag
            [bool]$isValid = $false

            # VALIDATION PHASE: Determine the type of input and validate accordingly

            # Case 1: Input is already a SecurityIdentifier object
            if ($SID -is [System.Security.Principal.SecurityIdentifier]) {

                $SecurityIdentifier = $SID
                $isValid = $true
                Write-Verbose -Message 'Input is already a SecurityIdentifier object'

            } elseif ($SID.PSObject.Properties.Name -contains 'SID' -and
                    ($SID.SID -is [System.Security.Principal.SecurityIdentifier] -or
                    ($SID.SID -is [string] -and
                    ((Test-IsValidSID -ObjectSID $SID.SID) -or
                $Variables.WellKnownSIDs.Contains($SID.SID))))) {

                # If the SID property contains a SecurityIdentifier object
                if ($SID.SID -is [System.Security.Principal.SecurityIdentifier]) {

                    $SecurityIdentifier = $SID.SID
                    $isValid = $true
                    Write-Verbose -Message 'Extracted SecurityIdentifier from input object property'

                } else {
                    # If the SID property contains a string SID
                    if ($Variables.WellKnownSIDs.Contains($SID.SID)) {

                        $isValid = $true
                        Write-Verbose -Message 'SID from property is a Well-Known SID'

                    } elseif (Test-IsValidSID -ObjectSID $SID.SID) {

                        $isValid = $true
                        Write-Verbose -Message 'SID from property matches valid SID pattern'

                    } #end If-ElseIf

                    # Continue processing with the string SID extracted from the property
                    $SID = $SID.SID
                } #end If-Else
            } elseif ($SID -is [string]) {

                # Check against Well-Known SIDs list
                if ($Variables.WellKnownSIDs.Contains($SID)) {

                    $isValid = $true
                    Write-Verbose -Message 'Input is a Well-Known SID string'

                } elseif (Test-IsValidSID -ObjectSID $SID) {

                    $isValid = $true
                    Write-Verbose -Message 'Input matches valid SID pattern'

                } #end If-ElseIf

            } #end If-ElseIf

            # If validation failed, exit with error
            if (-not $isValid) {

                Write-Error -Message ('Invalid SID format: {0}' -f $SID)
                return

            } #end If

            # RESOLUTION PHASE: Convert the validated SID to account name

            # Check cache first for performance optimization
            if ($Cache.Contains($SID)) {

                Write-Verbose -Message ('SID found in cache: {0}' -f $SID)
                $NTAccount = $Cache[$SID]

            } else {
                # Not in cache, perform resolution

                # Special handling for Well-Known SIDs
                if ($Variables.WellKnownSIDs.Contains($SID)) {

                    Write-Verbose -Message ('Resolving Well-Known SID: {0} from predefined list' -f $SID)
                    $NTAccount = $Variables.WellKnownSIDs[$SID]

                } else {

                    # Convert string SID to SecurityIdentifier object if needed
                    if ($SID -is [string] -and -not $SecurityIdentifier) {

                        Write-Verbose -Message ('Converting string SID to SecurityIdentifier object: {0}' -f $SID)
                        $SecurityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($SID)

                    } #end If

                    # Use ShouldProcess for verbose output and potential -WhatIf support
                    $ShouldProcessMessage = 'Translate SID {0} to NT Account Name' -f $SecurityIdentifier
                    if ($PSCmdlet.ShouldProcess($SecurityIdentifier, $ShouldProcessMessage)) {

                        Write-Verbose -Message 'Translating SID to NTAccount using .NET Framework'
                        $NTAccount = $SecurityIdentifier.Translate([System.Security.Principal.NTAccount])

                    } #end If

                } #end If-Else

                # Store result in cache for future lookups
                $Cache[$SID] = $NTAccount
                Write-Verbose -Message ('Successfully translated to: {0}' -f $NTAccount)

            } #end If-Else

            # Return the NT Account name to the pipeline
            return $NTAccount

        }
        # ERROR HANDLING PHASE: Handle specific exception types
        catch [System.Security.Principal.IdentityNotMappedException] {

            # This occurs when the SID cannot be mapped to an account name
            Write-Error -Message ('
                Identity Not Mapped Exception.
                The SID could not be translated to an account name: {0}' -f $SID
            )

        } catch [System.ArgumentException] {

            # This occurs when the SID format is invalid
            Write-Error -Message ('Invalid SID format: {0}' -f $SID) -Category InvalidArgument

        } catch {
            # Catch-all for unexpected errors
            Write-Error -Message (
                'An unexpected error occurred while converting SID {0}: {1}' -f
                $SID, $_.Exception.Message
            ) -Category NotSpecified

        } #end Try-Catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'translating SID to Name (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

        # Clear cache and sensitive data from memory for better resource management
        $Cache = $null
        $SecurityIdentifier = $null

        Write-Verbose -Message 'SID to Name conversion completed'
    } #end End
} #end Function Convert-SidToName
