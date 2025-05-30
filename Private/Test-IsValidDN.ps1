﻿function Test-IsValidDN {
    <#
        .SYNOPSIS
            Validates if the input string is a valid distinguished name (DN).

        .DESCRIPTION
            This function checks if the provided input string adheres to the structure of a valid
            distinguished name (DN) in Active Directory. It uses regex pattern matching to validate
            the DN structure without making actual AD queries.

            The function is idempotent and can process multiple DNs through pipeline input efficiently.
            It returns a boolean value indicating whether the input string is a valid DN.

        .PARAMETER ObjectDN
            The distinguished name to validate. This parameter accepts a string representing the
            DN of an Active Directory object. Multiple DNs can be processed through pipeline input.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'CN=Darth Vader,OU=Users,DC=EguibarIT,DC=local'

            Returns $true as this is a valid DN format.

        .EXAMPLE
            'CN=Test User,DC=domain,DC=com', 'Invalid DN' | Test-IsValidDN

            Processes multiple DNs through pipeline, returning boolean results for each.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'Invalid DN' -Verbose

            Returns $false and shows verbose output about the validation process.

        .INPUTS
            System.String
            You can pipe string values representing distinguished names to this function.

        .OUTPUTS
            System.Boolean
            Returns True if the provided string is a valid distinguished name, otherwise False.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .LINK
            https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            AD Object Management, Validation
    #>

    [CmdletBinding(ConfirmImpact = 'Low',
        SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished Name string to validate',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [string]
        $ObjectDN
    )

    Begin {

        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        # Initialize a boolean variable to store validation result
        [bool]$isValid = $false

        Write-Debug -Message 'Begin block: Regex pattern for DN validation initialized.'

    } #end Begin

    Process {

        Try {

            # Perform the actual validation
            $isValid = $ObjectDN -match $Constants.DnRegEx

            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                Write-Verbose -Message ('DistinguishedName validation result: {0}' -f $isValid)
            } #end If

        } catch {

            # Handle any exceptions gracefully
            Write-Error -Message ('Error validating DN: {0}. Error: {1}' -f $ObjectDN, $_.Exception.Message)
            $isValid = $false

        } #end Try-Catch

    } #end Process

    end {
        return $isValid
    } #end End
} #end Function Test-IsValidDN
