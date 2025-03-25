Function Set-AdInheritance {
    <#
        .SYNOPSIS
            Sets or clears inheritance settings on Active Directory objects.

        .DESCRIPTION
            This function modifies the inheritance settings of Active Directory objects. It can:
            - Enable or disable inheritance
            - Copy or remove inherited permissions when disabling inheritance
            - Process single objects or multiple objects via pipeline
            - Supports -WhatIf and -Confirm for safe execution

            The function is idempotent and will maintain the desired state even when run multiple times.

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object to modify.
            This parameter accepts pipeline input and must be a valid DN format.

        .PARAMETER RemoveInheritance
            Boolean parameter that controls the inheritance checkbox:
            - True: Removes inheritance (unchecks the box)
            - False: Enables inheritance (checks the box)

        .PARAMETER RemovePermissions
            Boolean parameter that determines what happens to inherited permissions when inheritance is disabled:
            - True: Copies the inherited permissions to explicit permissions
            - False: Removes the inherited permissions
            Only takes effect when RemoveInheritance is True.

        .EXAMPLE
            Set-AdInheritance -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveInheritance $true -RemovePermissions $false

            Disables inheritance on the specified OU and removes inherited permissions.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Set-AdInheritance -RemoveInheritance $true -RemovePermissions $true

            Disables inheritance on all OUs in the domain, copying inherited permissions to explicit permissions.

        .EXAMPLE
            Set-AdInheritance "OU=HR,DC=EguibarIT,DC=local" $false $false -WhatIf

            Shows what would happen if inheritance was enabled on the HR OU.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Test-IsValidDN                       ║ EguibarIT.DelegationPS
                Get-Acl                              ║ Microsoft.PowerShell.Security
                Set-Acl                              ║ Microsoft.PowerShell.Security
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Set-AdInheritance.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows/win32/secauthz/inheritance-of-access-control-entries

        .COMPONENT
            ActiveDirectory

        .ROLE
            Security Administration
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The Delegated Group Name',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM2 Bool for the IsProtected parameter
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present inheritance of object will be removed.',
            Position = 1)]
        [bool]
        $RemoveInheritance,

        # PARAM3 Bool for the preserveInheritance parameter
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present the permissions from the parent object are copied to the object.',
            Position = 2)]
        [bool]
        $RemovePermissions
    )

    Begin {

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

        # Store original location to restore later
        $originalLocation = Get-Location

        Set-Location -Path 'AD:\'
    }

    Process {
        try {
            $acl = Get-Acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPPath'])

            $action = if ($RemoveInheritance) {
                'Disable inheritance and {0} inherited permissions' -f $(if ($RemovePermissions) {
                        'copy'
                    } else {
                        'remove'
                    })
            } else {
                'Enable inheritance'
            } #end if-else

            if ($PSCmdlet.ShouldProcess($LDAPpath, $action)) {
                # First value will set/Remove the inheritance Check-Box
                #     set the value of the IsProtected parameter (1) to TRUE, the inheritance checkbox will be cleared.
                #     If we set it to FALSE, the checkbox will become checked
                # Second value will "copy" (true)  or "remove" (false) the permissions
                #     The "preserveInheritance" parameter (2) only has an effect when we uncheck the inheritance checkbox  (IsProtected = TRUE).
                #     If we set preserveInheritance to TRUE then the permissions from the parent object are copied to the object.
                #     It has the same effect as clicking "Add".
                #     If "preserverInheritance" is set to FALSE, it has the same effect as clicking �Remove�
                $acl.SetAccessRuleProtection($PSBoundParameters['RemoveInheritance'], $PSBoundParameters['RemovePermissions'])


                Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPPath'])

                Write-Verbose -Message ('Successfully modified inheritance settings on {0}' -f $LDAPpath)

            } #end If

        } catch {

            Write-Error -Message ('Failed to modify inheritance settings on {0}: {1}' -f $LDAPpath, $_.Exception.Message)

        } #end try-catch

    } #end Process

    End {
        # Restore original location
        Set-Location -Path $originalLocation

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'setting Inheritance and permissions.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end END
} #end Function Set-AdInheritance
