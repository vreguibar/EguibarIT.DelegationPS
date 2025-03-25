Function Remove-PreWin2000 {
    <#
        .SYNOPSIS
            Removes Pre-Windows 2000 Compatible Access built-in group permissions from specified Active Directory objects.

        .DESCRIPTION
            This function removes all permissions associated with the Pre-Windows 2000 Compatible Access built-in group
            from specified Active Directory objects. It supports both single object and pipeline input for bulk operations.

            The function uses LDAP filters for efficient querying and implements proper error handling for
            large-scale environments. It's designed to be idempotent - running it multiple times on the same
            object produces the same result.

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object or container from which Pre-Windows 2000 Compatible Access
            permissions will be removed. This parameter accepts pipeline input and must be a valid DN format.

        .PARAMETER Force
            Suppresses the confirmation prompt before removing permissions. Use with caution in production environments.

        .EXAMPLE
            Remove-PreWin2000 -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Removes Pre-Windows 2000 Compatible Access permissions from a single Organizational Unit.
            Prompts for confirmation before making changes.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Remove-PreWin2000 -Force

            Removes Pre-Windows 2000 Compatible Access permissions from all OUs in the domain.
            The -Force parameter suppresses confirmation prompts.

        .EXAMPLE
            "OU=HR,DC=EguibarIT,DC=local" | Remove-PreWin2000 -WhatIf

            Shows what changes would be made without actually making them.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                  ║ EguibarIT.DelegationPS
                Get-ADGroup                          ║ ActiveDirectory
                Test-IsValidDN                       ║ EguibarIT.DelegationPS
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
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Remove-PreWin2000.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understanding-security-groups#bkmk-prewindows

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
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Force the operation without confirmation.')]
        [switch]
        $Force
    )

    begin {

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
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        try {
            # Get 'Pre-Windows 2000 Compatible Access' group by SID using LDAP filter for efficiency
            $PreWin2000 = Get-ADGroup -LDAPFilter '(objectSID=S-1-5-32-554)' -ErrorAction Stop

            if (-not $PreWin2000) {
                throw 'Pre-Windows 2000 Compatible Access group not found'
            } #end If

        } catch {

            Write-Error -Message ('Failed to get Pre-Windows 2000 Compatible Access group: {0}' -f $_.Exception.Message)
            return

        } #end Try

    } #end Begin

    process {
        try {
            $Splat = @{
                Id                    = $PreWin2000
                LDAPPath              = $PSBoundParameters['LDAPPath']
                AdRight               = 'GenericAll'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'All'
                RemoveRule            = $true
            }

            If ($Force -or
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access" permissions?')) {

                Set-AclConstructor5 @Splat

                Write-Verbose -Message ('Successfully removed Pre-Windows 2000 Compatible Access permissions from {0}' -f $LDAPpath)

            } #end If

        } catch {

            Write-Error -Message ('Failed to remove permissions from {0}: {1}' -f $LDAPpath, $_.Exception.Message)

        } #end Try

    } #end Process

    end {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'removing Pre-Windows 2000 Compatible Access.'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END
} #end Function Remove-PreWin2000
