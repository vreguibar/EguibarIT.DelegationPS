# Remove Everyone ('S-1-1-0') Built-In Group from object
Function Remove-Everyone {
    <#
        .SYNOPSIS
            Removes Everyone built-in group permissions from specified Active Directory objects.

        .DESCRIPTION
            This function removes all permissions associated with the Everyone built-in group from
            specified Active Directory objects. It supports both single object and pipeline input for bulk operations.

            The function removes the following permissions:
            - ReadProperty
            - WriteProperty
            - GenericExecute

            It's designed to be idempotent - running it multiple times on the same object produces the same result.

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object or container from which Everyone
            permissions will be removed. This parameter accepts pipeline input for bulk operations.

            This parameter is validated to ensure it's a valid Distinguished Name format.

        .PARAMETER Force
            Suppresses the confirmation prompt before removing permissions. Use with caution in production
            environments.

        .EXAMPLE
            Remove-Everyone -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Removes Everyone permissions from a single Organizational Unit.
            Prompts for confirmation before making changes.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Remove-Everyone -Force

            Removes Everyone permissions from all Organizational Units in the domain.
            The -Force parameter suppresses confirmation prompts.

        .OUTPUTS
            [void]
            This function does not generate any output. Use -Verbose for detailed progress information.

        .NOTES
            Used Functions:
                Name                                  ║ Module
                ══════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                   ║ EguibarIT.DelegationPS
                Test-IsValidDN                        ║ EguibarIT.DelegationPS
                Write-Verbose                         ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                   ║ EguibarIT

        .NOTES
            Version:         1.2
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Remove-Everyone.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understanding-security-principals#everyone

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

    } #end Begin

    process {
        try {
            <#
                ACENumber              : 2
                IdentityReference      : Everyone
                ActiveDirectoryRights : ReadProperty, WriteProperty, GenericExecute
                AccessControlType      : Allow
                ObjectType             : GuidNULL
                InheritanceType        : All
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                    = 'EVERYONE'
                LDAPPath              = $PSBoundParameters['LDAPPath']
                AdRight               = 'ReadProperty', 'WriteProperty', 'GenericExecute'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.GuidNULL
                AdSecurityInheritance = 'All'
                RemoveRule            = $true
            }

            # Fix ShouldProcess to use the correct parameter (LDAPPath instead of Group)
            If ($Force -or
                $PSCmdlet.ShouldProcess($PSBoundParameters['LDAPPath'], 'Remove "EVERYONE" permissions?')) {

                # Ensure Constants is available before using it
                if ($null -eq $Constants -or $null -eq $Constants.GuidNULL) {

                    Write-Verbose -Message 'Using null for ObjectType as Constants.GuidNULL is not available'
                    $Splat['ObjectType'] = [System.guid]::New('00000000-0000-0000-0000-000000000000')

                }

                # Call Set-AclConstructor5 and store the result
                try {

                    Set-AclConstructor5 @Splat
                    Write-Verbose -Message ('Successfully removed Everyone permissions from {0}' -f $LDAPpath)

                } catch {

                    Write-Error -Message (
                        'Failed to remove Everyone permissions from {0}: {1}' -f
                        $LDAPpath,
                        $_.Exception.Message
                    )

                }
            } #end If
        } catch {

            Write-Error -Message ('Failed to remove Everyone permissions from {0}: {1}' -f $LDAPpath, $_.Exception.Message)

        } #end Try-catch

    } #end Process

    end {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'removing EVERYONE.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end END
} #end Function Remove-Everyone
