# Remove AUTHENTICATED USERS ('S-1-5-11') Built-In Group from object
Function Remove-AuthUser {
    <#
        .SYNOPSIS
            Removes Authenticated Users built-in group permissions from specified Active Directory objects.

        .DESCRIPTION
            This function removes all permissions associated with the Authenticated Users built-in group from
            specified Active Directory objects. It supports both single object and pipeline input for bulk operations.

            The function uses LDAP filters for efficient querying and implements proper error handling for
            large-scale environments. It's designed to be idempotent - running it multiple times on the same
            object produces the same result.

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object or container from which Authenticated Users
            permissions will be removed. This parameter accepts pipeline input for bulk operations.

            This parameter is validated to ensure it's a valid Distinguished Name format.

        .PARAMETER Force
            Suppresses the confirmation prompt before removing permissions. Use with caution in production
            environments.

        .EXAMPLE
            Remove-AuthUser -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Removes Authenticated Users permissions from a single Organizational Unit.
            Prompts for confirmation before making changes.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Remove-AuthUser -Force

            Removes Authenticated Users permissions from all Organizational Units in the domain.
            The -Force parameter suppresses confirmation prompts.

        .OUTPUTS
            [void]
            This function does not generate any output. Use -Verbose for detailed progress information.

        .NOTES
            Used Functions:
                Name                                  ║ Module
                ══════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                   ║ EguibarIT.DelegationPS
                Get-ADGroup                           ║ ActiveDirectory
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
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Remove-AuthUser.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understanding-security-principals#authenticated-users

        .COMPONENT
            ActiveDirectory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Active Directory Permission Management
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

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Force the operation without confirmation.'
        )]
        [switch]
        $Force
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
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        try {
            # Get 'Authenticated Users' group by SID using LDAP filter for efficiency
            $AuthenticatedUsers = Get-ADGroup -LDAPFilter '(objectSID=S-1-5-11)' -ErrorAction Stop

            if (-not $AuthenticatedUsers) {

                throw 'Authenticated Users group not found'

            } #end If

        } catch {

            Write-Error -Message ('Failed to get Authenticated Users group: {0}' -f $_.Exception.Message)
            return

        } #end Try-Catch

    } #end Begin

    Process {
        $Splat = @{
            Id                    = $AuthenticatedUsers
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }

        try {

            If ($Force -or
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "AUTHENTICATED USERS" permissions?')) {

                Set-AclConstructor5 @Splat

            } #end If

        } catch {

            Write-Error -Message ('
                Failed to remove Authenticated Users permissions from {0}: {1}' -f $LDAPpath, $_.Exception.Message
            )

        } #end Process
    } #end Process

    End {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'removing AUTHENTICATED USERS.'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END

} #end function Remove-AuthUser
