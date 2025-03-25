Function Remove-PrintOperator {
    <#
        .SYNOPSIS
            Removes Print Operators built-in group permissions from specified Active Directory objects.

        .DESCRIPTION
            This function removes all permissions associated with the Print Operators built-in group from
            specified Active Directory objects. It supports both single object and pipeline input for bulk operations.

            The function:
            - Removes CreateChild and DeleteChild rights for printQueue objects
            - Uses LDAP filters for efficient querying
            - Implements proper error handling for large-scale environments
            - Is idempotent - running it multiple times produces the same result

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object or container from which Print Operators
            permissions will be removed. This parameter accepts pipeline input and must be a valid DN format.

        .PARAMETER Force
            Suppresses the confirmation prompt before removing permissions. Use with caution in production
            environments.

        .EXAMPLE
            Remove-PrintOperator -LDAPPath "OU=Printers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Removes Print Operators permissions from a single OU.
            Prompts for confirmation before making changes.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Remove-PrintOperator -Force

            Removes Print Operators permissions from all OUs in the domain.
            The -Force parameter suppresses confirmation prompts.

        .EXAMPLE
            "OU=Printers,DC=EguibarIT,DC=local" | Remove-PrintOperator -WhatIf

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
                Get-AttributeSchemaHashTable         ║ EguibarIT.DelegationPS
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.3
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Remove-PrintOperator.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-printoperators

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

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Force the operation without confirmation.'
        )]
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


        # Get 'Print Operators' group by SID
        $PrintOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-550' }


        try {
            # Get 'Print Operators' group by SID using LDAP filter for efficiency
            $PrintOperators = Get-ADGroup -LDAPFilter '(objectSID=S-1-5-32-550)' -ErrorAction Stop

            if (-not $PrintOperators) {
                throw 'Print Operators group not found'
            } #end If

            # Initialize GuidMap if empty
            if (-not $Variables.GuidMap -or $Variables.GuidMap.Count -eq 0) {

                Write-Debug -Message 'Initializing attribute schema hash table...'
                Get-AttributeSchemaHashTable

            } #end If

        } catch {

            Write-Error -Message ('Initialization failed: {0}' -f $_.Exception.Message)
            return

        } #end Try-Catch

    } #end Begin

    process {

        try {
            <#
                ACENumber              : 1
                IdentityReference      : BUILTIN\Print Operators
                ActiveDirectoryRights : CreateChild, DeleteChild
                AccessControlType      : Allow
                ObjectType             : printQueue [ClassSchema]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                    = $PrintOperators
                LDAPPath              = $PSBoundParameters['LDAPPath']
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['printQueue']
                AdSecurityInheritance = 'None'
                RemoveRule            = $true
            }
            If ($Force -or
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Print Operators" permissions?')) {

                Set-AclConstructor5 @Splat

            } #end If
        } catch {

            Write-Error -Message ('Failed to remove Print Operators permissions from {0}: {1}' -f $LDAPpath, $_.Exception.Message)

        } #end Try-Catch

    } #end Process

    end {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'removing Print Operators.'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END
} #end Function Remove-PrintOperator
