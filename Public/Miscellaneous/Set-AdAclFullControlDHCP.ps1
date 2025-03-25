Function Set-AdAclFullControlDHCP {
    <#
        .SYNOPSIS
            Set delegation to fully manage Dynamic Host Configuration Protocol (DHCP).

        .DESCRIPTION
            This function configures the configuration container to delegate full DHCP management permissions
            to a specified group. It:

            - Sets GenericAll rights on dHCPClass objects and descendants
            - Configures CreateChild and DeleteChild rights for dHCPClass objects
            - Supports both adding and removing delegations
            - Implements proper error handling and progress tracking
            - Supports -WhatIf and -Confirm for safe execution

        .PARAMETER Group
            The identity of the group receiving the delegation. This should typically be a Domain Local group.
            Accepts pipeline input and can be specified as group name or Distinguished Name.

        .PARAMETER RemoveRule
            If specified, removes the delegated permissions instead of adding them.
            Use with caution as this affects DHCP management capabilities.

        .EXAMPLE
            Set-AdAclFullControlDHCP -Group "SL_DHCPRight"

            Delegates full DHCP management permissions to the specified group.

        .EXAMPLE
            Set-AdAclFullControlDHCP -Group "SL_DHCPRight" -RemoveRule

            Removes DHCP management permissions from the specified group.

        .EXAMPLE
            "SG_DHCPAdmins" | Set-AdAclFullControlDHCP -WhatIf

            Shows what changes would be made without actually making them.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                  ║ EguibarIT.DelegationPS
                Set-AclConstructor6                  ║ EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable         ║ EguibarIT.DelegationPS
                Get-AdObjectType                     ║ EguibarIT.DelegationPS
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
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Set-AdAclFullControlDHCP.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps

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

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
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
            Write-Debug -Message 'Initializing attribute schema hash table...'
            Get-AttributeSchemaHashTable

            # Verify Group exists
            $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

            if (-not $CurrentGroup) {
                throw ('Group {0} not found or not accessible' -f $PSBoundParameters['Group'])
            } #end If

        } catch {

            Write-Error -Message ('Initialization failed: {0}' -f $_.Exception.Message)
            return

        } #end Try-Catch

    } #end Begin

    Process {

        $operation = $RemoveRule ? 'Remove' : 'Add'

        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\xxx
            ActiveDirectoryRights : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : dHCPClass [ClassSchema]
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=NetServices,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.GuidNULL
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['dHCPClass']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            # Add the parameter to remove the rule
            $Splat.Add('RemoveRule', $true)

        } #end If

        if ($PSCmdlet.ShouldProcess($Group, ('{0} GenericAll permissions on DHCP objects' -f $operation))) {

            Set-AclConstructor6 @Splat

        } #end If

        <#
            ACENumber              : 2
            IdentityReference      : EguibarIT\xxx
            ActiveDirectoryRights : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : dHCPClass [ClassSchema]
            InheritanceType        : None
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=NetServices,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['dHCPClass']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            # Add the parameter to remove the rule
            $Splat.Add('RemoveRule', $true)

        } #end If

        if ($PSCmdlet.ShouldProcess($Group, ('{0} Create/Delete permissions on DHCP objects' -f $operation))) {

            Set-AclConstructor5 @Splat

        } #end If

    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} ' -f $PSBoundParameters['Group'])
        } #end If-Else

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'delegating DHCP.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end END
} #end Function Set-AdAclFullControlDHCP
