function Set-AdAclPkiAdmin {
    <#
        .SYNOPSIS
            Delegates full administrative permissions over the Certificate Authority (CA/PKI).

        .DESCRIPTION
            The Set-AdAclPkiAdmin function delegates comprehensive administrative permissions
            for a specified security group over the Active Directory Certificate Services
            infrastructure. This includes the Certificate Authority (CA) configuration
            container and related objects.

            The function performs the following actions:
            - Locates the Public Key Services container in the Configuration partition
            - Adds or removes Access Control Entries (ACEs) granting full control permissions
            - Establishes permission inheritance for child objects
            - Sets up management access for certificate templates and enrollment services

            This delegation enables the specified group to fully administer the PKI environment,
            including certificate issuance, revocation, template management, and CA configuration.

        .PARAMETER Group
            Specifies the security group that will receive or have removed PKI administrative
            permissions. This parameter accepts:
            - SAM Account Name (e.g., "SG_PkiAdmin")
            - Distinguished Name
            - Security Identifier (SID)
            - Group object from Get-ADGroup

        .PARAMETER ItRightsOuDN
            Specifies the Distinguished Name of the Organizational Unit containing the Rights groups,
            where the "Cert Publishers" built-in group resides. This is typically something like
            "OU=Rights,OU=Admin,DC=EguibarIT,DC=local" in a delegated administration model.

            This parameter is used to identify the location of security groups related to
            certificate services administration.

        .PARAMETER RemoveRule
            When specified, removes the PKI administrative permissions instead of granting them.
            Use this parameter when decommissioning administrative roles or reducing privileges.

        .PARAMETER Force
            When specified, suppresses confirmation prompts when performing permission changes.
            This is useful for automation scenarios where no user interaction is desired.

        .EXAMPLE
            Set-AdAclPkiAdmin -Group "SG_PkiAdmin" -ItRightsOuDN "OU=Rights,OU=Admin,DC=EguibarIT,DC=local"

            Grants full PKI administrative permissions to the "SG_PkiAdmin" security group.

        .EXAMPLE
            Set-AdAclPkiAdmin -Group "SG_PkiAdmin" -ItRightsOuDN "OU=Rights,OU=Admin,DC=EguibarIT,DC=local" -RemoveRule

            Removes PKI administrative permissions from the "SG_PkiAdmin" security group.

        .EXAMPLE
            $Splat = @{
                Group = "SG_PkiAdmin"
                ItRightsOuDN = "OU=Rights,OU=Admin,DC=EguibarIT,DC=local"
                Force = $true
            }
            Set-AdAclPkiAdmin @Splat

            Grants PKI administrative permissions without confirmation prompts using splatting.

        .INPUTS
            System.String
            Microsoft.ActiveDirectory.Management.ADGroup

            You can pipe group names or Group objects from Get-ADGroup to this function.

        .OUTPUTS
            System.Void

            This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                        ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Test-IsValidDN                             ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            PKI
            Active Directory Certificate Services

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Certificate Authority Management, PKI Administration
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        #PARAM2 Distinguished Name of the OU were the groups can be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU having the Rights groups, where the "Cert Publishers" built-in group resides (Usually OU=Rights,OU=Admin,DC=EguibarIT,DC=local).',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $ItRightsOuDN,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 3)]
        [Switch]
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

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACENumber             : 3
            IdentityReference     : EguibarIT\XXXX
            AdRight               : GenericAll
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # Certificate Authority Admin
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber             : 1
            IdentityReference     : EguibarIT\XXX
            AdRight               : ListChildren, ReadProperty, GenericWrite
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : None
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # rights to modify security permissions for Pre-Windows 2000 Compatible Access group.
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber             : 2
            IdentityReference     : EguibarIT\XXX
            AdRight               : ListChildren, ReadProperty, GenericWrite
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : None
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # rights to modify security permissions for Cert Publishers group.
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Cert Publishers,{0}' -f $PSBoundParameters['ItRightsOuDN']
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating management of PKI.'
        )
        Write-Verbose -Message $txt
    } #end END
}
