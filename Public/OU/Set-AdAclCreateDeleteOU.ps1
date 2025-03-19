function Set-AdAclCreateDeleteOU {
    <#
        .Synopsis
            The function will delegate the permission for a group to create/Delete
            Organizational Units objects within an OU
        .DESCRIPTION
            Configures the container (OU) to delegate the permissions to a group so it can create/delete OU objects.
        .EXAMPLE
            Set-AdAclCreateDeleteOU -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclCreateDeleteOU -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU that can be Changed
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.DelegationPS
                Set-AclConstructor6                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
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
            HelpMessage = 'Distinguished Name of the OU that can be Changed',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : Descendents
                InheritedObjectType : organizationalUnit [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['All']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['organizationalUnit']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for organizationalUnit?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for organizationalUnit?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : organizationalUnit [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['organizationalUnit']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for organizationalUnit?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for organizationalUnit?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : account [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : organizationalUnit [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['account']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['organizationalUnit']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for account?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for account?')) {
            Set-AclConstructor6 @Splat
        } #end If

    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating Create/Delete OU.'
        )
        Write-Verbose -Message $txt

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Create/Delete OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
