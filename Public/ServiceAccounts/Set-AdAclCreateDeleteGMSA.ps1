Function Set-AdAclCreateDeleteMSA {
    <#
            .Synopsis
                The function will delegate the premission for a group to Create/Delete Group Managed Service Accounts
            .DESCRIPTION
                The function will delegate the premission for a group to Create/Delete Group Managed Service Accounts
            .EXAMPLE
                Set-AdAclCreateDeleteGMSA -Group "SL_CreateUserRight" -LDAPpath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            .EXAMPLE
                Set-AdAclCreateDeleteGMSA -Group "SL_CreateUserRight" -LDAPpath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
            .PARAMETER Group
                [STRING] Identity of the group getting the delegation, usually a DomainLocal group.
            .PARAMETER LDAPpath
                [STRING] Distinguished Name of the object (or container) where the permissions are going to be configured.
            .PARAMETER RemoveRule
                [SWITCH] If present, the access rule will be removed
            .NOTES
                Used Functions:
                    Name                                   | Module
                    ---------------------------------------|--------------------------
                    Set-AclConstructor5                    | EguibarIT.Delegation
                    Set-AclConstructor6                    | EguibarIT.Delegation
                    Get-AttributeSchemaHashTable                | EguibarIT.Delegation
            .NOTES
                Version:         1.2
                DateModified:    07/Dec/2016
                LasModifiedBy:   Vicente Rodriguez Eguibar
                    vicente@eguibar.com
                    Eguibar Information Technology S.L.
                    http://www.eguibarit.com
        #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where the computer will get password reset
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the computer will get password reset',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

        If ( ($null -eq $Variables.GuidMap) -and
                     ($Variables.GuidMap -ne 0) -and
                     ($Variables.GuidMap -ne '') -and
                     (   ($Variables.GuidMap -isnot [array]) -or
                         ($Variables.GuidMap.Length -ne 0)) -and
                     ($Variables.GuidMap -ne $false)
        ) {
            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            Get-AttributeSchemaHashTable
        } #end If

    } #end Begin

    Process {
        <#
                ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ListChildren, ReadProperty, Delete, GenericWrite, WriteDacl
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ListChildren', 'ReadProperty', 'Delete', 'GenericWrite', 'WriteDacl'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.GuidNULL
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for GroupManagedServiceAccount?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for GroupManagedServiceAccount?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
                ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : msDS-GroupManagedServiceAccount [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for msDS-GroupManagedServiceAccount?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for msDS-GroupManagedServiceAccount?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
                ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : msDS-GroupManagedServiceAccount [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for msDS-GroupManagedServiceAccount?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for msDS-GroupManagedServiceAccount?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
                ACE number: 4
                --------------------------------------------------------
                      IdentityReference : XXX
                 ActiveDirectoryRightst : CreateChild, DeleteChild
                      AccessControlType : Allow
                             ObjectType : applicationVersion [ClassSchema]
                        InheritanceType : Descendents
                    InheritedObjectType : msDS-ManagedServiceAccount [ClassSchema]
                            IsInherited = False
            #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['applicationVersion']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for applicationVersion?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for applicationVersion?')) {
            Set-AclConstructor6 @Splat
        } #end If
    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Create Delete gMSA."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}


