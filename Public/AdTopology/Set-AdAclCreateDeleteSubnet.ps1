function Set-AdAclCreateDeleteSubnet {
    <#
        .Synopsis
            The function will delegate the permission for a group to
            create and delete Subnets
        .DESCRIPTION
            Configures the container (OU) to delegate the permissions to a group so it can create/delete Subnet objects.
        .EXAMPLE
            Set-AdAclCreateDeleteSubnet -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclCreateDeleteSubnet -Group "SG_SiteAdmins_XXXX" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.DelegationPS
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

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    begin {

        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    process {
        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRights : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : subnet [ClassSchema]
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Subnets,CN=Sites,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['subnet']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Create/Delete Subnets?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        }

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Create/Delete Subnets?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACENumber              : 2
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRights : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : subnet [ClassSchema]
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Subnets,CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['subnet']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Create/Delete Subnets?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Create/Delete Subnets?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'delegating Change Subnet.'
        )
        Write-Verbose -Message $txt
    } #end End
}
