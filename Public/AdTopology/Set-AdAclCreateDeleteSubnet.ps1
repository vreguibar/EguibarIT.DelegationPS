function Set-AdAclCreateDeleteSubnet {
    <#
        .Synopsis
            The function will delegate the premission for a group to
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
                Set-AclConstructor5                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $Group,

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    begin {
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

    process {
        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRightst : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : subnet [ClassSchema]
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Subnets,CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
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

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Create/Delete Subnets?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber              : 2
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRightst : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : subnet [ClassSchema]
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
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

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Create/Delete Subnets?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Change/Delete Subnet."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}
