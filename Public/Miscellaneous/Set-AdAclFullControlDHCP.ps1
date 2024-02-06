Function Set-AdAclFullControlDHCP {
    <#
        .Synopsis
            Set delegation to fully manage Dynamic Host Configuration Protocol (DHCP)
        .DESCRIPTION
            Configures the configuration container to delegate the permissions to a group so it can fully manage Dynamic Host Configuration Protocol (DHCP).
        .EXAMPLE
            Set-AdAclFullControlDHCP -Group "SL_DHCPRight"
        .EXAMPLE
            Set-AdAclFullControlDHCP -Group "SL_DHCPRight" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    07/Dec/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
        [String]
        $Group,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        $parameters = $null

        If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0)     -and
                 ($Variables.GuidMap -ne '')    -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
            ) {
            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            New-GuidObjectHashTable
        } #end If

    } #end Begin

    Process {
        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\xxx
            ActiveDirectoryRightst : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : dHCPClass [ClassSchema]
            IsInherited            : False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=NetServices,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.GuidNULL
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['dHCPClass']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACENumber              : 2
            IdentityReference      : EguibarIT\xxx
            ActiveDirectoryRightst : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : dHCPClass [ClassSchema]
            InheritanceType        : None
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=NetServices,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['dHCPClass']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
