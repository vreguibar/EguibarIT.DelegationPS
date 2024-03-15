function Set-AdAclLinkGPO {
    <#
        .Synopsis
            Set delegation to Link Group Policy Objects
        .DESCRIPTION
            The function will delegate the premission for a group to Link Group Policy Objects objects to Domain or OU
        .EXAMPLE
            Set-AdAclLinkGPO -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclLinkGPO -Group "SG_SiteAdmins_XXXX" -RemoveRule
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

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

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
            ACENumber             : 1
            --------------------------------------------------------
            IdentityReference     : XXX
            AdRight               : ReadProperty, WriteProperty
            AccessControlType     : Allow
            ObjectType            : gPLink [attributeSchema]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : True
        #>

        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Policies,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['gPLink']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Link GPO?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Link GPO?')) {
            Set-AclConstructor5 @Splat
        } #end If
    }

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
