function Set-AdAclPkiTemplateAdmin {
    <#
        .Synopsis
            The function will delegate template management premission for a group
            over Certificate Authority
        .DESCRIPTION
            Configures the configuration container to delegate the permissions to a group so it can fully manage CA Templates.
        .EXAMPLE
            Set-AdAclPkiTemplateAdmin -Group "SG_PkiAdmin"
        .EXAMPLE
            Set-AdAclPkiTemplateAdmin -Group "SG_PkiAdmin" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
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
        [String]
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

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

    } #end Begin

    Process {
        <#
            ACENumber             : 1
            IdentityReference     : EguibarIT\XXX
            AdRight               : GenericAll
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # Certificate Authority Template Admin
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI template?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for PKI template?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber             : 1
            LDAPpath              : CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference     : EguibarIT\XXX
            AdRight               : GenericAll
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # Certificate Authority Template Admin
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI template?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for PKI template?')) {
            Set-AclConstructor5 @Splat
        } #end If

    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding PKI template."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
