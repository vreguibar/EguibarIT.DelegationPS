Function Set-AdAclMngPrivilegedGroup {
    <#
        .Synopsis
            The function will delegate the premission for a group to Managed Privileged Groups
        .DESCRIPTION
            The function will delegate the premission for a group to Managed Privileged Groups
        .EXAMPLE
            Set-AdAclMngPrivilegedGroup -Group "SL_PGM"
        .EXAMPLE
            Set-AdAclMngPrivilegedGroup -Group "SL_PGM" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER RemoveRule
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    14/Oct/2016
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable

    } #end Begin

    Process {
        <#
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PGM":RPWP;member

            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : member [AttributeSchema]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['member']
            AdSecurityInheritance = 'None'
        }
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Change Password?')) {
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Change Password?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } # end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} ' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
