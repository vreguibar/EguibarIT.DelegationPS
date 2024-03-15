function Set-AdAclFullControlDFS {
    <#
        .Synopsis
            The function will delegate full control premission for a group
            over DFS
        .DESCRIPTION
            The function will delegate full control premission for a group
            over DFS
        .EXAMPLE
            Set-AdAclFullControlDFS -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclFullControlDFS -Group "SG_SiteAdmins_XXXX" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.Delegation
                Get-AdDomain                           | ActiveDirectory
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

    } #end Begin

    Process {
        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRightst : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                = $PSBoundParameters['Group']
            LDAPPath          = 'CN=DFSR-GlobalSettings,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight           = 'GenericAll'
            AccessControlType = 'Allow'
            ObjectType        = $Constants.guidNull
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Full Controll DFS Global Settings?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Full Controll DFS Global Settings?')) {
            Set-AclConstructor4 @Splat
        } #end If

        <#
            ACENumber              : 1
            DistinguishedName      : CN=Dfs-Configuration,CN=System,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\SL_DfsRight
            ActiveDirectoryRightst : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                = $PSBoundParameters['Group']
            LDAPPath          = 'CN=Dfs-Configuration,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight           = 'GenericAll'
            AccessControlType = 'Allow'
            ObjectType        = $Constants.guidNull
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Full Controll DFS Configuration?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Full Controll DFS Configuration?')) {
            Set-AclConstructor4 @Splat
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
