Function Set-AdAclRSoPLogging {
    <#
        .Synopsis
            Set delegation to Resultant Set of Policy (Logging)
        .DESCRIPTION
            The function will delegate the premission for a group to Resultant Set of Policy (Logging)
        .EXAMPLE
            Set-AdAclRSoPLogging -Group "SL_GpoRight"
        .EXAMPLE
            Set-AdAclRSoPLogging -Group "SL_GpoRight" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
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

        If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
        ) {
            # $Variables.ExtendedRightsMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.ExtendedRightsMap is empty. Calling function to fill it up.'
            New-ExtenderRightHashTable
        } #end If

        If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
        ) {
            # $Variables.ExtendedRightsMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.ExtendedRightsMap is empty. Calling function to fill it up.'
            New-ExtenderRightHashTable
        } #end If

    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ExtendedRight
                  AccessControlType : Allow
                         ObjectType : Generate Resultant Set of Policy (Logging) [ExtendedRight]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>

        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $Variables.defaultNamingContext
            AdRight               = 'ExtendedRight'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.ExtendedRightsMap['Generate Resultant Set of Policy (Logging)']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Generate Resultant Set of Policy (Logging)?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Generate Resultant Set of Policy (Logging)?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } # end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
