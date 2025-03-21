Function Set-AdAclRSoPLogging {
    <#
        .Synopsis
            Set delegation to Resultant Set of Policy (Logging)
        .DESCRIPTION
            The function will delegate the permission for a group to Resultant Set of Policy (Logging)
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
                Set-AclConstructor5                    | EguibarIT.DelegationPS
                Get-ExtendedRightHashTable             | EguibarIT.DelegationPS
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

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : ExtendedRight
                  AccessControlType : Allow
                         ObjectType : Generate Resultant Set of Policy (Logging) [ExtendedRight]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>

        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $Variables.defaultNamingContext
            AdRight               = 'ExtendedRight'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.ExtendedRightsMap['Generate Resultant Set of Policy (Logging)']
            AdSecurityInheritance = 'All'
        }

        # Check if RemoveRule switch is present.
        if ($PSBoundParameters['RemoveRule']) {

            $Splat['RemoveRule'] = $true
            $ActionDescription = ('Remove Generate Resultant Set of Policy (Logging) permissions from group {0}' -f $PSBoundParameters['Group'])

        } else {

            $ActionDescription = ('Grant Generate Resultant Set of Policy (Logging) permissions to group {0}' -f $PSBoundParameters['Group'])

        } #end If-Else

        # Perform the action with ShouldProcess
        if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], $ActionDescription)) {

            Set-AclConstructor5 @Splat
            Write-Verbose -Message ('Successfully completed {0}' -f $ActionDescription)

        } #end If
    } # end Process

    End {

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                $ActionDescription
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END
}
