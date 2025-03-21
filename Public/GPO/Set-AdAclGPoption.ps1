function Set-AdAclGPoption {
    <#
        .Synopsis
            Set delegation to GPO Options
        .DESCRIPTION
            The function will delegate the permission for a group to
            Change GPO options
        .EXAMPLE
            Set-AdAclGPoption -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclGPoption -Group "SG_SiteAdmins_XXXX" -RemoveRule
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

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACENumber             : 1
            --------------------------------------------------------
            IdentityReference     : XXX
            AdRight               : ReadProperty, WriteProperty
            AccessControlType     : Allow
            ObjectType            : gPOptions [attributeSchema]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : True
        #>

        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Policies,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['gPOptions']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        if ($PSBoundParameters['RemoveRule']) {

            $Splat['RemoveRule'] = $true
            $ActionDescription = ('Remove GpOption permissions from group {0}' -f $PSBoundParameters['Group'])

        } else {

            $ActionDescription = ('Grant GpOption permissions to group {0}' -f $PSBoundParameters['Group'])

        } #end If-Else

        # Perform the action with ShouldProcess
        if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], $ActionDescription)) {

            Set-AclConstructor5 @Splat
            Write-Verbose -Message ('Successfully completed {0}' -f $ActionDescription)

        } #end If
    }

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
} #end function Set-AdAclGPoption
