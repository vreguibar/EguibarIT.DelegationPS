﻿function Set-AdAclChangeSubnet {
    <#
        .Synopsis
            The function will delegate the permission for a group to
            Change Subnets
        .DESCRIPTION
            Long description
        .EXAMPLE
            Set-AdAclChangeSubnet -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclChangeSubnet -Group "SG_SiteAdmins_XXXX" -RemoveRule
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
            Version:         1.2
            DateModified:    11/Mar/2024
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
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 2)]
        [Switch]
        $Force
    )

    begin {

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

        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    process {
        # todo: TerminatingError(Set-AclConstructor5): "Cannot validate argument on parameter 'LDAPpath'. The " Test-IsValidDN -ObjectDN $_ " validation script for the argument with value "cn=subnets,cn=Sites,CN=Configuration,DC=EguibarIT,DC=local" did not return a result of True. Determine why the validation script failed, and then try the command again."
        <#
            ACENumber             : 1
            Id                    : XXX
            AdRight               : ReadProperty, WriteProperty
            AccessControlType     : Allow
            ObjectType            : subnet [classSchema]
            AdSecurityInheritance : All
            InheritedObjectType   : All [GuidNULL]
            IsInherited           : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'cn=subnets,cn=Sites,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['subnet']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Change AD Subnet')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        }

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Change AD Subnet?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating Change Subnet.'
        )
        Write-Verbose -Message $txt
    } #end End
}
