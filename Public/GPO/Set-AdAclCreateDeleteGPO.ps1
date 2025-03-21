function Set-AdAclCreateDeleteGPO {
    <#
        .SYNOPSIS
            Delegates GPO creation/deletion permissions to a security group.

        .DESCRIPTION
            Delegates permissions to create and delete Group Policy Objects (GPOs) to a specified security group
            within Active Directory's Group Policy Container. This function supports both granting and removing
            these permissions through the -RemoveRule parameter.

        .EXAMPLE
            Set-AdAclCreateDeleteGPO -Group 'SG_GPO_Admins'
            Grants GPO create/delete permissions to the SG_GPO_Admins group.

        .EXAMPLE
            Set-AdAclCreateDeleteGPO -Group 'SG_GPO_Admins' -RemoveRule
            Removes GPO create/delete permissions from the SG_GPO_Admins group.

        .EXAMPLE
            'SG_GPO_Admins' | Set-AdAclCreateDeleteGPO
            Grants permissions using pipeline input.

        .PARAMETER Group
            Specifies the security group that will receive or lose the GPO management permissions.
            Accepts distinguished names, SamAccountNames, or GUID strings.

        .PARAMETER RemoveRule
            When specified, removes the GPO management permissions instead of granting them.

        .NOTES
            Used Functions:
                Name                                      ║ Module
                ══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                       ║ EguibarIT.DelegationPS
                Get-AdObjectType                          ║ EguibarIT.DelegationPS
                Write-Verbose                             ║ Microsoft.PowerShell.Utility
                Write-Error                               ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    20/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'Default'
    )]
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
              ActiveDirectoryRights : CreateChild
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Policies,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }

        # Check if RemoveRule switch is present.
        if ($PSBoundParameters['RemoveRule']) {

            $Splat['RemoveRule'] = $true
            $ActionDescription = ('Remove GPO management permissions from group {0}' -f $PSBoundParameters['Group'])

        } else {

            $ActionDescription = ('Grant GPO management permissions to group {0}' -f $PSBoundParameters['Group'])

        } #end If-Else

        # Perform the action with ShouldProcess
        if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], $ActionDescription)) {

            Set-AclConstructor5 @Splat
            Write-Verbose -Message ('Successfully completed {0}' -f $ActionDescription)

        } #end If

    } #end Process

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
} #end function Set-AdAclCreateDeleteGPO
