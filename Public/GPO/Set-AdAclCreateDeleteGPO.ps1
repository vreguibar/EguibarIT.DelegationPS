function Set-AdAclCreateDeleteGPO {
    <#
        .SYNOPSIS
            Delegates permissions to create and delete Group Policy Objects (GPOs).

        .DESCRIPTION
            The Set-AdAclCreateDeleteGPO function grants or removes permissions to create and delete
            Group Policy Objects (GPOs) for a specified security group within Active Directory.

            This function performs the following actions:
            - Locates the Group Policy Container (CN=Policies,CN=System) in the domain
            - Adds or removes the appropriate Access Control Entries (ACEs) to allow GPO creation/deletion
            - Configures permissions that work with both GPMC and PowerShell-based GPO management

            The function requires Domain Admin privileges or equivalent permissions to modify the
            Group Policy Container ACL. It supports confirmation prompts through -Confirm and can be
            bypassed with -Force when used in automation scenarios.

        .PARAMETER Group
            Specifies the security group that will receive or lose GPO creation and deletion permissions.
            This parameter accepts various formats:
            - SAM Account Name (e.g., 'SG_GPO_Admins')
            - Distinguished Name (e.g., 'CN=SG_GPO_Admins,OU=Groups,DC=contoso,DC=com')
            - Security Identifier (SID) object or string
            - Group object from Get-ADGroup

        .PARAMETER RemoveRule
            When specified, the function removes GPO creation/deletion permissions instead of granting them.
            This is useful when decommissioning administrative roles or reducing privileges.

        .EXAMPLE
            Set-AdAclCreateDeleteGPO -Group 'SG_GPO_Admins'

            Grants permissions to create and delete Group Policy Objects to the 'SG_GPO_Admins' security group.

        .EXAMPLE
            Set-AdAclCreateDeleteGPO -Group 'SG_GPO_Admins' -RemoveRule

            Removes permissions to create and delete Group Policy Objects from the 'SG_GPO_Admins' security group.

        .EXAMPLE
            'SG_GPO_Admins' | Set-AdAclCreateDeleteGPO

            Grants GPO creation and deletion permissions using pipeline input.

        .EXAMPLE
            $Splat = @{
                Group = 'SG_GPO_Admins'
                RemoveRule = $true
            }
            Set-AdAclCreateDeleteGPO @Splat

            Removes GPO creation and deletion permissions using splatting.

        .INPUTS
            System.String
            Microsoft.ActiveDirectory.Management.ADGroup

            You can pipe group names as strings or Group objects from Get-ADGroup to this function.

        .OUTPUTS
            System.Void

            This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                        ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Group Policy

        .ROLE
            Security Administration

        .FUNCTIONALITY
            GPO Management, Delegation of Control
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
