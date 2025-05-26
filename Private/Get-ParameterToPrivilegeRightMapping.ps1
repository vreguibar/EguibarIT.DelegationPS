function Get-ParameterToPrivilegeRightMapping {
    <#
        .SYNOPSIS
            Returns a mapping of parameter names to privilege right keys.

        .DESCRIPTION
            This function returns a hashtable that maps parameter names used in the Set-GpoPrivilegeRight
            cmdlet to the corresponding system privilege right keys. This mapping allows the module
            to translate between human-readable parameter names and the actual system constants
            used in Group Policy Objects.

            The mapping includes all standard Windows privilege rights including logon rights,
            deny rights, and various system privileges.

            This function is primarily used by Add-ParameterBasedRight to process parameters
            passed to Set-GpoPrivilegeRight.

        .EXAMPLE
            $mapping = Get-ParameterToPrivilegeRightMapping
            $mapping['Backup']

            # Returns: SeBackupPrivilege

            Retrieves the mapping hashtable and looks up the system privilege right key
            corresponding to the 'Backup' parameter.

        .EXAMPLE
            $mapping = Get-ParameterToPrivilegeRightMapping
            $mapping.Keys | Sort-Object

            Retrieves the mapping hashtable and outputs all parameter names in alphabetical order.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            System.Collections.Hashtable

            Returns a hashtable with parameter names as keys and privilege right constants as values.
            For example: @{ 'Backup' = 'SeBackupPrivilege'; 'NetworkLogon' = 'SeNetworkLogonRight'; ... }

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                None                                       ║

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
            Security

        .FUNCTIONALITY
            Privilege Rights, User Rights Assignment
    #>
    [CmdletBinding()]
    [OutputType([Hashtable])]

    param()

    return @{
        'NetworkLogon'                   = 'SeNetworkLogonRight'
        'DenyNetworkLogon'               = 'SeDenyNetworkLogonRight'
        'InteractiveLogon'               = 'SeInteractiveLogonRight'
        'DenyInteractiveLogon'           = 'SeDenyInteractiveLogonRight'
        'RemoteInteractiveLogon'         = 'SeRemoteInteractiveLogonRight'
        'DenyRemoteInteractiveLogon'     = 'SeDenyRemoteInteractiveLogonRight'
        'BatchLogon'                     = 'SeBatchLogonRight'
        'DenyBatchLogon'                 = 'SeDenyBatchLogonRight'
        'ServiceLogon'                   = 'SeServiceLogonRight'
        'DenyServiceLogon'               = 'SeDenyServiceLogonRight'
        'MachineAccount'                 = 'SeMachineAccountPrivilege'
        'IncreaseQuota'                  = 'SeIncreaseQuotaPrivilege'
        'Backup'                         = 'SeBackupPrivilege'
        'ChangeNotify'                   = 'SeChangeNotifyPrivilege'
        'SystemTime'                     = 'SeSystemtimePrivilege'
        'TimeZone'                       = 'SeTimeZonePrivilege'
        'CreatePagefile'                 = 'SeCreatePagefilePrivilege'
        'CreateGlobal'                   = 'SeCreateGlobalPrivilege'
        'CreateSymbolicLink'             = 'SeCreateSymbolicLinkPrivilege'
        'EnableDelegation'               = 'SeEnableDelegationPrivilege'
        'RemoteShutdown'                 = 'SeRemoteShutdownPrivilege'
        'Audit'                          = 'SeAuditPrivilege'
        'Impersonate'                    = 'SeImpersonatePrivilege'
        'IncreaseWorkingSet'             = 'SeIncreaseWorkingSetPrivilege'
        'IncreaseBasePriority'           = 'SeIncreaseBasePriorityPrivilege'
        'LoadDriver'                     = 'SeLoadDriverPrivilege'
        'AuditSecurity'                  = 'SeSecurityPrivilege'
        'Relabel'                        = 'SeRelabelPrivilege'
        'SystemEnvironment'              = 'SeSystemEnvironmentPrivilege'
        'DelegateSessionUserImpersonate' = 'SeDelegateSessionUserImpersonatePrivilege'
        'ManageVolume'                   = 'SeManageVolumePrivilege'
        'ProfileSingleProcess'           = 'SeProfileSingleProcessPrivilege'
        'SystemProfile'                  = 'SeSystemProfilePrivilege'
        'Undock'                         = 'SeUndockPrivilege'
        'AssignPrimaryToken'             = 'SeAssignPrimaryTokenPrivilege'
        'Restore'                        = 'SeRestorePrivilege'
        'Shutdown'                       = 'SeShutdownPrivilege'
        'SyncAgent'                      = 'SeSyncAgentPrivilege'
        'TakeOwnership'                  = 'SeTakeOwnershipPrivilege'
        'TrustedCredMan'                 = 'SeTrustedCredManAccessPrivilege'
    }
} #end function
