function Get-PrivilegeRightMapping {
    <#
        .SYNOPSIS
            Returns a mapping of privilege right keys to their human-readable descriptions.

        .DESCRIPTION
            This function returns a hashtable that maps Windows privilege right constants to
            their human-readable descriptions. These descriptions match the text shown in the
            Group Policy Editor under "User Rights Assignment".

            The function provides a comprehensive mapping for all standard Windows privilege rights,
            including both logon rights and system privileges. This mapping is used by other functions
            in the module to provide meaningful descriptions when working with privilege rights.

            The mapping is organized into two sections:
            - Empty by default rights (rights that are typically not assigned to any user by default)
            - Parameter mapped rights (rights that correspond to parameters in Set-GpoPrivilegeRight)

        .EXAMPLE
            $mapping = Get-PrivilegeRightMapping
            $mapping['SeBackupPrivilege']

            # Returns: "Back up files and directories"

            Retrieves the mapping hashtable and displays the human-readable description
            for the SeBackupPrivilege right.

        .EXAMPLE
            $mapping = Get-PrivilegeRightMapping
            $mapping.Keys | Where-Object { $_ -like "*Logon*" }

            Lists all privilege right constants related to logon rights.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            System.Collections.Hashtable

            Returns a hashtable with privilege right constants as keys and their human-readable
            descriptions as values. For example:
            @{ 'SeBackupPrivilege' = 'Back up files and directories'; ... }

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

        .LINK
            https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment

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
        # Empty by default rights
        'SeTrustedCredManAccessPrivilege'           = 'Access Credential Manager as a trusted caller'
        'SeTcbPrivilege'                            = 'Act as part of the operating system'
        'SeCreateTokenPrivilege'                    = 'Create a token object'
        'SeCreatePermanentPrivilege'                = 'Create permanent shared objects'
        'SeDebugPrivilege'                          = 'Debug programs'
        'SeLockMemoryPrivilege'                     = 'Lock pages in memory'

        # Parameter mapped rights
        'SeDenyBatchLogonRight'                     = 'Deny log on as a batch job'
        'SeDenyInteractiveLogonRight'               = 'Deny log on locally'
        'SeDenyNetworkLogonRight'                   = 'Deny access to this computer from the network'
        'SeDenyRemoteInteractiveLogonRight'         = 'Deny log on through Remote Desktop Services'
        'SeDenyServiceLogonRight'                   = 'Deny log on as a service'
        'SeEnableDelegationPrivilege'               = 'Enable computer and user accounts to be trusted for delegation'
        'SeNetworkLogonRight'                       = 'Access this computer from the network'
        'SeRemoteInteractiveLogonRight'             = 'Allow log on through Remote Desktop Services'
        'SeBatchLogonRight'                         = 'Log on as a batch job'
        'SeInteractiveLogonRight'                   = 'Allow log on locally'
        'SeServiceLogonRight'                       = 'Log on as a service'
        'SeMachineAccountPrivilege'                 = 'Add workstations to domain'
        'SeIncreaseQuotaPrivilege'                  = 'Adjust memory quotas for a process'
        'SeBackupPrivilege'                         = 'Back up files and directories'
        'SeChangeNotifyPrivilege'                   = 'Bypass traverse checking'
        'SeSystemtimePrivilege'                     = 'Change the system time'
        'SeTimeZonePrivilege'                       = 'Change the time zone'
        'SeCreatePagefilePrivilege'                 = 'Create a pagefile'
        'SeCreateGlobalPrivilege'                   = 'Create global objects'
        'SeCreateSymbolicLinkPrivilege'             = 'Create symbolic links'
        'SeRemoteShutdownPrivilege'                 = 'Force shutdown from a remote system'
        'SeAuditPrivilege'                          = 'Generate security audits'
        'SeImpersonatePrivilege'                    = 'Impersonate a client after authentication'
        'SeIncreaseWorkingSetPrivilege'             = 'Increase a process working set'
        'SeIncreaseBasePriorityPrivilege'           = 'Increase scheduling priority'
        'SeLoadDriverPrivilege'                     = 'Load and unload device drivers'
        'SeSecurityPrivilege'                       = 'Manage auditing and security log'
        'SeRelabelPrivilege'                        = 'Modify an object label'
        'SeSystemEnvironmentPrivilege'              = 'Modify firmware environment values'
        'SeDelegateSessionUserImpersonatePrivilege' = 'Obtain an impersonation token for another user in the same session'
        'SeManageVolumePrivilege'                   = 'Perform volume maintenance tasks'
        'SeProfileSingleProcessPrivilege'           = 'Profile single process'
        'SeSystemProfilePrivilege'                  = 'Profile system performance'
        'SeUndockPrivilege'                         = 'Remove computer from docking station'
        'SeAssignPrimaryTokenPrivilege'             = 'Replace a process level token'
        'SeRestorePrivilege'                        = 'Restore files and directories'
        'SeShutdownPrivilege'                       = 'Shut down the system'
        'SeSyncAgentPrivilege'                      = 'Synchronize directory service data'
        'SeTakeOwnershipPrivilege'                  = 'Take ownership of files or other objects'
    }
} #end function
