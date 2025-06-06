function Add-PrivilegeRight {
    <#
        .SYNOPSIS
            Adds privilege rights (empty or parameter-based) to the specified collection.

        .DESCRIPTION
            The Add-PrivilegeRight function consolidates the logic for adding both empty privilege rights and parameter-based rights to a collection. It accepts a collection (or creates a new one if not provided) and a hashtable/dictionary of rights to add, where each key is the privilege right name and the value is a member list (which can be empty). The function uses internal mappings for privilege right descriptions and ensures consistent object structure for downstream processing.

        .PARAMETER Collection
            The collection to add privilege rights to. If not provided or null, a new System.Collections.Generic.List[object] collection will be created and returned.

        .PARAMETER RightsToAdd
            A hashtable or dictionary where keys are privilege right names and values are member lists (can be empty). Each right will be added to the collection with its associated members.

        .EXAMPLE
            $rightsCollection = [System.Collections.Generic.List[object]]::new()
            $rightsToAdd = @{ 'SeDenyInteractiveLogonRight' = @('Everyone') }
            Add-PrivilegeRight -Collection $rightsCollection -RightsToAdd $rightsToAdd

            Adds the 'SeDenyInteractiveLogonRight' privilege with 'Everyone' as a member to the specified collection.

        .EXAMPLE
            $rightsCollection = [System.Collections.Generic.List[object]]::new()
            $emptyRights = @{
                'SeTrustedCredManAccessPrivilege' = @()
                'SeTcbPrivilege' = @()
            }
            Add-PrivilegeRight -Collection $rightsCollection -RightsToAdd $emptyRights

            Adds two empty privilege rights to the collection.

        .INPUTS
            System.Collections.Generic.List[object]
            System.Collections.IDictionary
            You can pipe a hashtable of rights to the RightsToAdd parameter.

        .OUTPUTS
            System.Collections.Generic.List[object]
            Returns the updated collection with the added privilege rights.

        .NOTES
            Used Functions:
                Name                             ║ Module/Namespace
                ═════════════════════════════════╬══════════════════════════════
                Add-PrivilegeRight               ║ EguibarIT.DelegationPS (Private)
                Write-Verbose                    ║ Microsoft.PowerShell.Utility
                Write-Warning                    ║ Microsoft.PowerShell.Utility
                Write-Debug                      ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay              ║ EguibarIT.DelegationPS (Private)

        .NOTES
            Version:         3.1
            DateModified:    06/Jun/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibarit.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Add-PrivilegeRight.ps1

        .COMPONENT
            Group Policy

        .ROLE
            Security Configuration

        .FUNCTIONALITY
            Group Policy Management, Privilege Rights Consolidation
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Generic.List[object]])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Collection to add privilege rights to, most likely from PSBoundParameters from calling function',
            Position = 0)]
        [System.Collections.IDictionary]
        $RightsToAdd
    )

    Begin {

        # mapping hashtable containing:
        #     Keys as privilege right names (e.g. SeNetworkLogonRight, SeDenyNetworkLogonRight)
        #     Values as description of the right (e.g. 'Access this computer from the network', 'Deny access to this computer from the network')
        # This mapping is used to provide descriptions for the rights being added
        $rightMappings = @{
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

        # mapping hashtable containing:
        #    Keys as privilege right name (matching parameter name, e.g. NetworkLogon, DenyNetworkLogon)
        #    values as the actual privilege right name (e.g. SeNetworkLogonRight, SeDenyNetworkLogonRight)
        # This mapping is used to convert parameter names to actual privilege right names
        $parameterMappings = @{
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

        # Array containing privilege rights that are empty by default
        # These rights are added to the collection without any members
        $emptyRights = @(
            'SeTrustedCredManAccessPrivilege',
            'SeTcbPrivilege',
            'SeCreateTokenPrivilege',
            'SeCreatePermanentPrivilege',
            'SeDebugPrivilege',
            'SeLockMemoryPrivilege'
        )

        Write-Warning -Message 'Creating a new collection.'
        $Collection = [System.Collections.Generic.List[object]]::new()

    } #end Begin

    Process {

        #region Process Empty Member Rights

        Write-Debug -Message ('Processing {0} empty member rights' -f $emptyRights.Count)

        # iterate over the empty rights and lookup each right in the mappings. finally add them to the collection
        foreach ($right in $emptyRights) {

            # Directly add the right to the collection to avoid parameter binding issues
            $rightHash = @{
                Section     = 'Privilege Rights'
                Key         = $right
                Members     = [System.Collections.Generic.List[string]]::new()
                Description = $rightMappings[$right]
            }

            try {

                # Adding empty right directly to collection
                $Collection.Add($rightHash)

                Write-Debug -Message ('Added empty right {0} directly to collection' -f $right)

            } catch {

                Write-Warning -Message ('Failed to add empty right {0}: {1}' -f $right, $_.Exception.Message)

            } #end try-catch

        } #end foreach
        #endregion Process Empty Member Rights

        # Start processing the privilege rights based on bound parameters
        $totalParameters = ($RightsToAdd.Keys | Where-Object { $RightsToAdd.ContainsKey($_) }).Count
        $current = 0

        # iterate through each bound parameter (e.g. NetworkLogon, DenyNetworkLogon, etc.).
        # This is equal to the parameter name and is coming from the calling function PSBoundParameters
        # The right variable will be the key in the $parameterMappings dictionary
        foreach ($right in $RightsToAdd.Keys) {

            # Skip GpoToModify, Confirm, Debug, Verbose parameters, as those may be included in the PSBoundParameter collection
            if ($right -eq 'GpoToModify' -or
                $right -eq 'Confirm' -or
                $right -eq 'Verbose' -or
                $right -eq 'Debug' ) {
                continue
            } #end if

            # Check if parameter is in our mapping. (e.g. NetworkLogon, DenyNetworkLogon, etc.).
            # If it is, we will process it and add the right to the collection.
            # If not, we will skip it.
            if ($parameterMappings.ContainsKey($right)) {

                $current++
                $percentComplete = ($current / $totalParameters) * 100

                $Splat = @{
                    Activity        = 'Processing privilege rights'
                    Status          = 'Processing {0}' -f $right
                    PercentComplete = $percentComplete
                }
                Write-Progress @Splat

                # get the Key representing the right to add (e.g. SeNetworkLogonRight, SeDenyNetworkLogonRight, etc.)
                $rightKey = $parameterMappings[$right]

                # get the members to be assigned to the right.
                # This is the value pair og the key, coming the BoundParameters dictionary
                $members = $RightsToAdd[$right]

                # We have all information we need to add the right to the collection.
                # now we have to check members:
                # If KEY already contains members, check each member (SID string) and ensure it exists.
                # Then, process new members. Ensure each new member exist and has a SID. Extract the SID and add it to the members list.


                if ($null -eq $members) {

                    $members = [System.Collections.Generic.List[string]]::new()

                } #end if

                $rightHash = @{
                    Section     = 'Privilege Rights'
                    Key         = $rightKey
                    Members     = $members
                    Description = $rightMappings[$right]
                }
                try {

                    $Collection.Add($rightHash)
                    Write-Debug -Message ('Added right {0} to collection' -f $right)

                } catch {

                    Write-Warning -Message ('Failed to add right {0}: {1}' -f $right, $_.Exception.Message)

                } #end try-catch
            } #end if
        } #end foreach
    } #end Process

    End {

        Write-Verbose -Message ('Finalizing collection with {0} items' -f $Collection.Count)

        # Finalize the collection and return it
        return $Collection
    } #end End
} #end function Add-PrivilegeRight
