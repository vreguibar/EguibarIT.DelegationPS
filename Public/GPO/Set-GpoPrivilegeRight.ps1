Function Set-GpoPrivilegeRight {

    <#
        .Synopsis
            Modifies user rights assignments in a specified Group Policy Object (MUST be executed on DomainController)

        .DESCRIPTION
            The Set-GpoPrivilegeRight function allows for detailed configuration of user rights
            assignments within a Group Policy Object. It can grant or deny various privilege rights
            such as network logon, interactive logon, machine account creation, and backup privileges.

            This function follows the Active Directory tiering model and adheres to security best practices.
            It is designed to work in large-scale AD environments and minimizes performance overhead.

        .EXAMPLE
            Set-GpoPrivilegeRight -GpoToModify "Default Domain" -BatchLogon "Domain\User1","Domain\User2"
            This example assigns "Log on as a batch job" rights to User1 and User2 in the "Default Domain" GPO.

        .EXAMPLE
            Test-GpoPrivilegeRight -GpoToModify 'Domain Controllers Policy' -NetworkLogon 'DOMAIN\Domain Admins'

            This command grants the "Access this computer from the network" right to the "Domain Admins" group
            in the "Domain Controllers Policy" GPO.

        .EXAMPLE
            Test-GpoPrivilegeRight -GpoToModify 'Workstations Policy' -DenyInteractiveLogon 'DOMAIN\Remote Users'

            This command denies the "Allow Log On Locally" right to the "Remote Users" group in the
            "Workstations Policy" GPO.

        .EXAMPLE
            Test-GpoPrivilegeRight -GpoToModify 'Servers Policy' -NetworkLogon 'DOMAIN\Server Admins' -DenyNetworkLogon 'DOMAIN\Domain Users' -Backup 'DOMAIN\Backup Operators'

            This command makes multiple privilege right modifications in the "Servers Policy" GPO:
            - Grants "Access this computer from the network" to "Server Admins"
            - Denies "Access this computer from the network" to "Domain Users"
            - Grants "Back up files and directories" to "Backup Operators"

        .EXAMPLE
            $Splat = @{
                GpoToModify                    = 'My posh GPO'
                NetworkLogon                   = $NetworkLogon
                DenyNetworkLogon               = $DenyNetworkLogon
                InteractiveLogon               = $InteractiveLogon
                DenyInteractiveLogon           = $DenyInteractiveLogon
                RemoteInteractiveLogon         = $RemoteInteractiveLogon
                DenyRemoteInteractiveLogon     = $DenyRemoteInteractiveLogon
                BatchLogon                     = $BatchLogon
                DenyBatchLogon                 = $DenyBatchLogon
                ServiceLogon                   = $ServiceLogon
                DenyServiceLogon               = $DenyServiceLogon
                MachineAccount                 = $MachineAccount
                IncreaseQuota                  = $IncreaseQuota
                Backup                         = $Backup
                ChangeNotify                   = $ChangeNotify
                SystemTime                     = $SystemTime
                TimeZone                       = $TimeZone
                CreatePagefile                 = $CreatePagefile
                CreateGlobal                   = $CreateGlobal
                CreateSymbolicLink             = $CreateSymbolicLink
                EnableDelegation               = $EnableDelegation
                RemoteShutdown                 = $RemoteShutdown
                Audit                          = $Audit
                Impersonate                    = $Impersonate
                IncreaseWorkingSet             = $IncreaseWorkingSet
                IncreaseBasePriority           = $IncreaseBasePriority
                LoadDriver                     = $LoadDriver
                AuditSecurity                  = $AuditSecurity
                Relabel                        = $Relabel
                SystemEnvironment              = $SystemEnvironment
                DelegateSessionUserImpersonate = $DelegateSessionUserImpersonate
                ManageVolume                   = $ManageVolume
                ProfileSingleProcess           = $ProfileSingleProcess
                SystemProfile                  = $SystemProfile
                Undock                         = $Undock
                AssignPrimaryToken             = $AssignPrimaryToken
                Restore                        = $Restore
                Shutdown                       = $Shutdown
                SyncAgent                      = $SyncAgent
                TakeOwnership                  = $TakeOwnership
            }
            Set-GpoPrivilegeRight @Splat

            This example shows how to modify all Privilege Rights from a given GPO.
            Each parameter uses an Array with members named after the parameter.

        .PARAMETER GpoToModify
            Name of the GPO which will get the Privilege Right modification.

        .PARAMETER NetworkLogon
            Identity (SamAccountName) to be GRANTED the right "Access this computer from the network

        .PARAMETER DenyNetworkLogon
            Identity (SamAccountName) to configure the right "Deny access this computer from the network

        .PARAMETER InteractiveLogon
            Identity (SamAccountName) to be GRANTED the right "Allow Log On Locally"

        .PARAMETER DenyInteractiveLogon
            Identity (SamAccountName) to configure the right "Deny Log On Locally"

        .PARAMETER RemoteInteractiveLogon
            Identity (SamAccountName) to be GRANTED the right "Allow Log On through Remote Desktop Services"

        .PARAMETER DenyRemoteInteractiveLogon
            Identity (SamAccountName) to configure the right "Deny Log On through Remote Desktop Services"

        .PARAMETER BatchLogon
            Identity (SamAccountName) to be GRANTED the right "Log On as a Batch Job"

        .PARAMETER DenyBatchLogon
            Identity (SamAccountName) to configure the right "Deny Log On as a Batch Job"

        .PARAMETER ServiceLogon
            Identity (SamAccountName) to be GRANTED the right "Log On as a Service"

        .PARAMETER DenyServiceLogon
            Identity (SamAccountName) to configure the right "Deny Log On as a Service"

        .PARAMETER MachineAccount
            Identity (SamAccountName) to configure the right "Add workstations to Domain (Domain Join)".

        .PARAMETER IncreaseQuota
            Identity (SamAccountName) to configure the right "Adjust memory quotas for a process".

        .PARAMETER Backup
            Identity (SamAccountName) to configure the right "Back up files and directories".

        .PARAMETER ChangeNotify
            Identity (SamAccountName) to configure the right "Bypass traverse checking".

        .PARAMETER SystemTime
            Identity (SamAccountName) to configure the right "Change the system time".

        .PARAMETER TimeZone
            Identity (SamAccountName) to configure the right "Change the time zone".

        .PARAMETER CreatePagefile
            Identity (SamAccountName) to configure the right "Create a pagefile".

        .PARAMETER CreateGlobal
            Identity (SamAccountName) to configure the right "Create global objects".

        .PARAMETER CreateSymbolicLink
            Identity (SamAccountName) to configure the right "Create symbolic links".

        .PARAMETER EnableDelegation
            Identity (SamAccountName) to configure the right "Enable computer and user accounts to be trusted for delegation".

        .PARAMETER RemoteShutdown
            Identity (SamAccountName) to configure the right "Force shutdown from a remote system".

        .PARAMETER Audit
            Identity (SamAccountName) to configure the right "Generate security audits".

        .PARAMETER Impersonate
            Identity (SamAccountName) to configure the right "Impersonate a client after authentication".

        .PARAMETER IncreaseWorkingSet
            Identity (SamAccountName) to configure the right "Increase a process working set".

        .PARAMETER IncreaseBasePriority
            Identity (SamAccountName) to configure the right "Increase scheduling priority".

        .PARAMETER LoadDriver
            Identity (SamAccountName) to configure the right "Load and unload device drivers".

        .PARAMETER AuditSecurity
            Identity (SamAccountName) to configure the right "Manage auditing and security log".

        .PARAMETER Relabel
            Identity (SamAccountName) to configure the right "Modify an object label".

        .PARAMETER SystemEnvironment
            Identity (SamAccountName) to configure the right "Modify firmware environment values".

        .PARAMETER DelegateSessionUserImpersonate
            Identity (SamAccountName) to configure the right "Obtain an impersonation token for another user in the same session".

        .PARAMETER ManageVolume
            Identity (SamAccountName) to configure the right "Perform volume maintenance tasks".

        .PARAMETER ProfileSingleProcess
            Identity (SamAccountName) to configure the right "Profile single process".

        .PARAMETER SystemProfile
            Identity (SamAccountName) to configure the right "Profile system performance".

        .PARAMETER Undock
            Identity (SamAccountName) to configure the right "Remove computer from docking station".

        .PARAMETER AssignPrimaryToken
            Identity (SamAccountName) to configure the right "Replace a process level token".

        .PARAMETER Restore
            Identity (SamAccountName) to configure the right "Restore files and directories".

        .PARAMETER Shutdown
            Identity (SamAccountName) to configure the right "Shut down the system".

        .PARAMETER SyncAgent
            Identity (SamAccountName) to configure the right "Synchronize directory service data".

        .PARAMETER TakeOwnership
            Identity (SamAccountName) to configure the right "Take ownership of files or other objects".

        .OUTPUTS
            System.Void        .INPUTS
            System.String, System.Collections.Generic.List[Object]

        .OUTPUTS
            System.Void

        .NOTES
            Required Modules:
            - GroupPolicy
            - ActiveDirectory
            - EguibarIT
            - EguibarIT.DelegationPS

            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-GPO                                    ║ GroupPolicy
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Convert-SidToName                          ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Get-GptTemplate                            ║ EguibarIT.DelegationPS
                Set-GPOConfigSection                       ║ EguibarIT.DelegationPS
                Update-GpoVersion                          ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Add-Right                                  ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.3
            DateModified:    20/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar Information Technology S.L.
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            GroupPolicy

        .ROLE
            Security Configuration

        .FUNCTIONALITY
            Group Policy Rights Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([System.Void])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the GPO which will get the Privilege Right modification.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GpoToModify,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Access this computer from the network".',
            Position = 1)]
        [System.Collections.Generic.List[object]]
        $NetworkLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny access this computer from the network".',
            Position = 2)]
        [System.Collections.Generic.List[object]]
        $DenyNetworkLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Allow Log On Locally"',
            Position = 3)]
        [System.Collections.Generic.List[object]]
        $InteractiveLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be DENIED the right "Allow Log On Locally"',
            Position = 4)]
        [System.Collections.Generic.List[object]]
        $DenyInteractiveLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Allow Log On through Remote Desktop Services".',
            Position = 5)]
        [System.Collections.Generic.List[object]]
        $RemoteInteractiveLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be DENIED the right "Allow Log On through Remote Desktop Services".',
            Position = 6)]
        [System.Collections.Generic.List[object]]
        $DenyRemoteInteractiveLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Log On as a Batch Job".',
            Position = 7)]
        [System.Collections.Generic.List[object]]
        $BatchLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny Log On as a Batch Job".',
            Position = 8)]
        [System.Collections.Generic.List[object]]
        $DenyBatchLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Log On as a Service".',
            Position = 9)]
        [System.Collections.Generic.List[object]]
        $ServiceLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny Log On as a Service".',
            Position = 10)]
        [System.Collections.Generic.List[object]]
        $DenyServiceLogon,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Add workstations to Domain (Domain Join)".',
            Position = 11)]
        [System.Collections.Generic.List[object]]
        $MachineAccount,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Adjust memory quotas for a process".',
            Position = 12)]
        [System.Collections.Generic.List[object]]
        $IncreaseQuota,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Back up files and directories".',
            Position = 13)]
        [System.Collections.Generic.List[object]]
        $Backup,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Bypass traverse checking".',
            Position = 14)]
        [System.Collections.Generic.List[object]]
        $ChangeNotify,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Change the system time".',
            Position = 15)]
        [System.Collections.Generic.List[object]]
        $SystemTime,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Change the time zone".',
            Position = 16)]
        [System.Collections.Generic.List[object]]
        $TimeZone,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create a pagefile".',
            Position = 17)]
        [System.Collections.Generic.List[object]]
        $CreatePagefile,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create global objects".',
            Position = 18)]
        [System.Collections.Generic.List[object]]
        $CreateGlobal,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create symbolic links".',
            Position = 19)]
        [System.Collections.Generic.List[object]]
        $CreateSymbolicLink,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Enable computer and user accounts to be trusted for delegation".',
            Position = 20)]
        [System.Collections.Generic.List[object]]
        $EnableDelegation,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Force shutdown from a remote system".',
            Position = 21)]
        [System.Collections.Generic.List[object]]
        $RemoteShutdown,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Generate security audits".',
            Position = 22)]
        [System.Collections.Generic.List[object]]
        $Audit,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Impersonate a client after authentication".',
            Position = 23)]
        [System.Collections.Generic.List[object]]
        $Impersonate,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Increase a process working set".',
            Position = 24)]
        [System.Collections.Generic.List[object]]
        $IncreaseWorkingSet,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Increase scheduling priority".',
            Position = 25)]
        [System.Collections.Generic.List[object]]
        $IncreaseBasePriority,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Load and unload device drivers".',
            Position = 26)]
        [System.Collections.Generic.List[object]]
        $LoadDriver,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Manage auditing and security log".',
            Position = 27)]
        [System.Collections.Generic.List[object]]
        $AuditSecurity,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Modify an object label".',
            Position = 28)]
        [System.Collections.Generic.List[object]]
        $Relabel,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Modify firmware environment values".',
            Position = 29)]
        [System.Collections.Generic.List[object]]
        $SystemEnvironment,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Obtain an impersonation token for another user in the same session".',
            Position = 30)]
        [System.Collections.Generic.List[object]]
        $DelegateSessionUserImpersonate,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Perform volume maintenance tasks".',
            Position = 31)]
        [System.Collections.Generic.List[object]]
        $ManageVolume,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Profile single process".',
            Position = 32)]
        [System.Collections.Generic.List[object]]
        $ProfileSingleProcess,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Profile system performance".',
            Position = 33)]
        [System.Collections.Generic.List[object]]
        $SystemProfile,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Remove computer from docking station".',
            Position = 34)]
        [System.Collections.Generic.List[object]]
        $Undock,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Replace a process level token".',
            Position = 35)]
        [System.Collections.Generic.List[object]]
        $AssignPrimaryToken,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Restore files and directories".',
            Position = 36)]
        [System.Collections.Generic.List[object]]
        $Restore,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Shut down the system".',
            Position = 37)]
        [System.Collections.Generic.List[object]]
        $Shutdown,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Synchronize directory service data".',
            Position = 38)]
        [System.Collections.Generic.List[object]]
        $SyncAgent,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Take ownership of files or other objects".',
            Position = 39)]
        [System.Collections.Generic.List[object]]
        $TakeOwnership,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Force the operation without confirmation.')]
        [switch]
        $Force

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

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        #Create a principal object for current user
        $UserPrincipal = [System.Security.Principal.WindowsPrincipal]::New($CurrentUser)

        #Check if Administrator
        If ((-Not ($UserPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))) -and
            (-Not $PSBoundParameters.ContainsKey('WhatIf'))) {

            Write-Error -Message 'This function MUST be executed as Administrator, including elevation. Otherwise will throw errors'
            $PSCmdlet.ThrowTerminatingError()
        } #end If

        # Verify that given GPO exists.
        try {
            $Gpo = Get-GPO -Name $PSBoundParameters['GpoToModify'] -ErrorAction Stop

        } catch {

            $ErrorMessage = 'GPO "{0}" does not exist or cannot be accessed.' -f $GpoToModify
            Write-Error -Message $ErrorMessage
            throw $ErrorMessage
        } #end Try/Catch


        # Get the GptTmpl.inf content and store it in variable
        try {

            $GptTmpl = Get-GptTemplate -GpoName $PSBoundParameters['GpoToModify']

            if (($null -eq $GptTmpl) -or ($GptTmpl -isnot [IniFileHandler.IniFile])) {
                throw 'Failed to get a valid IniFileHandler.IniFile object from Get-GptTemplate'
            } #end If

        } catch {

            $ErrorMessage = 'Failed to retrieve GptTmpl.inf from GPO ''{0}'': {1}' -f $GpoToModify, $_.Exception.Message
            Write-Error -Message $ErrorMessage
            throw $ErrorMessage

        } #end Try/Catch

        # Check GPT does contains default sections ([Unicode] and [Version])
        If ( -not (($GptTmpl.SectionExists('Version')) -and
            ($GptTmpl.SectionExists('Unicode')))) {

            # Add the missing sections
            $GptTmpl.AddSection('Version')
            $GptTmpl.AddSection('Unicode')

            # Add missing Key-Value pairs
            $GptTmpl.SetKeyValue('Unicode', 'Unicode', 'yes')
            $GptTmpl.SetKeyValue('Version', 'Revision', '1')
            $GptTmpl.SetKeyValue('Version', 'signature', '$CHICAGO$')

        } #end If

        # Initialize collection for rights
        $rightsCollection = [System.Collections.Generic.List[object]]::new()

        # Log collection initialization for debugging
        Write-Debug -Message ('Initialized rights collection with capacity: {0}' -f $rightsCollection.Capacity)


    } #end Begin

    Process {
        # https://jigsolving.com/gpo-deep-dive-part-1/
        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment

        if ($PSCmdlet.ShouldProcess($PSBoundParameters['GpoToModify'], 'Set GPO Privilege Rights')) {

            # Ensure collection is the correct type before calling Add-EmptyPrivilegeRight
            if ($null -eq $rightsCollection -or -not ($rightsCollection -is [System.Collections.Generic.List[object]])) {

                Write-Verbose -Message '[DEBUG] Reinitializing rightsCollection as List[object]'
                $rightsCollection = [System.Collections.Generic.List[object]]::new()

            } #end If

            ################################################################################
            # Keep empty due to security concerns

            # Call the refactored external function that avoids parameter binding issues
            Add-EmptyPrivilegeRightLocal -Collection $rightsCollection

            ################################################################################
            # Logon restrictions and Rights (following Tier implementation)

            # Add parameter-based rights
            Add-ParameterBasedRight -Collection $rightsCollection -BoundParameters $PSBoundParameters


            ################################################################################
            # Process all the Rights

            foreach ($right in $rightsCollection) {

                try {
                    $gpoconfigParams = @{
                        CurrentSection = $right.Section
                        CurrentKey     = $right.Key
                        Members        = $right.Members
                        GptTmpl        = $GptTmpl
                    }

                    $GptTmpl = Set-GPOConfigSection @gpoconfigParams

                    Write-Debug -Message ('Updated privilege right: {0} - {1}' -f
                        $right.Key, $right.Description)

                } catch {

                    Write-Error -Message ('Failed to update privilege right {0}: {1}' -f
                        $right.Key, $_.Exception.Message)

                } #end try-catch

            } #end Foreach


            # Save INI file
            Try {

                $GptTmpl.SaveFile()
                Write-Verbose -Message ('Saving changes to GptTmpl.inf file of GPO {0}' -f $PSBoundParameters['GpoToModify'])

            } Catch {

                $ErrorMessage = 'Failed to save GptTmpl.inf file: {0}' -f $_.Exception.Message
                Write-Error -Message $ErrorMessage
                throw $ErrorMessage

            } Finally {

                if ($null -ne $GptTmpl) {

                    $GptTmpl.Dispose()
                    Write-Verbose -Message 'Disposed GptTmpl object'

                } #end If
            } #end Try-Catch-Finally

            # Increment Version
            # Get path to the GPTs.ini file. Increment to make changes.
            Write-Verbose -Message ('Updating GPO version for {0}' -f $PSBoundParameters['GpoToModify'])
            Update-GpoVersion -GpoName $PSBoundParameters['GpoToModify']

        } #end If ShouldProcess
    } #end Process

    End {
        if ($null -ne $Variables -and $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'delegating Privileged Rights on GPO.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end END
} #end Function Set-GpoPrivilegeRight
