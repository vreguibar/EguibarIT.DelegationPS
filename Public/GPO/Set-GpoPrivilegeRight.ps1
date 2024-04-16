Function Set-GpoPrivilegeRight {
    <#
        .Synopsis
            Set the Privileged Rights into a Group Policy Objects (MUST be executed on DomainController)
        .DESCRIPTION
            The function will modify the Privileged Rights into a Group Policy Object based on the Delegation Model with Tiers
        .EXAMPLE
            Set-GpoPrivilegeRight "Default Domain" "SL_InfraRight"
        .EXAMPLE
            Set-GpoPrivilegeRight -GpoToModify "Default Domain" -NetworkLogon "SL_InfraRight"
        .PARAMETER GpoToModify
            [STRING] Name of the GPO which will get the Restricted Groups modification.
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
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
                Get-ExtendedRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    07/Dec/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the GPO which will get the Privilege Right modification.',
            Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GpoToModify,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Access this computer from the network".',
            Position = 1)]
        [System.String[]]
        $NetworkLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny access this computer from the network".',
            Position = 2)]
        [System.String[]]
        $DenyNetworkLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Allow Log On Locally"',
            Position = 3)]
        [System.String[]]
        $InteractiveLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be DENIED the right "Allow Log On Locally"',
            Position = 4)]
        [System.String[]]
        $DenyInteractiveLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Allow Log On through Remote Desktop Services".',
            Position = 5)]
        [System.String[]]
        $RemoteInteractiveLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be DENIED the right "Allow Log On through Remote Desktop Services".',
            Position = 6)]
        [System.String[]]
        $DenyRemoteInteractiveLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Log On as a Batch Job".',
            Position = 7)]
        [System.String[]]
        $BatchLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny Log On as a Batch Job".',
            Position = 8)]
        [System.String[]]
        $DenyBatchLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to be GRANTED the right "Log On as a Service".',
            Position = 9)]
        [System.String[]]
        $ServiceLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Deny Log On as a Service".',
            Position = 10)]
        [System.String[]]
        $DenyServiceLogon,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Add workstations to Domain (Domain Join)".',
            Position = 11)]
        [System.String[]]
        $MachineAccount,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Adjust memory quotas for a process".',
            Position = 12)]
        [System.String[]]
        $IncreaseQuota,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Back up files and directories".',
            Position = 13)]
        [System.String[]]
        $Backup,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Bypass traverse checking".',
            Position = 14)]
        [System.String[]]
        $ChangeNotify,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Change the system time".',
            Position = 15)]
        [System.String[]]
        $SystemTime,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Change the time zone".',
            Position = 16)]
        [System.String[]]
        $TimeZone,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create a pagefile".',
            Position = 17)]
        [System.String[]]
        $CreatePagefile,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create global objects".',
            Position = 18)]
        [System.String[]]
        $CreateGlobal,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Create symbolic links".',
            Position = 19)]
        [System.String[]]
        $CreateSymbolicLink,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Enable computer and user accounts to be trusted for delegation".',
            Position = 20)]
        [System.String[]]
        $EnableDelegation,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Force shutdown from a remote system".',
            Position = 21)]
        [System.String[]]
        $RemoteShutdown,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Generate security audits".',
            Position = 22)]
        [System.String[]]
        $Audit,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Impersonate a client after authentication".',
            Position = 23)]
        [System.String[]]
        $Impersonate,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Increase a process working set".',
            Position = 24)]
        [System.String[]]
        $IncreaseWorkingSet,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Increase scheduling priority".',
            Position = 25)]
        [System.String[]]
        $IncreaseBasePriority,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Load and unload device drivers".',
            Position = 26)]
        [System.String[]]
        $LoadDriver,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Manage auditing and security log".',
            Position = 27)]
        [System.String[]]
        $AuditSecurity,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Modify an object label".',
            Position = 28)]
        [System.String[]]
        $Relabel,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Modify firmware environment values".',
            Position = 29)]
        [System.String[]]
        $SystemEnvironment,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Obtain an impersonation token for another user in the same session".',
            Position = 30)]
        [System.String[]]
        $DelegateSessionUserImpersonate,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Perform volume maintenance tasks".',
            Position = 31)]
        [System.String[]]
        $ManageVolume,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Profile single process".',
            Position = 32)]
        [System.String[]]
        $ProfileSingleProcess,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Profile system performance".',
            Position = 33)]
        [System.String[]]
        $SystemProfile,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Remove computer from docking station".',
            Position = 34)]
        [System.String[]]
        $Undock,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Replace a process level token".',
            Position = 35)]
        [System.String[]]
        $AssignPrimaryToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Restore files and directories".',
            Position = 36)]
        [System.String[]]
        $Restore,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Shut down the system".',
            Position = 37)]
        [System.String[]]
        $Shutdown,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Synchronize directory service data".',
            Position = 38)]
        [System.String[]]
        $SyncAgent,

        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (SamAccountName) to configure the right "Take ownership of files or other objects".',
            Position = 39)]
        [System.String[]]
        $TakeOwnership

    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()
        $ArrayList = [System.Collections.ArrayList]::New()




        # Variable representing the GPO template file (GptTmpl.inf)
        [System.Collections.Hashtable]$GptTmpl = [ordered]@{}

        # Get the GPO and include brackets {}
        $GpoId = '{' + (Get-GPO -Name $GpoToModify).Id + '}'

        # Get the SysVol path from registry
        $SysVolPath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' -Name sysvol).SysVol
        Write-Verbose -Message (' ...Sysvol path: {0}' -f $SysVolPath)

        # Get path where the GptTmpl.inf file should be stored
        $PathToGptTmpl = '{0}\{1}\Policies\{2}\Machine\microsoft\windows nt\SecEdit' -f $SysVolPath, $Variables.DnsFqdn, $GpoId
        Write-Verbose -Message (' ...GPT template file: {0}' -f $PathToGptTmpl)

        # If the folder does not exist yet, it will be created. If the folder exists already, the line will be ignored
        New-Item $PathToGptTmpl -ItemType Directory -ErrorAction SilentlyContinue

        # Get full path + filename
        $GptTmplFile = '{0}\GptTmpl.inf' -f $PathToGptTmpl

        # If file exist, get its content
        If (Test-Path -Path $GptTmplFile) {
            try {
                $GptTmpl = Get-IniContent -FilePath $GptTmplFile
                Write-Verbose -Message (' ...GPT template file retrieved succesfully: {0}' -f $PathToGptTmpl)
            } Catch {
                Throw
            } #end TRY
        } #end If

        # Verify if the GptTmpl.inf file exists by checking existing data
        If (-not ($GptTmpl.Contains('Version') -or
                $GptTmpl.Contains('Unicode'))) {

            # Add Section "Version" with first Key/Value pair
            $GptTmpl.Add('Version', [ordered]@{})

            # Add second Key/Value
            $GptTmpl['Version'].Add('signature', '"$CHICAGO$"')
            $GptTmpl['Version'].Add('Revision', '1')

            # Add Unicode Section
            $GptTmpl.Add('Unicode', [ordered]@{})

            # Add second Key/Value
            $GptTmpl['Unicode'].Add('Unicode', 'yes')
        } #end IF

    } #end Begin

    Process {

        # https://jigsolving.com/gpo-deep-dive-part-1/
        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment

        ################################################################################
        # Keep empty due to security concerns

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/access-credential-manager-as-a-trusted-caller
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeTrustedCredManAccessPrivilege'
            Members     = ''
            Description = 'Access Credential Manager as a trusted caller'
        }
        $ArrayList.Add($Splat)

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeTcbPrivilege'
            Members     = ''
            Description = 'Act as part of the operating system'
        }
        $ArrayList.Add($Splat)

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/create-a-token-object
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeCreateTokenPrivilege'
            Members     = ''
            Description = 'Create a token object'
        }
        $ArrayList.Add($Splat)

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/create-permanent-shared-objects
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeCreatePermanentPrivilege'
            Members     = ''
            Description = 'Create permanent shared objects'
        }
        $ArrayList.Add($Splat)

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/debug-programs
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeDebugPrivilege'
            Members     = ''
            Description = 'Debug Programs'
        }
        $ArrayList.Add($Splat)

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/lock-pages-in-memory
        $Splat = @{
            IniData     = $GptTmpl
            Section     = 'Privilege Rights'
            Key         = 'SeLockMemoryPrivilege'
            Members     = ''
            Description = 'Lock pages in memory'
        }
        $ArrayList.Add($Splat)





        ################################################################################
        # Logon restrictions (following Tier implementation)
        # PSBoundParameters for NetworkLogon, DenyNetworkLogon...

        # NetworkLogon
        If ($PSBoundParameters.ContainsKey('NetworkLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeNetworkLogonRight'
                Members     = $NetworkLogon
                Description = 'Access this computer from the network'
            }
            $ArrayList.Add($Splat)
        } #end If

        # DENY NetworkLogon
        If ($PSBoundParameters.ContainsKey('DenyNetworkLogon')) {

            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDenyNetworkLogonRight'
                Members     = $DenyNetworkLogon
                Description = 'Deny access to this computer from the network'
            }
            $ArrayList.Add($Splat)
        } #end If

        # InteractiveLogon
        If ($PSBoundParameters.ContainsKey('InteractiveLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeInteractiveLogonRight'
                Members     = $InteractiveLogon
                Description = 'Allow log on locally'
            }
            $ArrayList.Add($Splat)
        } #end If

        # DENY InteractiveLogon
        If ($PSBoundParameters.ContainsKey('DenyInteractiveLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDenyInteractiveLogonRight'
                Members     = $DenyInteractiveLogon
                Description = 'Deny log on locally'
            }
            $ArrayList.Add($Splat)
        } #end If

        # RemoteInteractiveLogon (RDP)
        If ($PSBoundParameters.ContainsKey('RemoteInteractiveLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeRemoteInteractiveLogonRight'
                Members     = $RemoteInteractiveLogon
                Description = 'Allow log on through Remote Desktop Services'
            }
            $ArrayList.Add($Splat)
        } #end If

        # DENY RemoteInteractiveLogon (RDP)
        If ($PSBoundParameters.ContainsKey('DenyRemoteInteractiveLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDenyRemoteInteractiveLogonRight'
                Members     = $DenyRemoteInteractiveLogon
                Description = 'Deny log on through Remote Desktop Services'
            }
            $ArrayList.Add($Splat)
        } #end If

        # BatchLogon
        If ($PSBoundParameters.ContainsKey('BatchLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeBatchLogonRight'
                Members     = $BatchLogon
                Description = 'Log on as a batch job'
            }
            $ArrayList.Add($Splat)
        } #end If

        # DENY BatchLogon
        If ($PSBoundParameters.ContainsKey('DenyBatchLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDenyBatchLogonRight'
                Members     = $DenyBatchLogon
                Description = 'Deny log on as a batch job'
            }
            $ArrayList.Add($Splat)
        } #end If

        # ServiceLogon
        If ($PSBoundParameters.ContainsKey('ServiceLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeServiceLogonRight'
                Members     = $ServiceLogon
                Description = 'Log on as a service'
            }
            $ArrayList.Add($Splat)
        } #end If

        # DENY ServiceLogon
        If ($PSBoundParameters.ContainsKey('DenyServiceLogon')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDenyServiceLogonRight'
                Members     = $DenyServiceLogon
                Description = 'Deny log on as a service'
            }
            $ArrayList.Add($Splat)
        } #end If





        ################################################################################
        # Remaining rights

        # Add workstations to domain
        If ($PSBoundParameters.ContainsKey('MachineAccount')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeMachineAccountPrivilege'
                Members     = $MachineAccount
                Description = 'Add workstations to domain'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Adjust memory quotas for a process
        If ($PSBoundParameters.ContainsKey('IncreaseQuota')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeIncreaseQuotaPrivilege'
                Members     = $IncreaseQuota
                Description = 'Adjust memory quotas for a process'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Back up files and directories
        If ($PSBoundParameters.ContainsKey('Backup')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeBackupPrivilege'
                Members     = $Backup
                Description = 'Back up files and directories'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Bypass traverse checking
        If ($PSBoundParameters.ContainsKey('ChangeNotify')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeChangeNotifyPrivilege'
                Members     = $ChangeNotify
                Description = 'Bypass traverse checking'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Change the system time
        If ($PSBoundParameters.ContainsKey('Systemtime')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeSystemtimePrivilege'
                Members     = $Systemtime
                Description = 'Change the system time'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Change the time zone
        If ($PSBoundParameters.ContainsKey('TimeZone')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeTimeZonePrivilege'
                Members     = $SeTimeZonePrivilege
                Description = 'Change the time zone'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Create a pagefile
        If ($PSBoundParameters.ContainsKey('CreatePagefile')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeCreatePagefilePrivilege'
                Members     = $CreatePagefile
                Description = 'Create a pagefile'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Create global objects
        If ($PSBoundParameters.ContainsKey('CreateGlobal')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeCreateGlobalPrivilege'
                Members     = $CreateGlobal
                Description = 'Create global objects'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Create symbolic links
        If ($PSBoundParameters.ContainsKey('CreateSymbolicLink')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeCreateSymbolicLinkPrivilege'
                Members     = $CreateSymbolicLink
                Description = 'Create symbolic links'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Enable computer and user accounts to be trusted for delegation
        If ($PSBoundParameters.ContainsKey('EnableDelegation')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeEnableDelegationPrivilege'
                Members     = $EnableDelegation
                Description = 'Enable computer and user accounts to be trusted for delegation'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Force shutdown from a remote system
        If ($PSBoundParameters.ContainsKey('RemoteShutdown')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeRemoteShutdownPrivilege'
                Members     = 'RemoteShutdown'
                Description = 'Force shutdown from a remote system'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Generate security audits
        If ($PSBoundParameters.ContainsKey('Audit')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeAuditPrivilege'
                Members     = $Audit
                Description = 'Generate security audits'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Impersonate a client after authentication
        If ($PSBoundParameters.ContainsKey('Impersonate')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeImpersonatePrivilege'
                Members     = $Impersonate
                Description = 'Impersonate a client after authentication'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Increase a process working set
        If ($PSBoundParameters.ContainsKey('IncreaseWorkingSet')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeIncreaseWorkingSetPrivilege'
                Members     = $IncreaseWorkingSet
                Description = 'Increase a process working set'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Increase scheduling priority
        If ($PSBoundParameters.ContainsKey('IncreaseBasePriority')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeIncreaseBasePriorityPrivilege'
                Members     = $IncreaseBasePriority
                Description = 'Increase scheduling priority'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Load and unload device drivers
        If ($PSBoundParameters.ContainsKey('LoadDriver')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeLoadDriverPrivilege'
                Members     = $LoadDriver
                Description = 'Load and unload device drivers'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Manage auditing and security log
        If ($PSBoundParameters.ContainsKey('AuditSecurity')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeSecurityPrivilege'
                Members     = $AuditSecurity
                Description = 'Manage auditing and security log'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Modify an object label
        If ($PSBoundParameters.ContainsKey('Relabel')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeRelabelPrivilege'
                Members     = $Relabel
                Description = 'Modify an object label'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Modify firmware environment values
        If ($PSBoundParameters.ContainsKey('SystemEnvironment')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeSystemEnvironmentPrivilege'
                Members     = $SystemEnvironment
                Description = 'Modify firmware environment values'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Obtain an impersonation token for another user in the same session
        If ($PSBoundParameters.ContainsKey('DelegateSessionUserImpersonate')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeDelegateSessionUserImpersonatePrivilege'
                Members     = $DelegateSessionUserImpersonate
                Description = 'Obtain an impersonation token for another user in the same session'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Perform volume maintenance tasks
        If ($PSBoundParameters.ContainsKey('ManageVolume')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeManageVolumePrivilege'
                Members     = $ManageVolume
                Description = 'Perform volume maintenance tasks'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Profile single process
        If ($PSBoundParameters.ContainsKey('ProfileSingleProcess')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeProfileSingleProcessPrivilege'
                Members     = $ProfileSingleProcess
                Description = 'Profile single process'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Profile system performance
        If ($PSBoundParameters.ContainsKey('SystemProfile')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeSystemProfilePrivilege'
                Members     = $SystemProfile
                Description = 'Profile system performance'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Remove computer from docking station
        If ($PSBoundParameters.ContainsKey('Undock')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeUndockPrivilege'
                Members     = $Undock
                Description = 'Remove computer from docking station'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Replace a process level token
        If ($PSBoundParameters.ContainsKey('AssignPrimaryToken')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeAssignPrimaryTokenPrivilege'
                Members     = $AssignPrimaryToken
                Description = 'Replace a process level token'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Restore files and directories
        If ($PSBoundParameters.ContainsKey('Restore')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeRestorePrivilege'
                Members     = $Restore
                Description = 'Restore files and directories'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Shut down the system
        If ($PSBoundParameters.ContainsKey('Shutdown')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeShutdownPrivilege'
                Members     = $Shutdown
                Description = 'Shut down the system'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Synchronize directory service data
        If ($PSBoundParameters.ContainsKey('SyncAgent')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeSyncAgentPrivilege'
                Members     = $SyncAgent
                Description = 'Synchronize directory service data'
            }
            $ArrayList.Add($Splat)
        } #end If

        # Take ownership of files or other objects
        If ($PSBoundParameters.ContainsKey('TakeOwnership')) {
            $Splat = @{
                IniData     = $GptTmpl
                Section     = 'Privilege Rights'
                Key         = 'SeTakeOwnershipPrivilege'
                Members     = $TakeOwnership
                Description = 'Take ownership of files or other objects'
            }
            $ArrayList.Add($Splat)
        } #end If





        ################################################################################
        # Process all the Rights

        Foreach ($item in $ArrayList) {

            Try {

                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], ('Delegate the permisssions for "{0}"?') -f $item.Description)) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "{1}" section of the GPO' -f ($Item.Members -join '; '), $item.Description)

            } Catch {

                Write-Error -Message ('Error while configuring "{0}" on GPO' -f $item.Description)
                Throw

            } #end Try-Catch

        } #end Foreach





        # Save INI file
        Try {
            $GptTmpl | Out-IniFile -FilePath $GptTmplFile -Encoding 'Unicode' -Force
            Write-Verbose -Message ('Saving changes to file {0}' -f $GptTmplFile)
        } Catch {
            Throw 'The GptTmpl.inf file could not be saved: {0}. Message is {1}', $_, $_.Message
        }

        # Increment Version
        # Get path to the GPTs.ini file. Increment to make changes.
        $PathToGpt = '{0}\{1}\Policies\{2}\gpt.ini' -f $SysVolPath, $Variables.DnsFqdn, $GpoId

        try {
            # Get the GPO object
            $de = New-Object System.DirectoryServices.DirectoryEntry('LDAP://CN={0},CN=Policies,CN=System,{1}' -f $GpoId, $Variables.defaultNamingContext)

            # Get the VersionObject of the DirectoryEntry (the GPO)
            $VersionObject = [Int64]($de.Properties['VersionNumber'].Value.ToString())

            Write-Verbose -Message ('Old GPO Version Number: {0}' -f $VersionObject)

            # Convert the value into a 8 digit HEX string
            $HexValue = $VersionObject.ToString('x8')

            # Top 16 bits HEX UserVersionNumber - first 4 characters (complete with zero to the left)
            # This is the UserVersion
            $HexUserVN = $HexValue.Substring(0, 4)

            # Lower 16 bits HEX ComputerVersionNumber - last 4 characters (complete with zero to the left)
            # This is the ComputerVersion
            $HexComputerVN = $HexValue.Substring(4)

            #Top 16 bits as Integer UserVersionNumber. Not used because these changes are only related to Computer
            #$UserVN = [Convert]::ToInt64($HexUserVN, 16)

            #Lower 16 bits as Integer ComputerVersionNumber
            $ComputerVN = [Convert]::ToInt64($HexComputerVN, 16)

            # Increment Computer Version Number by 3
            $ComputerVN += 3

            # Concatenate '0x' and 'HEX UserVersionNumber having 4 digits' and 'HEX ComputerVersionNumber having 4
            # digits' (0x must be added in order to indicate Hexadecimal number, otherwise fails)
            $NewHex = '0x{0}{1}' -f $HexUserVN, $ComputerVN.ToString('x4')

            # Convert the New Hex number to integer
            $NewVersionObject = [Convert]::ToInt64($NewHex, 16)

            #Update the GPO VersionNumber with the new value
            $de.Properties['VersionNumber'].Value = $NewVersionObject.ToString()

            # Save the information on the DirectoryObject
            $de.CommitChanges();

            #Close the DirectoryEntry
            $de.Close()

            # Write new version value to GPT (Including Section Name)
            # Check path to file
            If (Test-Path -Path $PathToGpt) {
                # Create Hashtable with corresponding data
                $Gpt = @{'General' = @{'Version' = $NewVersionObject.ToString() } }

                # Save Hashtable to the GPT.INI file
                $Gpt | Out-IniFile -FilePath $PathToGpt -Force

                Write-Verbose -Message ('Saving new Version of GPO to file {0}' -f $PathToGpt)
            } #end IF

        } catch {

            #Console.WriteLine("An error occurred: '{0}'", ex.Message);
            throw 'The GPTs.ini file could not be modified: {0}. Message is {1}', $_, $_.Message
        } finally {

            Write-Verbose -Message ('Version of GPO updated. Original Number: {0}. New Number: {1}' -f $VersionObject.ToString(), $NewVersionObject.ToString())
        } #end Try
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Privileged Rights."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} #end Function
