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
        $DenyServiceLogon

    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

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

        # PSBoundParameters for NetworkLogon, DenyNetworkLogon...

        # NetworkLogon
        If ($PSBoundParameters.ContainsKey('NetworkLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeNetworkLogonRight'
                    Members = $NetworkLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Network Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Network Logon" section of the GPO' -f ($NetworkLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Network Logon" on GPO'
                Throw
            }
        } #end If

        # DENY NetworkLogon
        If ($PSBoundParameters.ContainsKey('DenyNetworkLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeDenyNetworkLogonRight'
                    Members = $DenyNetworkLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for DENY Network Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "DENY Network Logon" section of the GPO' -f ($DenyNetworkLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "DENY Network Logon" on GPO'
                Throw
            }
        } #end If

        # InteractiveLogon
        If ($PSBoundParameters.ContainsKey('InteractiveLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeInteractiveLogonRight'
                    Members = $InteractiveLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Interactive Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Interactive Logon" section of the GPO' -f ($InteractiveLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Interactive Logon" on GPO'
                Throw
            }
        } #end If

        # DENY InteractiveLogon
        If ($PSBoundParameters.ContainsKey('DenyInteractiveLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeDenyInteractiveLogonRight'
                    Members = $DenyInteractiveLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for DENY Interactive Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Deny Interactive Logon" section of the GPO' -f ($DenyInteractiveLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Deny Interactive Logon" on GPO'
                Throw
            }
        } #end If

        # RemoteInteractiveLogon (RDP)
        If ($PSBoundParameters.ContainsKey('RemoteInteractiveLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeRemoteInteractiveLogonRight'
                    Members = $RemoteInteractiveLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Remote Interactive Logon (RDP)?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Remote Interactive Logon (RDP)" section of the GPO' -f ($RemoteInteractiveLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Remote Interactive Logon (RDP)" on GPO'
                Throw
            }
        } #end If

        # DENY RemoteInteractiveLogon (RDP)
        If ($PSBoundParameters.ContainsKey('DenyRemoteInteractiveLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeDenyRemoteInteractiveLogonRight'
                    Members = $DenyRemoteInteractiveLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for DENY Remote Interactive Logon (RDP)?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Deny Remote Interactive Logon (RDP)" section of the GPO' -f ($DenyRemoteInteractiveLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Deny Remote Interactive Logon (RDP)" on GPO'
                Throw
            }
        } #end If

        # BatchLogon
        If ($PSBoundParameters.ContainsKey('BatchLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeBatchLogonRight'
                    Members = $BatchLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Batch Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Batch Logon" section of the GPO' -f ($BatchLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Batch Logon" on GPO'
                Throw
            }
        } #end If

        # DENY BatchLogon
        If ($PSBoundParameters.ContainsKey('DenyBatchLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeDenyBatchLogonRight'
                    Members = $DenyBatchLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for DENY Batch Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Deny Batch Logon" section of the GPO' -f ($DenyBatchLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Deny Batch Logon" on GPO'
                Throw
            }
        } #end If

        # ServiceLogon
        If ($PSBoundParameters.ContainsKey('ServiceLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeServiceLogonRight'
                    Members = $ServiceLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Service Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Service Logon" section of the GPO' -f ($ServiceLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Service Logon" on GPO'
                Throw
            }
        } #end If

        # DENY ServiceLogon
        If ($PSBoundParameters.ContainsKey('DenyServiceLogon')) {
            try {
                $Splat = @{
                    IniData = $GptTmpl
                    Section = 'Privilege Rights'
                    Key     = 'SeDenyServiceLogonRight'
                    Members = $DenyServiceLogon
                }
                If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for DENY Service Logon?')) {
                    Set-IniFileSection @Splat
                } #end If
                Write-Verbose -Message ('Added members {0} to "Deny Service Logon" section of the GPO' -f ($DenyServiceLogon -join '; '))
            } catch {
                Write-Error -Message 'Error while configuring "Deny Service Logon" on GPO'
                Throw
            }
        } #end If


        # Save INI file
        Try {
            $GptTmpl | Out-IniFile -FilePath $GptTmplFile -Force
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
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} #end Function
