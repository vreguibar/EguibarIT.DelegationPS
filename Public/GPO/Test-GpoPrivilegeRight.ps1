Function Test-GpoPrivilegeRight {

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([void])]

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
        $Backup

    )

    Begin {

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $ArrayList = [System.Collections.Generic.List[object]]::New()

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        #Create a principal object for current user
        $UserPrincipal = [System.Security.Principal.WindowsPrincipal]::New($CurrentUser)

        #Check if Administrator
        If (-Not ($UserPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))) {
            Write-Error -Message 'This function MUST be executed as Administrator, including elevation. Otherwise will throw errors'
            $PSCmdlet.ThrowTerminatingError()
        }





        # Helper function to add rights
        function Add-Right {
            <#
                .SYNOPSIS
                    Adds members to a specific privilege right in the configuration.

                .DESCRIPTION
                    This function allows adding a list of members to a specified privilege right by storing
                    the information in a temporary hashtable and then appending it to an ArrayList.
                    It supports ShouldProcess for WhatIf functionality and includes detailed verbose messaging.

                .PARAMETER Key
                    The privilege right key to which the members will be assigned.

                .PARAMETER Members
                    A list of members (objects) that will be associated with the given privilege right.

                .EXAMPLE
                    Add-Right -Key 'SeBackupPrivilege' -Members @('Domain\Admins', 'Local\Backup Operators')
            #>

            [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]

            param (

                [Parameter(Mandatory = $true)]
                [string]
                $Key,

                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [AllowEmptyString()]
                [AllowEmptyCollection()]
                [System.Collections.Generic.List[object]]
                $Members
            )

            [Hashtable]$TmpHash = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

            #if ($PSCmdlet.ShouldProcess($Key, "Assign $Description")) {
            $TmpHash = @{
                iniContent = $iniContent
                Section    = 'Privilege Rights'
                Key        = $Key
                Members    = $Members
                #Description = $Description
            }
            [void]$ArrayList.Add($TmpHash)
            #}
        } #end Function Add-Right






        # Verify that given GPO exists.
        $Gpo = Get-GPO -Name $PSBoundParameters['GpoToModify'] -ErrorAction SilentlyContinue
        if (-not $Gpo) {
            throw "GPO '$GpoToModify' does not exist."
        }




        # Get the GptTmpl.inf content and store it in variable
        $GptTmpl = Get-GptTemplate -GpoName $PSBoundParameters['GpoToModify']

        if (($null -eq $GptTmpl) -or ($GptTmpl -isnot [IniFileHandler.IniFile])) {
            throw 'Failed to get a valid IniFileHandler.IniFile object from Get-GptTemplate'
        } #end If

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

    } #end Begin

    Process {
        # https://jigsolving.com/gpo-deep-dive-part-1/
        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment

        # Add rights based on provided parameters



        ################################################################################
        # Keep empty due to security concerns
        #region EmptyMemberRights

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/access-credential-manager-as-a-trusted-caller
        $Splat = @{
            Key     = 'SeTrustedCredManAccessPrivilege'
            Members = [string]::Empty
            #Description = 'Access Credential Manager as a trusted caller'
        }
        Add-Right @Splat

        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/debug-programs
        $Splat = @{
            Key     = 'SeDebugPrivilege'
            Members = [string]::Empty
            #Description = 'Debug Programs'
        }
        Add-Right @Splat

        #endregion EmptyMemberRights





        ################################################################################
        # Logon restrictions (following Tier implementation)
        # PSBoundParameters for NetworkLogon, DenyNetworkLogon...

        #region LogonRestrictions

        # NetworkLogon
        if ($PSBoundParameters.ContainsKey('NetworkLogon')) {
            Write-Verbose -Message 'GRANTING "Access this computer from the network" right...'
            $Splat = @{
                Key     = 'SeNetworkLogonRight'
                Members = $NetworkLogon
            }
            Add-Right @Splat
        } #end If

        # DENY NetworkLogon
        If ($PSBoundParameters.ContainsKey('DenyNetworkLogon')) {
            $Splat = @{
                Key     = 'SeDenyNetworkLogonRight'
                Members = $DenyNetworkLogon
                #Description = 'Deny access to this computer from the network'
            }
            Add-Right @Splat
        } #end If

        # InteractiveLogon
        If ($PSBoundParameters.ContainsKey('InteractiveLogon')) {
            $Splat = @{
                Key     = 'SeInteractiveLogonRight'
                Members = $InteractiveLogon
                #Description = 'Allow log on locally'
            }
            Add-Right @Splat
        } #end If

        # DENY InteractiveLogon
        If ($PSBoundParameters.ContainsKey('DenyInteractiveLogon')) {
            $Splat = @{
                Key     = 'SeDenyInteractiveLogonRight'
                Members = $DenyInteractiveLogon
                #Description = 'Deny log on locally'
            }
            Add-Right @Splat
        } #end If

        #endregion LogonRestrictions




        ################################################################################
        # Remaining rights

        #region RemainingRights

        # Add workstations to domain
        If ($PSBoundParameters.ContainsKey('MachineAccount')) {
            $Splat = @{
                Key     = 'SeMachineAccountPrivilege'
                Members = $MachineAccount
                #Description = 'Add workstations to domain'
            }
            Add-Right @Splat
        } #end If

        # Adjust memory quotas for a process
        If ($PSBoundParameters.ContainsKey('IncreaseQuota')) {
            $Splat = @{
                Key     = 'SeIncreaseQuotaPrivilege'
                Members = $IncreaseQuota
                #Description = 'Adjust memory quotas for a process'
            }
            Add-Right @Splat
        } #end If

        # Back up files and directories
        If ($PSBoundParameters.ContainsKey('Backup')) {
            $Splat = @{
                Key     = 'SeBackupPrivilege'
                Members = $Backup
                #Description = 'Back up files and directories'
            }
            Add-Right @Splat
        } #end If

        #endregion RemainingRights





        ################################################################################
        # Process all the Rights

        Foreach ($Rights in $ArrayList) {

            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], ('Delegate the permissions for "{0}"?') -f $Rights)) {

                # Check if [Privilege Rights] section exist. Create it if it does not exist
                If (-not $GptTmpl.SectionExists($Rights.Section)) {

                    Write-Verbose -Message ('Section "{0}" does not exist. Creating it!.' -f $Rights.Section)
                    $GptTmpl.AddSection($Rights.Section)

                } #end If



                # Add corresponding Key-Value pairs.
                # Each pair will verify proper members are added.
                Try {

                    $Splat = @{
                        CurrentSection = $Rights.Section
                        CurrentKey     = $Rights.Key
                        Members        = $Rights.members
                        GptTmpl        = $GptTmpl
                        Confirm        = $false
                    }
                    $GptTmpl = Set-GPOConfigSection @Splat

                } Catch {

                    Write-Error -Message ('
                        Something went wrong while trying to update Key-Value pairs (before Set-GPOConfigSection).
                        Section: {0}
                        Key:     {1}
                        Members: {2}
                        {3}
                        ' -f $Rights.Section, $Rights.Key, $Rights.members, $_
                    )

                } #end Try-Catch

            } #end If
        } #end Foreach


        # Save INI file
        Try {
            $GptTmpl.SaveFile()
            Write-Verbose -Message ('Saving changes to GptTmpl.inf file og GPO {0}' -f $PSBoundParameters['GpoToModify'])

        } Catch {
            Write-Error -Message ('Something went wrong while trying to save the GptTmpl.inf file...')
            ##Get-ErrorDetail -ErrorRecord $_
            Throw
        } Finally {
            $GptTmpl.Dispose()
        } #end Try-Catch-Finally

        # Increment Version
        # Get path to the GPTs.ini file. Increment to make changes.
        Write-Verbose -Message ('Updating GPO version for {0}' -f $PSBoundParameters['GpoToModify'])
        Update-GpoVersion -GpoName $PSBoundParameters['GpoToModify']

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating Privileged Rights on GPO.'
        )
        Write-Verbose -Message $txt
    } #end END
} #end Function
