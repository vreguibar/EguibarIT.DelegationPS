Function Add-GroupToSCManager {
    <#
        .Synopsis
            Adds a group to the Service Control Manager (SCM) ACL.

        .DESCRIPTION
            This function adds a specified group to the Service Control Manager (SCM) ACL with specified permissions.
            It modifies the SCM security descriptor to include the group with specific access rights.

        .EXAMPLE
            Add-GroupToSCManager -Group "SG_AdAdmins"

        .EXAMPLE
            Add-GroupToSCManager -Group "SG_AdAdmins" -computer DC1

        .EXAMPLE
            $Splat = @{
                Group    = "SG_AdAdmins"
                Computer = DC1
                Verbose  = $true
            }
            Add-GroupToSCManager @Splat

        .PARAMETER Group
            Specifies the group to be added to the SCM ACL.

        .PARAMETER Computer
            Remote computer to execute the commands.

        .PARAMETER Force
            If present, the function will not ask for confirmation when performing actions.

        .NOTES
            This function relies on SC.exe located at $env:SystemRoot\System32\

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-AdObjectType                       | EguibarIT.DelegationPS
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    23/May/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM2 STRING for the Remote Computer Name
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName', 'ComputerName')]
        $Computer,

        # PARAM3 SWITCH to force operations without confirmation
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 2)]
        [Switch]
        $Force
    )

    Begin {

        Set-StrictMode -Version Latest

        $error.clear()

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderDelegation) {

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

        # Save current error action preference
        $savedErrorActionPreference = $ErrorActionPreference

        # Set to Continue to avoid terminating errors
        $ErrorActionPreference = 'Continue'

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        # Get group SID
        $GroupSID = $CurrentGroup.SID.Value

        # Make sure computer has 'sc.exe'. sc.exe supports remoting by giving \\computername
        $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"

        # Map permissions to access rights using enum values
        # https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
        $permissionMap = @{
            'FullControl'    = (
                [ServiceControlManagerFlags]::SC_MANAGER_ALL_ACCESS -bor
                [ServiceControlManagerFlags]::READ_CONTROL -bor
                [ServiceControlManagerFlags]::WRITE_DAC -bor
                [ServiceControlManagerFlags]::WRITE_OWNER -bor
                [ServiceControlManagerFlags]::DELETE
            )
            'ReadAndExecute' = (
                [ServiceControlManagerFlags]::SC_MANAGER_CONNECT -bor
                [ServiceControlManagerFlags]::SC_MANAGER_ENUMERATE_SERVICE -bor
                [ServiceControlManagerFlags]::SC_MANAGER_LOCK -bor
                [ServiceControlManagerFlags]::SC_MANAGER_QUERY_LOCK_STATUS -bor
                [ServiceControlManagerFlags]::READ_CONTROL -bor
                [ServiceControlManagerFlags]::Generic_Execute
            )
            'Read'           = (
                [ServiceControlManagerFlags]::SC_MANAGER_CONNECT -bor
                [ServiceControlManagerFlags]::SC_MANAGER_ENUMERATE_SERVICE -bor
                [ServiceControlManagerFlags]::READ_CONTROL
            )
            'Write'          = [ServiceControlManagerFlags]::SC_MANAGER_CREATE_SERVICE
            'Start'          = [ServiceControlManagerFlags]::SC_MANAGER_CONNECT
            'Stop'           = [ServiceControlManagerFlags]::SC_MANAGER_CONNECT
        }
    } #end Begin

    Process {
        # Get current 'Service Control Manager (SCM)' acl in SDDL format
        Write-Verbose -Message 'Get current "Service Control Manager (SCM)" acl in SDDL format'

        $MySDDL = if ($Computer) {
            (& $ServiceControlCmd.Definition @("\\$Computer", 'sdshow', 'scmanager'))[1]
        } else {
            (& $ServiceControlCmd.Definition @('sdshow', 'scmanager'))[1]
        } #end If-Else

        Write-Verbose -Message ('Retrieved SDDL: {0}' -f $MySDDL)

        # Build the Common Security Descriptor from SDDL
        Write-Verbose -Message 'Build the Common Security Descriptor from SDDL'
        $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $False, $MySDDL)

        # Add new DACL
        Write-Verbose -Message 'Add new DACL'
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Add group from SCM?')) {

            try {
                $Permission.DiscretionaryAcl.AddAccess(
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Security.Principal.SecurityIdentifier]"$($GroupSID)",
                    $permissionMap['FullControl'], # int accessMask
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None
                )

                $message = 'Successfully Added AccessControlType Allow for {0}'
                Write-Verbose -Message ($message -f $PSBoundParameters['Group'])
            } catch {
                $errorMessage = 'Failed to add access because {0}'
                Write-Error -Message ($errorMessage -f $_.Exception.Message)
            } #end Try-Catch

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $accessControlSections = [System.Security.AccessControl.AccessControlSections]::All
                $sddl = $Permission.GetSddlForm($accessControlSections)

                # Use sc.exe to set the SDDL directly
                # This approach avoids using Set-Acl which requires administrative privileges
                If ($Computer) {
                    $scArgs = @("\\$Computer", 'sdset', 'scmanager', "$sddl")
                    $result = & $ServiceControlCmd.Definition $scArgs
                } else {
                    $scArgs = @('sdset', 'scmanager', "$sddl")
                    $result = & $ServiceControlCmd.Definition $scArgs
                }

                # Check if the operation was successful
                if ($LASTEXITCODE -eq 0 -or $result -match 'SUCCESS') {
                    Write-Verbose -Message 'Successfully set ACL in Service Control Manager'
                } else {
                    $failMessage = 'Failed to set Security in the Service Control Manager: {0}'
                    Write-Error -Message ($failMessage -f $result)
                }
            } catch {
                $failExMessage = 'Failed to set Security in the Service Control Manager because {0}'
                Write-Error -Message ($failExMessage -f $_.Exception.Message)
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        # Restore previous error action preference
        $ErrorActionPreference = $savedErrorActionPreference

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'adding Service Control Manager (SCM) access.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end Function Add-GroupToSCManager
