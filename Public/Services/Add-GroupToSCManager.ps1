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

        .NOTES
            This function relies on SC.exe located at $env:SystemRoot\System32\

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-AdObjectType                       | EguibarIT.DelegationPS & EguibarIT.HousekeepingPS
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0
            DateModified:    20/Mar/2024
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

        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName', 'ComputerName')]
        $Computer
    )

    Begin {

        Set-StrictMode -Version Latest

        $error.clear()

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

        # get current 'Service Control Manager (SCM)' acl in SDDL format
        Write-Verbose -Message 'Get current "Service Control Manager (SCM)" acl in SDDL format'

        $MySDDL = if ($Computer) {
            (& $ServiceControlCmd.Definition @("\\$Computer", 'sdshow', 'scmanager'))[1]
        } else {
           ( & $ServiceControlCmd.Definition @('sdshow', 'scmanager'))[1]
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

                Write-Verbose -Message ('Successfully Added {0} for {1}' -f $_.AceType, $PSBoundParameters['Group'])
            } catch {
                Write-Error -Message ('Failed to add access because {0}' -f $_.Exception.Message)
            }

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $sddl = $Permission.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                If ($Computer) {
                    & $ServiceControlCmd.Definition @("\\$Computer", 'sdset', 'scmanager', "$sddl")
                } else {
                    & $ServiceControlCmd.Definition @('sdset', 'scmanager', "$sddl")
                }
                Write-Verbose -Message 'Successfully set ACL in Service Control Manager'
            } catch {
                Write-Error -Message ('Failed to set Security in the registry because {0}' -f $_.Exception.Message)
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'adding Service Control Manager (SCM) access.'
        )
        Write-Verbose -Message $txt
    } #end END
} # End Function
