function Set-ServicePermission {

    <#
        .SYNOPSIS
            Sets specific permissions for a specified service on a local or remote computer.

        .DESCRIPTION
            This function allows you to grant permissions (FullControl, ReadAndExecute, Read, Write, Start, or Stop)
            for a specified service on a local or remote computer to a specified user or group.

        .PARAMETER ServiceName
            The name of the service to modify permissions for. Accepts multiple service names.

        .PARAMETER ComputerName
            The name of the remote computer on which the service resides. Defaults to the local computer.

        .PARAMETER Group
            The group for whom to set the specified permissions.

        .PARAMETER Permission
            The level of permission to set for the specified user.
            Valid values are 'FullControl', 'ReadAndExecute', 'Read', 'Write', 'Start', and 'Stop'.

        .PARAMETER PassThru
            If specified, returns the service object with the updated permissions.

        .INPUTS
            System.String, System.String[]

        .OUTPUTS
            Win32_Service (if -PassThru is specified)

        .EXAMPLE
            Set-ServicePermission -ServiceName 'wuauserv' -Username 'EguibarIT\davade' -Permission 'FullControl' -Verbose

            Sets FullControl permissions for 'EguibarIT\davade' on the 'wuauserv' service with verbose output.

        .EXAMPLE
            $Splat = @{
                ServiceName  = 'BITS'
                ComputerName = 'DC1'
                Group        = 'Yoda_T0'
                Permission   = 'FullControl'
                PassThru     = $True
                Verbose      = $true
            }
            $CurrentDACL = Set-ServicePermission @Splat

            Using splatting, Sets FullControl permissions for 'EguibarIT\Yoda_TO' on the 'BITS' service
            of DC1 remote computer with verbose output. Results are stored on $CurrentDACL variable

        .NOTES
            Version:         1.0
            DateModified:    28-Oct-2024
            LasModifiedBy:   Vicente R. Eguibar
                vicente@EguibarIT.com
                http://www.eguibarit.com

        .NOTES
            Used Functions:
                Name                           | Module
                -------------------------------|--------------------------
                Get-AdObjectType               | EguibarIT & EguibarIT.DelegationPS
                New-Object                     | Microsoft.PowerShell.Utility
                New-CimSession                 | CimCmdlets
                Invoke-CimMethod               | CimCmdlets
                Get-CimInstance                | CimCmdlets
                New-CimInstance                | CimCmdlets
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]

    param(

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Service name (or array of service names) to which the permission will be set.',
            Position = 0)]
        [string[]]
        $ServiceName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [PSDefaultValue(Help = 'Default Value is "$env:COMPUTERNAME"')]
        [Alias('Host', 'PC', 'Server', 'HostName', 'Computer')]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Permission to be configured on the service.',
            Position = 3)]
        [PSDefaultValue(Help = 'Default Value is "Read"')]
        [ValidateSet('FullControl', 'ReadAndExecute', 'Read', 'Write', 'Start', 'Stop')]
        [string]
        $Permission = 'Read',

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Return the permission after set.',
            Position = 4)]
        [switch]
        $PassThru

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

        # Define access rights as enum for better readability
        enum ServiceAccessRights {
            SERVICE_QUERY_CONFIG = 0x0001
            SERVICE_CHANGE_CONFIG = 0x0002
            SERVICE_QUERY_STATUS = 0x0004
            SERVICE_ENUMERATE_DEPENDENTS = 0x0008
            SERVICE_START = 0x0010
            SERVICE_STOP = 0x0020
            SERVICE_PAUSE_CONTINUE = 0x0040
            SERVICE_INTERROGATE = 0x0080
            SERVICE_USER_DEFINED_CONTROL = 0x0100
            READ_CONTROL = 0x00020000
            WRITE_DAC = 0x00040000
            WRITE_OWNER = 0x00080000
            DELETE = 0x00010000
        }

        # Map permissions to access rights using enum values
        $permissionMap = @{
            'FullControl'    = [int]([ServiceAccessRights]::SERVICE_QUERY_CONFIG -bor
                [ServiceAccessRights]::SERVICE_CHANGE_CONFIG -bor
                [ServiceAccessRights]::SERVICE_QUERY_STATUS -bor
                [ServiceAccessRights]::SERVICE_ENUMERATE_DEPENDENTS -bor
                [ServiceAccessRights]::SERVICE_START -bor
                [ServiceAccessRights]::SERVICE_STOP -bor
                [ServiceAccessRights]::SERVICE_PAUSE_CONTINUE -bor
                [ServiceAccessRights]::SERVICE_INTERROGATE -bor
                [ServiceAccessRights]::SERVICE_USER_DEFINED_CONTROL -bor
                [ServiceAccessRights]::READ_CONTROL -bor
                [ServiceAccessRights]::WRITE_DAC -bor
                [ServiceAccessRights]::WRITE_OWNER -bor
                [ServiceAccessRights]::DELETE)
            'ReadAndExecute' = [int]([ServiceAccessRights]::SERVICE_QUERY_CONFIG -bor
                [ServiceAccessRights]::SERVICE_QUERY_STATUS -bor
                [ServiceAccessRights]::SERVICE_ENUMERATE_DEPENDENTS -bor
                [ServiceAccessRights]::SERVICE_START -bor
                [ServiceAccessRights]::SERVICE_STOP -bor
                [ServiceAccessRights]::READ_CONTROL)
            'Read'           = [int]([ServiceAccessRights]::SERVICE_QUERY_CONFIG -bor
                [ServiceAccessRights]::SERVICE_QUERY_STATUS -bor
                [ServiceAccessRights]::SERVICE_ENUMERATE_DEPENDENTS -bor
                [ServiceAccessRights]::READ_CONTROL)
            'Write'          = [int][ServiceAccessRights]::SERVICE_CHANGE_CONFIG
            'Start'          = [int][ServiceAccessRights]::SERVICE_START
            'Stop'           = [int][ServiceAccessRights]::SERVICE_STOP
        }


        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            #throw 'This function requires administrative privileges. Please run PowerShell as Administrator.'
        }


        # Create CIM session if remote computer
        if ($ComputerName -ne $env:COMPUTERNAME) {

            $Computer = Get-AdObjectType -Identity $PSBoundParameters['ComputerName']

            try {
                $script:cimSession = New-CimSession -ComputerName $Computer.Name -ErrorAction Stop
                $script:cimParams = @{ CimSession = $cimSession }
            } catch {
                throw "Failed to create CIM session to '$ComputerName'. Error: $_"
            } #end Try-Catch
        } else {
            $script:cimParams = @{}
        } #end If-Else

        $Identity = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {

        # Iterate all services
        foreach ($service in $ServiceName) {
            try {
                Write-Verbose "Processing service: $service"

                # Get the service
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$service'" @cimParams
                if (-not $svc) {
                    Write-Error "Service '$service' not found"
                    continue
                } #end If

                # Get current security descriptor
                $getSDResult = Invoke-CimMethod -InputObject $svc -MethodName GetSecurityDescriptor @cimParams
                $currentDACL = $getSDResult.Descriptor.DACL

                if ($getSDResult.ReturnValue -ne 0) {
                    Write-Error -Message ('
                        Failed to get security descriptor for {0}.
                        Return value: {1}' -f $service, $getSDResult.ReturnValue
                    )
                    continue
                } else {
                    Write-Verbose -Message ('Got security descriptor for {0}.' -f $service)
                } #end If-Else


                # Get the current Owner and Group
                $currentOwner = $getSDResult.Descriptor.Owner
                $currentGroup = $getSDResult.Descriptor.Group

                # Create new Owner Trustee if not present
                if (-not $currentOwner) {
                    $ownerTrusteeArgs = @{
                        ClassName = 'Win32_Trustee'
                        Namespace = 'root/cimv2'
                        Property  = @{
                            Domain    = 'NT AUTHORITY'
                            Name      = 'SYSTEM'
                            SIDString = 'S-1-5-18'
                        }
                    }
                    $currentOwner = New-CimInstance -ClientOnly @ownerTrusteeArgs
                }

                # Create new Group Trustee if not present
                if (-not $currentGroup) {
                    $groupTrusteeArgs = @{
                        ClassName = 'Win32_Trustee'
                        Namespace = 'root/cimv2'
                        Property  = @{
                            Domain    = 'BUILTIN'
                            Name      = 'Administrators'
                            SIDString = 'S-1-5-32-544'
                        }
                    }
                    $currentGroup = New-CimInstance -ClientOnly @groupTrusteeArgs
                }

                # Create the new Trustee object for the user
                $trusteeArgs = @{
                    ClassName = 'Win32_Trustee'
                    Namespace = 'root/cimv2'
                    Property  = @{
                        Name      = $Identity.SamAccountName
                        SIDString = ([System.Security.Principal.SecurityIdentifier]::New($Identity.SID.Value)).Value
                        Domain    = $env:USERDNSDOMAIN
                    }
                }
                $trustee = New-CimInstance -ClientOnly @trusteeArgs
                Write-Verbose -Message ('Created trustee: {0}' -f ($trustee | Out-String))

                # Define new ACE (Access Control Entry)
                $aceArgs = @{
                    ClassName = 'Win32_Ace'
                    Namespace = 'root/cimv2'
                    Property  = @{
                        AccessMask = [UInt32]$permissionMap[$Permission]
                        AceFlags   = [UInt32]0  # Adjusted for default case, change if needed
                        AceType    = [UInt32]0  # ACCESS_ALLOWED_ACE_TYPE
                        Trustee    = $trustee
                    }
                }
                $ace = New-CimInstance -ClientOnly @aceArgs
                Write-Verbose -Message ('Created ACE: {0}' -f ($ace | Out-String))

                # Add new ACE to the DACL
                $newDACL = @($currentDACL + $ace)

                # Convert to CIM-compatible ACE instances
                $cimDACL = foreach ($aceEntry in $newDACL) {
                    New-CimInstance -ClientOnly -Namespace 'root/cimv2' -ClassName 'Win32_Ace' -Property @{
                        AccessMask = [UInt32]$aceEntry.AccessMask
                        AceFlags   = [UInt32]$aceEntry.AceFlags
                        AceType    = [UInt32]$aceEntry.AceType
                        Trustee    = $aceEntry.Trustee
                    }
                }

                # Create the new security descriptor with updated DACL
                $newSDArgs = @{
                    ControlFlags = [UInt32]0x0004  # SE_DACL_PRESENT
                    Owner        = $currentOwner
                    Group        = $currentGroup
                    DACL         = [CimInstance[]]$cimDACL
                }
                $Splat = @{
                    ClientOnly = $true
                    Namespace  = 'root/cimv2'
                    ClassName  = 'Win32_SecurityDescriptor'
                    Property   = $newSDArgs
                }
                $newSD = New-CimInstance @Splat


                # Apply the updated security descriptor
                if ($PSCmdlet.ShouldProcess($service, "Add permission $Permission for $Groupe")) {

                    Write-Verbose -Message ('Setting security descriptor for service {0}...' -f $service)
                    Write-Verbose -Message ('Owner: {0}' -f $currentOwner.Name)
                    Write-Verbose -Message ('Group: {0}' -f $currentGroup.Name)
                    Write-Verbose -Message ('Number of ACEs: {0}' -f $newAces.Count)

                    $Splat = @{
                        InputObject = $svc
                        MethodName  = 'SetSecurityDescriptor'
                        Arguments   = @{ Descriptor = $newSD }
                    }
                    $setSDResult = Invoke-CimMethod @Splat @cimParams

                    if ($setSDResult.ReturnValue -ne 0) {
                        Write-Error "Failed to set security descriptor for '$service'. Return value: $($setSDResult.ReturnValue)"
                        continue
                    }

                    Write-Verbose -Message ('
                        Successfully added {0} permission
                        for $Username on service {1}' -f $Permission, $service
                    )

                    if ($PassThru) {
                        Get-CimInstance -ClassName Win32_Service -Filter "Name='$service'" @cimParams
                    }
                }
            } catch {
                Write-Error -Message ('Error processing service {0}: {1}' -f $service, $_)
            }
        } #end Foreach Service
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'setting permissions on service.'
        )
        Write-Verbose -Message $txt

        if ($script:cimSession) {
            Remove-CimSession -CimSession $script:cimSession
        }
    } #end End
} #end Function
