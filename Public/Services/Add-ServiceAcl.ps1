Function Add-ServiceAcl {
    <#
        .Synopsis
            Adds a group to the specified Service ACL.

        .DESCRIPTION
            This function adds a specified group to the Service  ACL with specified permissions.

        .EXAMPLE
            Add-ServiceAcl -Group "SG_AdAdmins"

        .EXAMPLE
            Add-ServiceAcl -Group "SG_AdAdmins" -computer DC1

        .EXAMPLE
            $Splat = @{
                Group    = "SG_AdAdmins"
                Computer = DC1
                Verbose  = $true
            }
            Add-ServiceAcl @Splat

        .PARAMETER Service
            Specifies the service to be configured.

        .PARAMETER Group
            Specifies the group to be added to the SCM ACL.

        .PARAMETER Computer
            Remote computer to execute the commands.

        .NOTES
            This function relies on SC.exe located at $env:SystemRoot\System32\

        .NOTES
            Version:         1.2
            DateModified:    30/Oct/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specifies the service to be configured.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceName')]
        [String]
        $Service,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands..',
            Position = 2)]
        [Alias('Host', 'PC', 'Server', 'HostName')]
        [String]
        $Computer

    )

    Begin {

        $error.clear()

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

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        # Get group SID
        $GroupSID = $CurrentGroup.SID.Value

        # Make sure computer has 'sc.exe'. sc.exe supports remoting by giving \\computername
        $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"

    } #end Begin

    Process {

        # get current Service acl in SDDL format
        Write-Verbose -Message 'Get current Service acl in SDDL format'

        $MySDDL = if ($Computer) {
            (& $ServiceControlCmd.Definition @("\\$Computer", 'sdshow', $PSBoundParameters['Service']))[1]
        } else {
           ( & $ServiceControlCmd.Definition @(, 'sdshow', $PSBoundParameters['Service']))[1]
        } #end If-Else

        Write-Verbose -Message ('Retrieved SDDL: {0}' -f $MySDDL)

        try {

            # Build the Common Security Descriptor from SDDL
            Write-Verbose -Message 'Building the Common Security Descriptor from SDDL'
            $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $false, $MySDDL)

        } catch {
            Write-Error -Message ('Failed to retrieve or validate SDDL for service "{0}": {1}' -f $PSBoundParameters['Service'], $_.Exception.Message)
            return  # Exit the function if SDDL retrieval or validation fails
        }


        # Add new DACL
        Write-Verbose -Message 'Add new DACL'
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Add group Service ACL?')) {

            try {
                # https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
                # Combine the desired flags instead of 983551
                $combinedFlags = [ServiceAccessFlags] 'Delete, ReadControl, WriteDac, WriteOwner, AllAccess' -as [int]


                $Permission.DiscretionaryAcl.AddAccess(
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Security.Principal.SecurityIdentifier]"$($GroupSID)",
                    $combinedFlags,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None
                )

                Write-Verbose -Message ('Successfully Added {0} for {1}' -f $_.AceType, $PSBoundParameters['Group'])
            } catch {
                Write-Warning -Message "Failed to add access because $($_.Exception.Message)"
            }

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $sddl = $Permission.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                If ($Computer) {
                    & $ServiceControlCmd.Definition @("\\$Computer", 'sdset', $PSBoundParameters['Service'], "$sddl")
                } else {
                    & $ServiceControlCmd.Definition @('sdset', $PSBoundParameters['Service'], "$sddl")
                }
                Write-Verbose -Message ('Successfully set ACL in Service {0}' -f $PSBoundParameters['Service'])
            } catch {
                Write-Warning -Message "Failed to set Security in the registry because $($_.Exception.Message)"
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'adding Service access.'
        )
        Write-Verbose -Message $txt
    } #end END
} # End Function
