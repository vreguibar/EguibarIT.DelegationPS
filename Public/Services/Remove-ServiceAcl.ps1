Function Remove-ServiceAcl {
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

    } #end Begin

    Process {

        # get current Service acl in SDDL format
        Write-Verbose -Message 'Get current Service acl in SDDL format'

        $Splat = @{
            ScriptBlock = { ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow', $PSBoundParameters['Service']))[1]) }
        }
        If ($Computer) {
            $Splat.Add('ComputerName', $Computer)
        } #end If
        $MySDDL = Invoke-Command @Splat

        # Build the Common Security Descriptor from SDDL
        Write-Verbose -Message 'Build the Common Security Descriptor from SDDL'
        $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $False, $MySDDL)

        # Search the DACL for the given Group SID. Delete if found!
        Write-Verbose -Message 'Search the DACL for the given Group SID. Delete if found!'
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove group from Service DACL?')) {

            $Permission.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier.Value -eq $GroupSID } | ForEach-Object {
                try {
                    $Permission.DiscretionaryAcl.RemoveAccessSpecific(
                        $_.AceType,
                        $_.SecurityIdentifier,
                        $_.AccessMask,
                        [System.Security.AccessControl.InheritanceFlags]::None,
                        [System.Security.AccessControl.PropagationFlags]::None
                    )
                    Write-Verbose -Message ('Successfully removed {0} for {1}' -f $_.AceType, $PSBoundParameters['Group'])
                } catch {
                    Write-Warning -Message "Failed to remove access because $($_.Exception.Message)"
                } #end Try-Catch
            } #end $Permission

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $sddl = $Permission.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                # Make sure computer has 'sc.exe':
                $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"

                If ($Computer) {
                    & $ServiceControlCmd.Definition @("\\$Computer", 'sdset', $PSBoundParameters['Service'], "$sddl")
                } else {
                    & $ServiceControlCmd.Definition @('sdset', $PSBoundParameters['Service'], "$sddl")
                }
                Write-Verbose -Message ('Successfully removed ACL in Service {0}' -f $PSBoundParameters['Service'])
            } catch {
                Write-Error -Message "Failed to remove Security because $($_.Exception.Message)"
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing Service access.'
        )
        Write-Verbose -Message $txt
    } #end END

} #end Function
