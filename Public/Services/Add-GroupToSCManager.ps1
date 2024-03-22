Function Add-GroupToSCManager {
    <#
        .Synopsis
            Adds a group to the Service Control Manager (SCM) ACL.

        .DESCRIPTION
            This function adds a specified group to the Service Control Manager (SCM) ACL with specified permissions.

        .EXAMPLE
            Add-GroupToSCManager -Group "EguibarIT\SG_AdAdmins"

        .EXAMPLE
            $Splat = @{
                Group = "EguibarIT\SG_AdAdmins"
                Verbose = $true
            }
            Add-GroupToSCManager @Splat

        .PARAMETER Group
            Specifies the group to be added to the SCM ACL.

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
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $Group,

        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands..',
            Position = 0)]
        [Alias('Host', 'PC', 'Server', 'HostName')]
        [String]
        $Computer
    )

    Begin {

        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New()

        $MySDDL = $null

        # New ACL variable
        $NewAcl = [System.Security.AccessControl.DirectorySecurity]::New()

        # Define new Access Rule using above indicated Account
        $Rule = [System.Security.AccessControl.FileSystemAccessRule]::New($PSBoundParameters['Group'], 'ReadData, AppendData, ReadPermissions', 'None', 'None', 'Allow')


    } #end Begin

    Process {

        # get current 'Service Control Manager (SCM)' acl in SDDL format
        Write-Verbose -Message 'Get current "Service Control Manager (SCM)" acl in SDDL format'
        $Splat = @{
            ScriptBlock = ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow', 'scmanager'))[1])
        }
        If ($Computer) {
            $Splat.Add('ComputerName', $Computer)
        } #end If
        $MySDDL = Invoke-Command @Splat

        Write-Verbose -Message 'Original SDDL...'
        $MySDDL

        # Import SDDL into variable
        Write-Verbose -Message 'Import "Service Control Manager (SCM)" SDDL into NewAcl variable'
        $NewAcl.SetSecurityDescriptorSddlForm($MySDDL)

        # Add new Access Rule to ACL variable
        Write-Verbose -Message 'Add new Access Rule into NewAcl variable'
        $NewAcl.SetAccessRule($Rule)

        Write-Verbose -Message 'New Access will be...'
        $NewAcl.Access

        Write-Verbose -Message 'Updated SDDL will be...'
        $NewAcl.Sddl

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Update permissions on SCM?')) {

            Write-Verbose -Message 'Updating SCM Access'
            $Splat = @{
                ScriptBlock = (& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdset', 'scmanager', "$($NewAcl.Sddl)"))
            }
            If ($Computer) {
                $Splat.Add('ComputerName', $Computer)
            } #end If
            Invoke-Command @Splat
        } #end If


    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished changing Service Control Manager (SCM) access."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} # End Function
