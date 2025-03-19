function Get-ServiceAcl {
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByName')]
    [OutputType([void])]

    param(

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the service. For example BITS',
            ParameterSetName = 'ByName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceName', 'Service')]
        [string[]]
        $Name,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Display Name of the service. For example "Background Intelligent Transfer Service"',
            ParameterSetName = 'ByDisplayName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceDisplayName')]
        [string[]]
        $DisplayName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName', 'ComputerName')]
        [string]
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

        If (-Not $Computer) {
            Write-Verbose -Message 'No computer name provided. Trying the local computer instead.'
            $Computer = $env:COMPUTERNAME
        }

        # If display name was provided, get the actual service name:
        switch ($PSCmdlet.ParameterSetName) {
            'ByDisplayName' {
                Write-Verbose -Message 'Query the service(s) using DisplayName'
                $Name = Get-Service -DisplayName $DisplayName -ComputerName $Computer -ErrorAction Stop |
                    Select-Object -ExpandProperty Name
            }
        } #end Switch

        # Make sure computer has 'sc.exe':
        $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"
        if (-not $ServiceControlCmd) {
            throw "Could not find $env:SystemRoot\system32\sc.exe command!"
        } #end If

    } #end Begin

    Process {

        Write-Verbose -Message 'Getting the services'
        # Get-Service does the work looking up the service the user requested:

        $Splat = @{
            ComputerName = $Computer
            ScriptBlock  = { param($service) Get-Service -Name $service }
            ArgumentList = $PSBoundParameters['Name']
        }
        $CurrentService = Invoke-Command @splat

        ForEach ($_ in $CurrentService) {

            # We might need this info in catch block, so store it to a variable
            $CurrentName = $_.Name

            Write-Verbose -Message 'Getting SDDL'
            # Get SDDL using sc.exe
            $Sddl = & $ServiceControlCmd.Definition "\\$Computer" sdshow "$CurrentName" | Where-Object { $_ }

            try {

                Write-Verbose -Message 'Get the DACL from the SDDL string'
                $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)

            } catch {
                Write-Warning "Couldn't get security descriptor for service '$Current': $Sddl"
                return
            } #end Try-Catch

            # Create the custom object with the note properties
            $CustomObject = New-Object -TypeName PSObject -Property (
                [ordered] @{
                    Name = $_.Name
                    Dacl = $Dacl
                }
            )

            # Add the 'Access' property:
            $CustomObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
                $this.Dacl.DiscretionaryAcl | ForEach-Object {
                    $CurrentDacl = $_

                    try {

                        $IdentityReference = $CurrentDacl.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
                        Write-Verbose -Message 'Translated SID to account'

                    } catch {
                        $IdentityReference = $CurrentDacl.SecurityIdentifier.Value
                    }

                    New-Object -TypeName PSObject -Property ([ordered] @{
                            ServiceRights     = [ServiceAccessFlags] $CurrentDacl.AccessMask
                            AccessControlType = $CurrentDacl.AceType
                            IdentityReference = $IdentityReference
                            IsInherited       = $CurrentDacl.IsInherited
                            InheritanceFlags  = $CurrentDacl.InheritanceFlags
                            PropagationFlags  = $CurrentDacl.PropagationFlags
                        })
                }
            }

            # Add 'AccessToString' property that mimics a property of the same name from normal Get-Acl call
            $CustomObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
                $this.Access | ForEach-Object {
                    '{0} {1} {2}' -f $_.IdentityReference, $_.AccessControlType, $_.ServiceRights
                } | Out-String
            }

        } #end Foreach

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'getting Service ACL.'
        )
        Write-Verbose -Message $txt

        return $CustomObject
    } #end End
}
