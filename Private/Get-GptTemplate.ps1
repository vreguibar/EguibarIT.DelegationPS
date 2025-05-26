function Get-GptTemplate {
    <#
        .SYNOPSIS
            Retrieves or creates the GPT template (GptTmpl.inf) for a specified Group Policy Object.

        .DESCRIPTION
            This function retrieves or creates the GPT template file (GptTmpl.inf) for a specified
            Group Policy Object (GPO).

            It performs the following operations:
            - Retrieves the specified GPO using the Group Policy module
            - Locates or creates the necessary directory structure in SYSVOL
            - Creates the GptTmpl.inf file if it doesn't exist
            - Returns an IniFileHandler.IniFile object representing the template

            This function is essential for Group Policy security settings management as it provides
            access to the underlying infrastructure file that stores security configurations.

            The function handles errors gracefully with detailed error messages for better troubleshooting
            and supports pipeline input for efficient batch processing.

        .PARAMETER GpoName
            The name of the Group Policy Object (GPO) for which the GPT template is to be retrieved.
            This parameter accepts both direct input and pipeline input, including objects from Get-GPO.

        .PARAMETER DomainName
            The Fully Qualified Domain Name (FQDN) of the domain containing the GPO.
            If not specified, the current user's domain (from environment variable USERDNSDOMAIN) is used.

        .PARAMETER Server
            The Domain Controller to connect to for Group Policy operations.
            If not specified, the nearest Domain Controller is automatically selected.

        .EXAMPLE
            Get-GptTemplate -GpoName "Default Domain Policy"

            Retrieves the GPT template for the "Default Domain Policy" GPO in the current domain.
            Creates the template file if it doesn't exist.

        .EXAMPLE
            Get-GptTemplate -GpoName "Default Domain Policy" -DomainName "EguibarIT.local" -Server "DC01.EguibarIT.local"

            Retrieves the GPT template for the "Default Domain Policy" GPO in the EguibarIT.local domain,
            connecting to the specified domain controller DC01.EguibarIT.local.

        .EXAMPLE
            Get-GPO -Name "Default Domain Policy" | Get-GptTemplate

            Retrieves the GPT template for the GPO object passed through the pipeline.

        .EXAMPLE
            "Default Domain Policy" | Get-GptTemplate

            Retrieves the GPT template for the GPO name passed through the pipeline.

        .INPUTS
            System.String
            Microsoft.GroupPolicy.Gpo

            You can pipe a GPO name as a string or a GPO object from Get-GPO to this function.

        .OUTPUTS
            IniFileHandler.IniFile

            Returns an IniFileHandler.IniFile object representing the GPT template if successful.
            Returns $null if the operation fails.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-GPO                                    ║ GroupPolicy
                New-Item                                   ║ Microsoft.PowerShell.Management
                Test-Path                                  ║ Microsoft.PowerShell.Management
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Import-MyModule                            ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Group Policy

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Group Policy Management
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
        ConfirmImpact = 'Low')]
    [OutputType([IniFileHandler.IniFile])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name of the GPO.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PolicyName')]
        [string]
        $GpoName,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the domain name containing the GPO. If not specified, the current user domain is used.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [string]
        $DomainName,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the domain controller to connect to. If not specified, the nearest DC is used.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Alias('DC', 'DomainController')]
        [string]
        $Server
    )

    Begin {
        # Set strict mode to catch syntax errors
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.MyCommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$false)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        # Import required modules
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false

        ##############################
        # Variables Definition

        # Initialize the splat hashtable for Get-GPO parameters
        [hashtable]$SplatGpo = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Create and return the IniFileHandler.IniFile object
        $GptTmpl = [IniFileHandler.IniFile]::new()

        # Add the GPO name to the splat if provided
        if ($PSBoundParameters.ContainsKey('GpoName')) {
            $SplatGpo['Name'] = $PSBoundParameters['GpoName']
        }

        # Add the domain name to the splat if provided
        if ($PSBoundParameters.ContainsKey('DomainName')) {
            $SplatGpo['Domain'] = $PSBoundParameters['DomainName']
        }

        # Add the server to the splat if provided
        if ($PSBoundParameters.ContainsKey('Server')) {
            $SplatGpo['Server'] = $PSBoundParameters['Server']
        }

        # Add ErrorAction to the splat
        $SplatGpo['ErrorAction'] = 'Stop'


        # Get the domain FQDN - use the provided domain or the current user's domain
        [string]$DomainFQDN = if ($PSBoundParameters.ContainsKey('DomainName')) {
            $PSBoundParameters['DomainName']
        } else {
            $env:USERDNSDOMAIN
        } #end if-else

        $PDCEmulator = (Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator

    } #end Begin

    Process {
        try {

            # Get the GPO object
            $Gpo = Get-GPO @SplatGpo

            Write-Debug -Message ('
                GPO object retrieved successfully: {0}
                GPO ID: {0}' -f $Gpo.DisplayName, $Gpo.Id
            )


            # Construct the GPT template path
            #[string]$DomainPath = '\\{0}\SYSVOL\{0}' -f $PDCEmulator
            [string]$DomainPath = '\\{0}\SYSVOL\{0}' -f $DomainFQDN
            [string]$GpoPath = '{0}\Policies\{1}\Machine\Microsoft\Windows NT\SecEdit\' -f $DomainPath, ('{' + $($Gpo.Id) + '}')
            [string]$GpoPathFile = '{0}GptTmpl.inf' -f $GpoPath

            Write-Debug -Message ('Constructed GPT template path: {0}' -f $GpoPath)

            # Check if the directory exists and create it if necessary
            if (-not (Test-Path -Path $GpoPath -PathType Container)) {

                Write-Debug -Message ('GPT template path does not exist. Creating new folder path: {0}' -f $GpoPath)

                # Use ShouldProcess to confirm the directory creation
                if ($PSCmdlet.ShouldProcess($GpoPath, 'Create Directory')) {

                    try {

                        # Create the directory
                        New-Item -ItemType Directory -Path $GpoPath -Force -ErrorAction Stop | Out-Null
                        Write-Debug -Message ('Directory created successfully: {0}' -f $GpoPath)

                    } catch {

                        Write-Error -Message ('
                            Error while trying to create the folder for {0}.
                            Error: {1}' -f $Gpo.DisplayName, $_.Exception.Message
                        )
                        return $null

                    } #end Try-Catch

                } else {

                    # User chose not to create the directory
                    Write-Debug -Message ('Directory creation skipped due to ShouldProcess: {0}' -f $GpoPath)
                    return $null

                } #end if-else

            } #end if

            # Check if the file exists and create it if necessary
            if (-not (Test-Path -Path $GpoPathFile -PathType Leaf)) {

                Write-Debug -Message ('GPT template file does not exist. Creating new file: {0}' -f $GpoPathFile)

                # Use ShouldProcess to confirm the file creation
                if ($PSCmdlet.ShouldProcess($GpoPathFile, 'Create File')) {

                    try {

                        # Create the file with Unicode encoding
                        [System.IO.File]::WriteAllText($GpoPathFile, '', [System.Text.Encoding]::Unicode)
                        Write-Debug -Message ('File created successfully: {0}' -f $GpoPathFile)

                    } catch {

                        Write-Error -Message ('
                            Error while trying to create GptTmpl.inf file within folder for {0}.
                            Error: {1}' -f $Gpo.DisplayName, $_.Exception.Message
                        )
                        return $null

                    } #end Try-Catch

                } else {

                    # User chose not to create the file
                    Write-Debug -Message ('File creation skipped due to ShouldProcess: {0}' -f $GpoPathFile)
                    return $null

                } #end if-else

            } #end if


            Write-Debug -Message ('Creating IniFileHandler.IniFile object for: {0}' -f $GpoPathFile)

            # Read the GptTmpl.inf file into an IniFileHandler.IniFile object
            $GptTmpl.ReadFile($GpoPathFile)

            Write-Debug -Message 'GPT template object created successfully.'

            # Ensure we're returning an IniFileHandler.IniFile object
            if ($GptTmpl -is [IniFileHandler.IniFile]) {

                return $GptTmpl

            } else {

                throw 'Failed to create an IniFileHandler.IniFile object'

            } #end If-Else

        } catch {

            # Check the error type and provide appropriate messages
            if ($_.Exception.ToString() -like '*GPNotFoundException*') {

                Write-Error -Message ('GPO not found: {0}. Error: {1}' -f $PSBoundParameters['GpoName'], $_.Exception.Message)

            } elseif ($_.Exception.ToString() -like '*DirectoryNotFoundException*') {

                Write-Error -Message ('Directory not found: {0}. Error: {1}' -f $GpoPath, $_.Exception.Message)

            } elseif ($_.Exception.ToString() -like '*FileNotFoundException*') {

                Write-Error -Message ('File not found: {0}. Error: {1}' -f $GpoPathFile, $_.Exception.Message)

            } elseif ($_.Exception.ToString() -like '*UnauthorizedAccessException*') {

                Write-Error -Message ('Access denied while attempting to access {0}. Error: {1}' -f $GpoPathFile, $_.Exception.Message)

            } else {

                Write-Error -Message ('An unexpected error occurred while handling the GPT template path. Error: {0}' -f $_.Exception.Message)

            } #end If-ElseIf-Else

            return $null
        } #end Try-Catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.FooterDelegation) {
            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'Returning GptTmpl object (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end function Get-GptTemplate
