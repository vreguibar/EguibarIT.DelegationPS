Function Import-MyModule {
    <#
        .SYNOPSIS
            Imports a PowerShell module with enhanced error handling and functionality.

        .DESCRIPTION
            This function provides a robust wrapper around Import-Module with additional
            features and safeguards:

            - Enhanced error handling and detailed error messages
            - Version control (minimum and specific versions)
            - Verbose logging of import process
            - Support for special modules (GroupPolicy, ServerManager)
            - Pipeline input support
            - Module pre-existence checking
            - Force import capabilities
            - Global scope options

            The function is idempotent and handles edge cases gracefully.

        .PARAMETER Name
            The name of the module to import. Required. Accepts pipeline input.

        .PARAMETER MinimumVersion
            The minimum acceptable version of the module. Optional.
            Format: Major.Minor.Build.Revision

        .PARAMETER RequiredVersion
            The exact version of the module required. Optional.
            If specified, only this version will be imported.

        .PARAMETER Force
            Forces a module import even if already loaded. Optional.

        .PARAMETER Global
            Imports the module into the global scope. Optional.

        .PARAMETER PassThru
            Returns the imported module object. Optional.

        .PARAMETER Prefix
            Adds a prefix to imported module commands. Optional.

        .PARAMETER DisableNameChecking
            Suppresses naming convention warnings. Optional.

        .PARAMETER NoClobber
            Prevents overwriting existing commands. Optional.

        .PARAMETER Scope
            Specifies import scope: 'Global' or 'Local'. Optional.

        .PARAMETER SkipEditionCheck
            Skips PowerShell edition compatibility check. Optional.

        .PARAMETER UseWindowsPowerShell
            Forces Windows PowerShell compatibility mode. Optional.

        .EXAMPLE
            Import-MyModule -Name 'ActiveDirectory'

            Imports the ActiveDirectory module with default settings.

        .EXAMPLE
            'AzureAD', 'MSOnline' | Import-MyModule -Force -Verbose

            Imports multiple modules via pipeline with forced import and verbose output.

        .EXAMPLE
            Import-MyModule -Name 'Exchange' -MinimumVersion '2.0.0' -Prefix 'EX' -PassThru

            Imports Exchange module with version check, command prefix, and returns the module object.

        .OUTPUTS
            [System.Management.Automation.PSModuleInfo]
            When -PassThru is specified, returns the imported module object.

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Import-Module                        ║ Microsoft.PowerShell.Core
                Get-Module                           ║ Microsoft.PowerShell.Core
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:        2.2
            DateModified:    24/Mar/2025
            LastModifiedBy: Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Import-MyModule.ps1

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module

        .COMPONENT
            PowerShell Module Management

        .ROLE
            System Administration
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Management.Automation.PSModuleInfo])]

    Param (

        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the module to be imported',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Module', 'ModuleName')]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [switch]
        $Force,

        [Parameter(Mandatory = $false)]
        [switch]
        $Global,

        [Parameter(Mandatory = $false)]
        [System.Version]
        $MinimumVersion,

        [Parameter(Mandatory = $false)]
        [System.Version]
        $RequiredVersion,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru,

        [Parameter(Mandatory = $false)]
        [string]
        $Prefix,

        [Parameter(Mandatory = $false)]
        [switch]
        $DisableNameChecking,

        [Parameter(Mandatory = $false)]
        [switch]
        $NoClobber,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Global', 'Local')]
        [string]
        $Scope,

        [Parameter(Mandatory = $false)]
        [switch]
        $SkipEditionCheck,

        [Parameter(Mandatory = $false)]
        [switch]
        $UseWindowsPowerShell
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

        # Store original verbose preference
        $originalVerbosePreference = $VerbosePreference

        # Get Hashtable with corresponding parameters to import module
        # Build import parameters hashtable
        $importParams = @{
            Name        = $Name
            ErrorAction = 'Stop'
            Verbose     = $PSBoundParameters['Verbose'] -eq $true
        }


        # Add optional parameters if specified
        $optionalParams = @(
            'Force', 'Global', 'MinimumVersion', 'RequiredVersion', 'PassThru',
            'Prefix', 'DisableNameChecking', 'NoClobber', 'Scope', 'SkipEditionCheck',
            'UseWindowsPowerShell'
        )

        foreach ($param in $optionalParams) {

            if ($PSBoundParameters.ContainsKey($param)) {

                $importParams[$param] = $PSBoundParameters[$param]

            } #end If

        } #end ForEach

    } #end Begin

    Process {

        try {

            # Handle special modules
            $specialModules = @{
                'GroupPolicy'   = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\GroupPolicy\GroupPolicy.psd1'
                'ServerManager' = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1'
            }

            if ($specialModules.ContainsKey($Name)) {

                if (Test-Path -Path $specialModules[$Name]) {

                    if ($PSCmdlet.ShouldProcess($Name, 'Import special module')) {

                        Import-Module -Name $specialModules[$Name] @importParams
                        Write-Verbose -Message ('Successfully imported special module {0}' -f $Name)
                        return
                    } #end If

                } else {

                    throw ('Special module path not found: {0}' -f $specialModules[$Name])

                } #end If-Else

            } #end If

            if (-not $availableModule) {
                Write-Error -Message ('Module "{0}" is not installed. Please install the module before importing.' -f $Name)
            } #end If


            # Check if module is available
            $availableModule = Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue
            if (-not $availableModule) {

                throw ('Module {0} is not installed' -f $Name)

            } #end If

            # Check if already imported
            $importedModule = Get-Module -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $importedModule -and -not $Force) {

                Write-Verbose -Message ('Module {0} is already imported' -f $Name)

                if ($PassThru) {
                    return $importedModule
                } #end If

                return
            } #end If

            # Perform the import
            if ($PSCmdlet.ShouldProcess($Name, 'Import module')) {

                $importedModule = Import-Module @importParams
                Write-Verbose -Message ('Successfully imported module {0}' -f $Name)

                if ($PassThru) {
                    return $importedModule
                } #end If

            } #end If




        } catch {

            Write-Error -Message ('Failed to import module {0}: {1}' -f $Name, $_.Exception.Message)

        } #end Try-Catch

    } #end Process

    End {
        # Restore original verbose preference
        $VerbosePreference = $originalVerbosePreference

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'importing module.'
            )
            Write-Verbose -Message $txt
        }#end if

    } #end End
} #end Function Import-MyModule
