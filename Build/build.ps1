param (
    [ValidateSet('Release', 'debug')]$Configuration = 'debug',
    [Parameter(Mandatory = $false)][String]$NugetAPIKey,
    [Parameter(Mandatory = $false)][Switch]$ExportAlias
)


# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'This script requires PowerShell version 5.0 or later.'
}

# Initialize Modules
function Initialize-Modules {
    #$requiredModules = @('PSScriptAnalyzer', 'Pester', 'platyPS', 'PowerShellGet', 'ActiveDirectory', 'GroupPolicy')
    $requiredModules = @('PSScriptAnalyzer', 'Pester', 'platyPS', 'PowerShellGet')

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Warning "Module '$module' is missing or out of date. Installing module now."
            Install-Module -Name $module -Scope CurrentUser -Force
        } else {
            Import-Module -Name $module -Force
        }
    }
}

# Task: Initialization
#task Init {
Function Init {
    Write-Verbose -Message 'Initializing Module PSScriptAnalyzer'
    Initialize-Modules
}

# Task: Testing
#task Test {
Function Test {
    try {
        Write-Verbose -Message 'Running PSScriptAnalyzer on Public functions'
        Invoke-ScriptAnalyzer '.\Public' -Recurse

        Write-Verbose -Message 'Running PSScriptAnalyzer on Private functions'
        Invoke-ScriptAnalyzer '.\Private' -Recurse

        Write-Verbose -Message 'Running PSScriptAnalyzer on Enums functions'
        Invoke-ScriptAnalyzer '.\Enums' -Recurse

        Write-Verbose -Message 'Running PSScriptAnalyzer on Classes functions'
        Invoke-ScriptAnalyzer '.\Classes' -Recurse

    } catch {
        throw "Couldn't run Script Analyzer"
    }

    <#
    try {
        Write-Verbose -Message "Running Pester Tests"
        $config = [PesterConfiguration]::Default
        $config.TestResult.Enabled = $true
        $Results = Invoke-Pester -Script ".\Tests\*.Tests.ps1" -OutputFormat NUnitXml -OutputFile ".\Tests\TestResults.xml" -Configuration $config
        if($Results.FailedCount -gt 0) {
            throw "$($Results.FailedCount) Tests failed"
        }
    } Catch {
        throw "Couldn't run Pester Tests"
    }
    #>
}


# Task: Debug build
#task DebugBuild -if ($Configuration -eq 'debug') {
Function DebugBuild {
    $Script:ModuleName = (Test-ModuleManifest -Path '.\*.psd1').Name
    Write-Verbose $ModuleName
    if (Test-Path ".\Output\temp\$($ModuleName)") {
        Write-Verbose -Message 'Output temp folder does exist, continuing build.'

    } else {
        Write-Verbose -Message 'Output temp folder does not exist. Creating it now'
        New-Item -Path ".\Output\temp\$($ModuleName)" -ItemType Directory -Force
    }

    if (!($ModuleVersion)) {
        Write-Verbose -Message 'No new ModuleVersion was provided, locating existing version from psd file.'
        $ModuleVersion = (Test-ModuleManifest -Path ".\$($ModuleName).psd1").Version
        $ModuleVersion = "$($ModuleVersion.Major).$($ModuleVersion.Minor).$($ModuleVersion.Build)"
        Write-Verbose "ModuleVersion found from psd file: $ModuleVersion"
    }

    if (Test-Path ".\Output\temp\$($ModuleName)\$($ModuleVersion)") {
        Write-Warning -Message "Version: $($ModuleVersion) - folder was detected in .\Output\temp\$($ModuleName). Removing old temp folder."
        Remove-Item ".\Output\temp\$($ModuleName)\$($ModuleVersion)" -Recurse -Force
    }

    Write-Verbose -Message "Creating new temp module version folder: .\Output\temp\$($ModuleName)\$($ModuleVersion)."
    try {
        New-Item -Path ".\Output\temp\$($ModuleName)\$($ModuleVersion)" -ItemType Directory
    } catch {
        throw "Failed creating the new temp module folder: .\Output\temp\$($ModuleName)\$($ModuleVersion)"
    }

    Write-Verbose -Message 'Generating the Module Manifest for temp build and generating new Module File'
    try {
        Copy-Item -Path ".\$($ModuleName).psd1" -Destination ".\Output\temp\$($ModuleName)\$ModuleVersion\"
        New-Item -Path ".\Output\temp\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1" -ItemType File
    } catch {
        throw "Failed copying Module Manifest from: .\$($ModuleName).psd1 to .\Output\temp\$($ModuleName)\$ModuleVersion\ or Generating the new psm file."
    }

    Write-Verbose -Message 'Updating Module Manifest with Public Functions'
    $publicFunctions = Get-ChildItem -Path '.\Public\*.ps1'
    $privateFunctions = Get-ChildItem -Path '.\Private\*.ps1'
    try {
        Write-Verbose -Message 'Appending Public functions to the psm file'
        $functionsToExport = New-Object -TypeName System.Collections.ArrayList
        foreach ($function in $publicFunctions.Name) {
            Write-Verbose -Message "Exporting function: $(($function.split('.')[0]).ToString())"
            $functionsToExport.Add(($function.split('.')[0]).ToString())
        }
        Update-ModuleManifest -Path ".\Output\temp\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psd1" -FunctionsToExport $functionsToExport
    } catch {
        throw 'Failed updating Module manifest with public functions'
    }
    $ModuleFile = ".\Output\temp\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psm1"
    Write-Verbose -Message 'Building the .psm1 file'
    Write-Verbose -Message 'Appending Public Functions'
    Add-Content -Path $ModuleFile -Value '### --- PUBLIC FUNCTIONS --- ###'
    foreach ($function in $publicFunctions.Name) {
        try {
            Write-Verbose -Message "Updating the .psm1 file with function: $($function)"
            $content = Get-Content -Path ".\Public\$($function)"
            Add-Content -Path $ModuleFile -Value "#Region - $function"
            Add-Content -Path $ModuleFile -Value $content
            if ($ExportAlias.IsPresent) {
                $AliasSwitch = $false
                $Sel = Select-String -Path ".\Public\$($function)" -Pattern 'CmdletBinding' -Context 0, 1
                $mylist = $Sel.ToString().Split([Environment]::NewLine)
                foreach ($s in $mylist) {
                    if ($s -match 'Alias') {
                        $alias = (($s.split(':')[2]).split('(')[1]).split(')')[0]
                        Write-Verbose -Message "Exporting Alias: $($alias) to Function: $($function)"
                        Add-Content -Path $ModuleFile -Value "Export-ModuleMember -Function $(($function.split('.')[0]).ToString()) -Alias $alias"
                        $AliasSwitch = $true
                    }
                }
                if ($AliasSwitch -eq $false) {
                    Write-Verbose -Message "No alias was found in function: $($function))"
                    Add-Content -Path $ModuleFile -Value "Export-ModuleMember -Function $(($function.split('.')[0]).ToString())"
                }
            } else {
                Add-Content -Path $ModuleFile -Value "Export-ModuleMember -Function $(($function.split('.')[0]).ToString())"
            }
            Add-Content -Path $ModuleFile -Value "#EndRegion - $function"
        } catch {
            throw "Failed adding content to .psm1 for function: $($function)"
        }
    }

    Write-Verbose -Message 'Appending Private functions'
    Add-Content -Path $ModuleFile -Value '### --- PRIVATE FUNCTIONS --- ###'
    foreach ($function in $privateFunctions.Name) {
        try {
            Write-Verbose -Message "Updating the .psm1 file with function: $($function)"
            $content = Get-Content -Path ".\Private\$($function)"
            Add-Content -Path $ModuleFile -Value "#Region - $function"
            Add-Content -Path $ModuleFile -Value $content
            Add-Content -Path $ModuleFile -Value "#EndRegion - $function"
        } catch {
            throw "Failed adding content to .psm1 for function: $($function)"
        }
    }
}

# Task: Build
#task Build -if($Configuration -eq 'Release') {
Function Build {

    $Script:ModuleName = (Test-ModuleManifest -Path '.\EguibarIT.DelegationPS.psd1').Name
    Write-Verbose $ModuleName

    if (Test-Path ".\Output\$($ModuleName)") {
        Write-Verbose -Message 'Output folder does exist, continuing build.'
    } else {
        Write-Verbose -Message 'Output folder does not exist. Creating it now'
        New-Item -Path ".\Output\$($ModuleName)" -ItemType Directory -Force
    } #end If-Else

    if (!($ModuleVersion)) {
        Write-Verbose -Message 'No new ModuleVersion was provided, locating existing version from psd file.'
        $oldModuleVersion = (Test-ModuleManifest -Path ".\$($ModuleName).psd1").Version

        $publicFunctions = Get-ChildItem -Path '.\Public\*.ps1'
        $privateFunctions = Get-ChildItem -Path '.\Private\*.ps1'
        $ClassesFunctions = Get-ChildItem -Path '.\Classes\*.ps1'
        $EnumsFunctions = Get-ChildItem -Path '.\Enums\*.ps1'
        $totalFunctions = $publicFunctions.count + $privateFunctions.count + $ClassesFunctions.count + $EnumsFunctions.count
        $ModuleBuildNumber = $oldModuleVersion.Build + 1
        Write-Verbose -Message 'Updating the Moduleversion'

        $Script:ModuleVersion = "$($oldModuleVersion.Major).$($totalFunctions).$($ModuleBuildNumber)"
        Write-Verbose "Mew ModuleVersion: $ModuleVersion"
        Update-ModuleManifest -Path ".\$($ModuleName).psd1" -ModuleVersion $ModuleVersion
    } #end If

    if (Test-Path ".\Output\$($ModuleName)\$($ModuleVersion)") {
        Write-Warning -Message "Version: $($ModuleVersion) - folder was detected in .\Output\$($ModuleName). Removing old temp folder."
        Remove-Item ".\Output\$($ModuleName)\$($ModuleVersion)" -Recurse -Force
    } #end If

    Write-Verbose -Message "Creating new temp module version folder: .\Output\$($ModuleName)\$($ModuleVersion)."
    if (Test-Path ".\Output\$($ModuleName)") {
        Write-Verbose -Message 'Detected old folder, removing it from output folder'
        Remove-Item -Path ".\Output\$($ModuleName)" -Recurse -Force
    } #end If

    try {
        New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)" -ItemType Directory
    } catch {
        throw "Failed creating the new temp module folder: .\Output\$($ModuleName)\$($ModuleVersion)"
    } #end Try-Catch

    Write-Verbose -Message 'Generating the Module Manifest for temp build and generating new Module File'
    try {
        Copy-Item -Path ".\$($ModuleName).psd1" -Destination ".\Output\$($ModuleName)\$ModuleVersion\"
        New-Item -Path ".\Output\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1" -ItemType File
    } catch {
        throw "Failed copying Module Manifest from: .\$($ModuleName).psd1 to .\Output\$($ModuleName)\$ModuleVersion\ or Generating the new psm file."
    } #end Try-Catch

    Write-Verbose -Message 'Updating Module Manifest with Public Functions'
    try {
        Write-Verbose -Message 'Appending Public functions to the psm file'
        $functionsToExport = New-Object -TypeName System.Collections.ArrayList
        foreach ($function in $publicFunctions.Name) {
            Write-Verbose -Message "Exporting function: $(($function.split('.')[0]).ToString())"
            $functionsToExport.Add(($function.split('.')[0]).ToString())
        }
        Update-ModuleManifest -Path ".\Output\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psd1" -FunctionsToExport $functionsToExport
    } catch {
        throw 'Failed updating Module manifest with public functions'
    } #end Try-Catch

    Write-Verbose -Message 'Copying Public .ps1 files'
    try {
        New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Public" -ItemType Directory -ErrorAction Continue
        Copy-Item -Path ".\$($ModuleName).psm1" -Destination ".\Output\$($ModuleName)\$ModuleVersion\"
        Copy-Item -Path '.\Public\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Public\"
    } catch {
        throw "Failed copying Public functions from: .\$($ModuleName)\Public\ to .\Output\$($ModuleName)\$ModuleVersion\Public\"
    } #end Try-Catch

    Write-Verbose -Message 'Copying Private .ps1 functions'
    try {
        New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Private" -ItemType Directory -ErrorAction Continue
        Copy-Item -Path '.\Private\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Private\"
    } catch {
        throw "Failed copying Private functions from: .\$($ModuleName)\Private\ to .\Output\$($ModuleName)\$ModuleVersion\Private\"
    } #end Try-Catch

    Write-Verbose -Message 'Copying Classes .ps1 functions'
    try {
        New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Classes" -ItemType Directory -ErrorAction Continue
        Copy-Item -Path '.\Classes\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Classes\"
    } catch {
        throw "Failed copying Classes functions from: .\$($ModuleName)\Classes\ to .\Output\$($ModuleName)\$ModuleVersion\Classes\"
    } #end Try-Catch

    Write-Verbose -Message 'Copying Enums .ps1 functions'
    try {
        New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Enums" -ItemType Directory -ErrorAction Continue
        Copy-Item -Path '.\Enums\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Enums\"
    } catch {
        throw "Failed copying Enums functions from: .\$($ModuleName)\Enums\ to .\Output\$($ModuleName)\$ModuleVersion\Enums\"
    } #end Try-Catch

    Write-Verbose -Message 'Updating Module Manifest with root module'
    try {
        Write-Verbose -Message 'Updating the Module Manifest'
        Update-ModuleManifest -Path ".\Output\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psd1" -RootModule "$($ModuleName).psm1"
    } catch {
        Write-Warning -Message 'Failed appinding the rootmodule to the Module Manifest'
    }

    Write-Verbose -Message 'Compiling Help files'
    Write-Verbose -Message 'Importing the module to be able to output documentation'
    Try {
        Write-Verbose -Message 'Importing the module to be able to output documentation'
        Import-Module ".\Output\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1"
    } catch {
        throw "Failed importing the module: $($ModuleName)"
    }

    <#
    if ($null -eq $platyPS -or ($platyPS | Sort-Object Version -Descending | Select-Object -First 1).Version -lt [version]0.12) {
        Write-Verbose -Verbose 'platyPS module not found or below required version of 0.12, installing the latest version.'
        Install-Module -Force -Name platyPS -Scope CurrentUser -Repository PSGallery
    }
    if (!(Get-ChildItem -Path '.\Docs')) {
        Write-Verbose -Message 'Docs folder is empty, generating new fiiles'
        if (Get-Module -Name $($ModuleName)) {
            Write-Verbose -Message "Module: $($ModuleName) is imported into session, generating Help Files"
            New-MarkdownHelp -Module $ModuleName -OutputFolder '.\Docs' -ErrorAction SilentlyContinue
            New-MarkdownAboutHelp -OutputFolder '.\Docs' -AboutName $ModuleName -ErrorAction SilentlyContinue
            New-ExternalHelp '.\Docs' -OutputPath ".\Output\$($ModuleName)\$($ModuleVersion)\en-US\" -ErrorAction SilentlyContinue
        } else {
            throw 'Module is not imported, cannot generate help files'
        }
    } else {
        Write-Verbose -Message 'Removing old Help files, to generate new files.'
        Remove-Item -Path '.\Docs\*.*' -Exclude 'about_*'
        if (Get-Module -Name $($ModuleName)) {
            Write-Verbose -Message "Module: $($ModuleName) is imported into session, generating Help Files"
            New-MarkdownHelp -Module $ModuleName -OutputFolder '.\Docs' -ErrorAction SilentlyContinue
            New-ExternalHelp '.\Docs' -OutputPath ".\Output\$($ModuleName)\$($ModuleVersion)\en-US\" -ErrorAction SilentlyContinue
        }
    }
    #>


} #end Function

# Task: Clean
#task Clean -if($Configuration -eq 'Release') {
Function Clean {
    if (Test-Path '.\Output\temp') {
        Write-Verbose -Message 'Removing temp folders'
        Remove-Item '.\Output\temp' -Recurse -Force
    } #end If
} #end Function

# Task: Publish
#task Publish -if($Configuration -eq 'Release') {
Function Publish {

    Write-Verbose -Message 'Publishing Module to PowerShell gallery'
    Write-Verbose -Message "Importing Module .\Output\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1"

    Import-Module ".\Output\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1"

    If ((Get-Module -Name $ModuleName) -and ($NugetAPIKey)) {
        try {
            Write-Verbose -Message "Publishing Module: $($ModuleName)"
            Publish-Module -Name $ModuleName -NuGetApiKey $NugetAPIKey
        } catch {
            throw 'Failed publishing module to PowerShell Gallery'
        } #end Try-Catch
    } else {
        Write-Warning -Message "Something went wrong, couldn't publish module to PSGallery. Did you provide a NugetKey?."
    } #end If-Else
} #end Function

<#
# Call tasks based on configuration
#task . Init, DebugBuild, Build, Clean, Publish

# Run the tasks based on configuration
if ($Configuration -eq 'debug') {
    #Init
    DebugBuild
    Clean
} elseif ($Configuration -eq 'Release') {
    #Init
    Build
    Clean
    Publish
}
#>

# Call tasks based on configuration
switch ($Configuration) {
    'debug' {
        Init
        Test
        DebugBuild
        Clean
    }
    'Release' {
        Init
        Build
        Clean
        Publish
    }
}
