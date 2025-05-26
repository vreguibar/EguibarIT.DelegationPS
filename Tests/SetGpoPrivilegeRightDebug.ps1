# SetGpoPrivilegeRightDebug.ps1

# Import the PowerShell module
Import-Module -Name (Split-Path -Path $PSScriptRoot -Parent) -Force -Verbose

# Parameters for the Set-GpoPrivilegeRight function
$params = @{
    GpoToModify = 'Test GPO'
    WhatIf      = $true  # This will prevent actual changes
}

# Verbose and debug output
$VerbosePreference = 'Continue'
$DebugPreference = 'Continue'

# Try running the function
try {
    Write-Host "Starting test of Set-GpoPrivilegeRight..." -ForegroundColor Green
    
    # Create a mock implementation without using Pester
    function Get-GPO {
        param([string]$Name)
        return @{
            DisplayName = 'Test GPO'
            Id = [System.Guid]::NewGuid()
            Path = 'Test Path'
        }
    }
    
    # Mock Get-GptTemplate
    function global:Get-GptTemplate {
        param([string]$GpoName)
        # Create a mock IniFile object with required methods
        $mockIniFile = New-Object -TypeName PSObject
        $mockIniFile | Add-Member -MemberType ScriptMethod -Name SectionExists -Value { param($section) return $true }
        $mockIniFile | Add-Member -MemberType ScriptMethod -Name SaveFile -Value { return $null }
        $mockIniFile | Add-Member -MemberType ScriptMethod -Name Dispose -Value { return $null }
        $mockIniFile | Add-Member -MemberType ScriptMethod -Name SetKeyValue -Value { param($section, $key, $value) return $null }
        $mockIniFile | Add-Member -MemberType ScriptMethod -Name AddSection -Value { param($section) return $null }
        return $mockIniFile
    }
    
    # Other mocks as needed
    function global:Set-GPOConfigSection { return $GptTmpl }
    function global:Update-GpoVersion { return $null }
    
    # Mock Windows identity checks
    $Script:mockIdentity = New-Object -TypeName PSObject
    $Script:mockIdentity | Add-Member -TypeName PSObject -MemberType ScriptMethod -Name GetCurrent -Value { return $Script:mockIdentity }
    $Script:mockIdentity | Add-Member -MemberType NoteProperty -Name Name -Value "TEST\TestUser"
    
    $Script:mockPrincipal = New-Object -TypeName PSObject
    $Script:mockPrincipal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value { return $true }
    
    # Override required .NET classes for testing
    function global:New-Object {
        param($TypeName, $ArgumentList)
        
        if ($TypeName -eq 'System.Security.Principal.WindowsPrincipal') {
            return $Script:mockPrincipal
        }
        elseif ($TypeName -eq 'System.Security.Principal.WindowsIdentity') {
            return $Script:mockIdentity
        }
        else {
            # Call original New-Object
            Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
        }
    }
    
    # Call the function directly with our mocked environment
    function global:Get-FunctionDisplay { return "Mock function display" }
    
    # Call the function - this should not throw an error due to our fix
    Set-GpoPrivilegeRight @params
    
    Write-Host "Set-GpoPrivilegeRight completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    # Clean up our mocks
    Remove-Item -Path function:global:Get-GptTemplate -Force -ErrorAction SilentlyContinue
    Remove-Item -Path function:global:Set-GPOConfigSection -Force -ErrorAction SilentlyContinue
    Remove-Item -Path function:global:Update-GpoVersion -Force -ErrorAction SilentlyContinue
    Remove-Item -Path function:global:New-Object -Force -ErrorAction SilentlyContinue
    Remove-Item -Path function:global:Get-FunctionDisplay -Force -ErrorAction SilentlyContinue
}
