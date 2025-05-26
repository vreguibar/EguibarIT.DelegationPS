# Set-GpoPrivilegeRight.EmptyCollection.Tests.ps1
# This test focuses specifically on handling empty collections in the Set-GpoPrivilegeRight function

$moduleName = 'EguibarIT.DelegationPS'
$functionName = 'Set-GpoPrivilegeRight'

Describe "$functionName with Empty Collections" {
    BeforeAll {
        # Import the module
        $modulePath = Split-Path -Path $PSScriptRoot -Parent
        Import-Module -Name $modulePath -Force

        # Mock dependencies we need for testing
        Mock -CommandName Get-GPO -MockWith {
            return @{
                DisplayName = 'Test GPO'
                Id = [System.Guid]::NewGuid()
                Path = 'Test Path'
            }
        }

        Mock -CommandName Get-GptTemplate -MockWith {
            # Create a mock IniFile object with required methods
            $mockIniFile = New-Object -TypeName PSObject
            $mockIniFile | Add-Member -MemberType ScriptMethod -Name SectionExists -Value { param($section) return $true }
            $mockIniFile | Add-Member -MemberType ScriptMethod -Name SaveFile -Value { return $null }
            $mockIniFile | Add-Member -MemberType ScriptMethod -Name Dispose -Value { return $null }
            $mockIniFile | Add-Member -MemberType ScriptMethod -Name SetKeyValue -Value { param($section, $key, $value) return $null }
            $mockIniFile | Add-Member -MemberType ScriptMethod -Name AddSection -Value { param($section) return $null }
            return $mockIniFile
        }

        Mock -CommandName Set-GPOConfigSection -MockWith { return $GptTmpl }
        Mock -CommandName Update-GpoVersion -MockWith { return $null }

        # Mock for user principal checks (requires admin)
        Mock -CommandName Get-FunctionDisplay -MockWith { return "Mocked function display" }

        # Mock WindowsIdentity and WindowsPrincipal
        $mockIdentity = @{
            Name = 'Test User'
        }
        $mockPrincipal = New-Object -TypeName PSObject
        $mockPrincipal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value { return $true }

        # This is a bit hacky but works for testing
        function global:New-Object {
            param($TypeName, $ArgumentList)

            if ($TypeName -eq 'System.Security.Principal.WindowsPrincipal') {
                return $mockPrincipal
            }
            else {
                # Call original New-Object for other cases
                Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
            }
        }

        # Mock static method GetCurrent()
        function global:GetCurrent {
            return $mockIdentity
        }

        # Extend [System.Security.Principal.WindowsIdentity] with our mock
        $typeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")
        $oldValue = $typeAccelerators::Get["System.Security.Principal.WindowsIdentity"]
        $typeAccelerators::Remove("System.Security.Principal.WindowsIdentity")

        # Construct a type with the same name but our mock implementation
        $mockType = New-Object -TypeName PSObject
        $mockType | Add-Member -MemberType ScriptMethod -Name GetCurrent -Value ${function:GetCurrent} -Force
        $typeAccelerators::Add("System.Security.Principal.WindowsIdentity", $mockType.GetType())
    }

    AfterAll {
        # Clean up type accelerator hack
        if ($oldValue) {
            $typeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")
            $typeAccelerators::Remove("System.Security.Principal.WindowsIdentity")
            $typeAccelerators::Add("System.Security.Principal.WindowsIdentity", $oldValue)
        }

        # Clean up global functions
        Remove-Item -Path function:global:New-Object -ErrorAction SilentlyContinue
        Remove-Item -Path function:global:GetCurrent -ErrorAction SilentlyContinue
    }

    It "Should handle empty rights collection without error" {
        # Set common parameter values
        $params = @{
            GpoToModify = 'Test GPO'
            WhatIf = $true  # Don't make actual changes
        }

        # This should not throw an error now that we've implemented the local function
        { Set-GpoPrivilegeRight @params } | Should -Not -Throw
    }
}
