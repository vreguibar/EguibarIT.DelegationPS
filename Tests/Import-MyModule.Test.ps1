Describe 'Import-MyModule' {
    BeforeAll {
        # Mock dependencies
        Mock Import-Module { }
        Mock Get-Module { $null }
        Mock Write-Error { }
        Mock Test-Path { $true }
    }

    Context 'Parameter Validation' {
        It 'Should require Name parameter' {
            { Import-MyModule } | Should -Throw
        }

        It 'Should accept pipeline input' {
            { 'TestModule' | Import-MyModule } | Should -Not -Throw
        }

        It 'Should validate version format' {
            { Import-MyModule -Name 'Test' -MinimumVersion 'invalid' } | Should -Throw
        }
    }

    Context 'Special Module Handling' {
        It 'Should handle GroupPolicy module' {
            Import-MyModule -Name 'GroupPolicy' -Force
            Should -Invoke Import-Module -Times 1
        }

        It 'Should handle ServerManager module' {
            Import-MyModule -Name 'ServerManager' -Force
            Should -Invoke Import-Module -Times 1
        }
    }

    Context 'Module Import Logic' {
        It 'Should check for module availability' {
            Mock Get-Module { $null }
            Import-MyModule -Name 'NonExistentModule'
            Should -Invoke Write-Error -Times 1
        }

        It 'Should handle already imported modules' {
            Mock Get-Module { [PSCustomObject]@{ Name = 'TestModule' } }
            Import-MyModule -Name 'TestModule'
            Should -Invoke Import-Module -Times 0
        }

        It 'Should force import when specified' {
            Mock Get-Module { [PSCustomObject]@{ Name = 'TestModule' } }
            Import-MyModule -Name 'TestModule' -Force
            Should -Invoke Import-Module -Times 1
        }
    }

    Context 'Error Handling' {
        It 'Should handle Import-Module failures' {
            Mock Import-Module { throw 'Import failed' }
            Import-MyModule -Name 'FailingModule'
            Should -Invoke Write-Error -Times 1
        }
    }
}
