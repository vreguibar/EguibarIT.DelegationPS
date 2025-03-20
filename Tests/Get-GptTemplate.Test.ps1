Describe 'Get-GptTemplate' {
    BeforeAll {
        # Mock the required functions
        Mock Import-MyModule { }
        Mock Get-GPO {
            [PSCustomObject]@{
                Id          = '12345678-1234-1234-1234-123456789012'
                DisplayName = 'Test GPO'
            }
        }
        Mock Test-Path { return $false } -ParameterFilter { $Path -like '*SecEdit*' -and $PathType -eq 'Container' }
        Mock Test-Path { return $false } -ParameterFilter { $Path -like '*GptTmpl.inf' -and $PathType -eq 'Leaf' }
        Mock New-Item { return $true }
        Mock Write-Error { }
        Mock Write-Verbose { }
        Mock Write-Progress { }
        Mock Get-FunctionDisplay { return 'Test Function Display' }

        # Mock the [System.IO.File]::WriteAllText method
        Mock WriteAllText { } -ModuleName Get-GptTemplate

        # Mock the IniFileHandler.IniFile class
        Mock New-Object {
            return [PSCustomObject]@{
                ReadFile = { param($path) }
            }
        } -ParameterFilter { $TypeName -eq 'IniFileHandler.IniFile' }

        # Set environment variables
        $env:USERDNSDOMAIN = 'contoso.com'

        # Define the Variables hashtable
        $script:Variables = @{
            HeaderDelegation = 'Header {0} {1} {2}'
            FooterDelegation = 'Footer {0} {1}'
        }
    }

    Context 'Parameter Validation' {
        It 'Should throw when GpoName is null or empty' {
            { Get-GptTemplate -GpoName $null } | Should -Throw
            { Get-GptTemplate -GpoName '' } | Should -Throw
        }

        It 'Should accept valid GpoName' {
            { Get-GptTemplate -GpoName 'Test GPO' } | Should -Not -Throw
        }

        It 'Should accept pipeline input' {
            { 'Test GPO' | Get-GptTemplate } | Should -Not -Throw
        }
    }

    Context 'Function Execution' {
        It 'Should call Get-GPO with correct parameters' {
            Get-GptTemplate -GpoName 'Test GPO'
            Should -Invoke Get-GPO -ParameterFilter { $Name -eq 'Test GPO' }
        }

        It 'Should check if the directory exists' {
            Get-GptTemplate -GpoName 'Test GPO'
            Should -Invoke Test-Path -ParameterFilter { $Path -like '*SecEdit*' -and $PathType -eq 'Container' }
        }

        It "Should create the directory if it doesn't exist" {
            Get-GptTemplate -GpoName 'Test GPO'
            Should -Invoke New-Item -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like '*SecEdit*' }
        }

        It 'Should check if the file exists' {
            Get-GptTemplate -GpoName 'Test GPO'
            Should -Invoke Test-Path -ParameterFilter { $Path -like '*GptTmpl.inf' -and $PathType -eq 'Leaf' }
        }

        It "Should create the file if it doesn't exist" {
            Get-GptTemplate -GpoName 'Test GPO'
            Should -Invoke WriteAllText -ModuleName Get-GptTemplate
        }
    }

    Context 'Error Handling' {
        It 'Should return null when Get-GPO fails' {
            Mock Get-GPO { throw [Microsoft.GroupPolicy.GPNotFoundException]::new('GPO not found') }
            $result = Get-GptTemplate -GpoName 'Non-existent GPO'
            $result | Should -Be $null
            Should -Invoke Write-Error
        }

        It 'Should return null when directory creation fails' {
            Mock New-Item { throw [System.IO.DirectoryNotFoundException]::new('Directory not found') } -ParameterFilter { $ItemType -eq 'Directory' }
            $result = Get-GptTemplate -GpoName 'Test GPO'
            $result | Should -Be $null
            Should -Invoke Write-Error
        }
    }

    Context 'ShouldProcess Support' {
        It 'Should not create directory when ShouldProcess is false' {
            Mock ShouldProcess { return $false } -ModuleName Get-GptTemplate
            $result = Get-GptTemplate -GpoName 'Test GPO' -WhatIf
            Should -Not -Invoke New-Item
            $result | Should -Be $null
        }
    }
}
