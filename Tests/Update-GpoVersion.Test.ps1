BeforeAll {
    # Import required modules
    Import-Module -Name 'GroupPolicy' -Force
    Import-Module -Name 'EguibarIT' -Force
    Import-Module -Name 'EguibarIT.DelegationPS' -Force

    # Mock Variables
    $script:mockGpoName = 'Test GPO'
    $script:mockGuid = 'E47B9889-3A1A-4A7B-9C7E-1234567890AB'
    $script:mockDomain = 'contoso.com'
    $script:mockGptPath = "\\$mockDomain\SYSVOL\$mockDomain\Policies\{$mockGuid}\gpt.ini"
    $script:mockLdapPath = "LDAP://CN={$mockGuid},CN=Policies,CN=System,DC=contoso,DC=com"

    # Mock the environment variable
    $env:USERDNSDOMAIN = $mockDomain

    # Mock helper functions
    function Test-AdminPrivilege {
        return $true
    }
    function Import-MyModule {
    }
    function Get-FunctionDisplay {
        return 'Test Display'
    }

    # Mock GPO object
    $script:mockGpo = @{
        DisplayName = $mockGpoName
        Id          = $mockGuid
    }

    # Mock DirectoryEntry
    $script:mockDe = @{
        Properties    = @{
            'VersionNumber'            = @{ Value = '65536' }  # Hex: 0x00010000
            'gPCMachineExtensionNames' = @{ Value = '' }
        }
        CommitChanges = { }
        Close         = { }
    }

    # Mock IniFile handler
    $script:mockIniFile = @{
        SectionExists = { param($section) return $false }
        AddSection    = { param($section) }
        SetKeyValue   = { param($section, $key, $value) }
        SaveFile      = { param($path) }
    }
}

Describe 'Update-GpoVersion' {
    BeforeEach {
        # Mock core cmdlets
        Mock -CommandName Get-GPO -MockWith { $mockGpo }
        Mock -CommandName Test-Path -MockWith { $true }
        Mock -CommandName Write-Error
        Mock -CommandName Write-Debug
        Mock -CommandName Write-Verbose
        Mock -CommandName Write-Progress

        # Mock .NET classes
        Mock -CommandName New-Object -ParameterFilter {
            $TypeName -eq 'System.DirectoryServices.DirectoryEntry'
        } -MockWith { $mockDe }
    }

    Context 'Parameter Validation' {
        It 'Should have mandatory GpoName parameter' {
            (Get-Command Update-GpoVersion).Parameters['GpoName'].Attributes.Mandatory |
                Should -BeTrue
        }

        It 'Should accept pipeline input' {
            (Get-Command Update-GpoVersion).Parameters['GpoName'].Attributes.ValueFromPipeline |
                Should -BeTrue
        }

        It 'Should validate IncrementBy range' {
            { Update-GpoVersion -GpoName $mockGpoName -IncrementBy 0 } |
                Should -Throw
            { Update-GpoVersion -GpoName $mockGpoName -IncrementBy 101 } |
                Should -Throw
        }
    }

    Context 'GPO Version Calculations' {
        It 'Should correctly increment version number' {
            # Arrange
            $initialVersion = '65536'  # Hex: 0x00010000
            $expectedNewVersion = '65539'  # Hex: 0x00010003 (increment by 3)
            $mockDe.Properties['VersionNumber'].Value = $initialVersion

            # Act
            Update-GpoVersion -GpoName $mockGpoName -WhatIf:$false

            # Assert
            Should -Invoke -CommandName Write-Debug -ParameterFilter {
                $Message -match "New GPO Version Number: $expectedNewVersion"
            }
        }

        It 'Should handle custom increment value' {
            # Arrange
            $initialVersion = '65536'  # Hex: 0x00010000
            $expectedNewVersion = '65541'  # Hex: 0x00010005 (increment by 5)
            $mockDe.Properties['VersionNumber'].Value = $initialVersion

            # Act
            Update-GpoVersion -GpoName $mockGpoName -IncrementBy 5 -WhatIf:$false

            # Assert
            Should -Invoke -CommandName Write-Debug -ParameterFilter {
                $Message -match "New GPO Version Number: $expectedNewVersion"
            }
        }
    }

    Context 'Error Handling' {
        It 'Should handle non-existent GPO' {
            # Arrange
            Mock -CommandName Get-GPO -MockWith { throw [Microsoft.GroupPolicy.GPNotFoundException]::new() }

            # Act
            Update-GpoVersion -GpoName 'NonExistentGPO'

            # Assert
            Should -Invoke -CommandName Write-Error -ParameterFilter {
                $Message -match 'GPO not found'
            }
        }

        It 'Should handle inaccessible SYSVOL path' {
            # Arrange
            Mock -CommandName Test-Path -MockWith { $false }

            # Act
            Update-GpoVersion -GpoName $mockGpoName

            # Assert
            Should -Invoke -CommandName Write-Error -ParameterFilter {
                $Message -match 'GPT.INI not found'
            }
        }
    }

    Context 'Pipeline Input' {
        It 'Should process multiple GPOs from pipeline' {
            # Arrange
            $gpos = @($mockGpoName, 'Second GPO', 'Third GPO')

            # Act
            $gpos | Update-GpoVersion -WhatIf:$false

            # Assert
            Should -Invoke -CommandName Get-GPO -Times 3
            Should -Invoke -CommandName Write-Progress -Times 3
        }
    }

    Context 'WhatIf Support' {
        It 'Should not modify GPO when using -WhatIf' {
            # Act
            Update-GpoVersion -GpoName $mockGpoName -WhatIf

            # Assert
            Should -Invoke -CommandName Get-GPO -Times 1
            Should -Not -Invoke Write-Error
            $mockDe.Properties['VersionNumber'].Value | Should -Be '65536'
        }
    }
}
