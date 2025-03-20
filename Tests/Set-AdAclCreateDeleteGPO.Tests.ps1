# Set-AdAclCreateDeleteGPO.Tests.ps1
Describe 'Set-AdAclCreateDeleteGPO' {
    BeforeAll {
        # Mock module variables
        $script:Variables = @{
            HeaderDelegation     = 'Test Header {0} {1} {2}'
            FooterDelegation     = 'Test Footer {0} {1}'
            defaultNamingContext = 'DC=contoso,DC=com'
        }

        $script:Constants = @{
            guidNull = [guid]::Empty
        }

        # Mock Get-AdObjectType
        Mock -CommandName Get-AdObjectType -MockWith {
            return [PSCustomObject]@{
                DistinguishedName = 'CN=TestGroup,DC=contoso,DC=com'
                ObjectClass       = 'group'
            }
        }

        # Mock Set-AclConstructor5
        Mock -CommandName Set-AclConstructor5 -MockWith { return $true }
    }

    Context 'Parameter Validation' {
        It 'Should throw when Group parameter is null' {
            { Set-AdAclCreateDeleteGPO -Group $null } |
                Should -Throw
        }

        It 'Should throw when Group parameter is empty' {
            { Set-AdAclCreateDeleteGPO -Group '' } |
                Should -Throw
        }

        It 'Should accept valid group name' {
            { Set-AdAclCreateDeleteGPO -Group 'TestGroup' -WhatIf } |
                Should -Not -Throw
        }
    }

    Context 'Function Behavior' {
        It 'Should call Set-AclConstructor5 with correct parameters for delegation' {
            # Act
            Set-AdAclCreateDeleteGPO -Group 'TestGroup' -Confirm:$false

            # Assert
            Should -Invoke Set-AclConstructor5 -Times 1 -Exactly -ParameterFilter {
                $AdRight -contains 'CreateChild' -and
                $AdRight -contains 'DeleteChild' -and
                $AccessControlType -eq 'Allow'
            }
        }

        It 'Should add RemoveRule parameter when -RemoveRule switch is used' {
            # Act
            Set-AdAclCreateDeleteGPO -Group 'TestGroup' -RemoveRule -Confirm:$false

            # Assert
            Should -Invoke Set-AclConstructor5 -Times 1 -Exactly -ParameterFilter {
                $RemoveRule -eq $true
            }
        }
    }

    Context 'ShouldProcess Behavior' {
        It 'Should support WhatIf' {
            # Act
            Set-AdAclCreateDeleteGPO -Group 'TestGroup' -WhatIf

            # Assert
            Should -Invoke Set-AclConstructor5 -Times 0
        }

        It 'Should support Confirm' {
            # Arrange
            Mock -CommandName ShouldProcess -MockWith { return $false }

            # Act
            Set-AdAclCreateDeleteGPO -Group 'TestGroup' -Confirm

            # Assert
            Should -Invoke Set-AclConstructor5 -Times 0
        }
    }

    Context 'Error Handling' {
        It 'Should handle Get-AdObjectType errors' {
            # Arrange
            Mock -CommandName Get-AdObjectType -MockWith { throw 'AD Error' }

            # Act & Assert
            { Set-AdAclCreateDeleteGPO -Group 'TestGroup' } |
                Should -Throw 'AD Error'
        }

        It 'Should handle Set-AclConstructor5 errors' {
            # Arrange
            Mock -CommandName Set-AclConstructor5 -MockWith { throw 'ACL Error' }

            # Act & Assert
            { Set-AdAclCreateDeleteGPO -Group 'TestGroup' } |
                Should -Throw 'ACL Error'
        }
    }

    Context 'Verbose Output' {
        It 'Should provide verbose output on success' {
            # Arrange
            $VerboseOutput = $null

            # Act
            Set-AdAclCreateDeleteGPO -Group 'TestGroup' -Verbose 4>&1 |
                ForEach-Object { $VerboseOutput += $_ }

            # Assert
            $VerboseOutput | Should -Not -BeNullOrEmpty
        }
    }
}
