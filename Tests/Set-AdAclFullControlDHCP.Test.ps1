Describe 'Set-AdAclFullControlDHCP' {
    BeforeAll {
        # Mock dependencies
        Mock Get-AdObjectType {
            [PSCustomObject]@{
                ObjectClass = 'group'
                Name        = 'TestGroup'
            }
        }
        Mock Set-AclConstructor5 { }
        Mock Set-AclConstructor6 { }
        Mock Get-AttributeSchemaHashTable { }
        Mock Write-Error { }
    }

    Context 'Parameter Validation' {
        It 'Should require Group parameter' {
            { Set-AdAclFullControlDHCP } | Should -Throw
        }

        It 'Should accept pipeline input' {
            { 'TestGroup' | Set-AdAclFullControlDHCP } | Should -Not -Throw
        }

        It 'Should validate group existence' {
            Mock Get-AdObjectType { $null }
            { Set-AdAclFullControlDHCP -Group 'NonExistentGroup' } | Should -Throw
        }
    }

    Context 'Permission Assignment' {
        It 'Should process valid inputs' {
            Set-AdAclFullControlDHCP -Group 'TestGroup' -Force
            Should -Invoke Set-AclConstructor5 -Times 1
            Should -Invoke Set-AclConstructor6 -Times 1
        }

        It 'Should handle RemoveRule parameter' {
            Set-AdAclFullControlDHCP -Group 'TestGroup' -RemoveRule -Force
            Should -Invoke Set-AclConstructor5 -ParameterFilter { $RemoveRule -eq $true }
            Should -Invoke Set-AclConstructor6 -ParameterFilter { $RemoveRule -eq $true }
        }
    }

    Context 'Error Handling' {
        It 'Should handle Set-AclConstructor failures' {
            Mock Set-AclConstructor5 { throw 'Access Denied' }
            Set-AdAclFullControlDHCP -Group 'TestGroup' -Force
            Should -Invoke Write-Error
        }
    }
}
