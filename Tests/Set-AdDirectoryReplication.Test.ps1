Describe 'Set-AdDirectoryReplication' {
    BeforeAll {
        # Mock dependencies
        Mock Test-AdPrivileges { $true }
        Mock Get-AdObjectType {
            [PSCustomObject]@{
                ObjectClass = 'group'
                Name        = 'TestGroup'
            }
        }
        Mock Set-AclConstructor4 { }
        Mock Get-AttributeSchemaHashTable { }
        Mock Get-ExtendedRightHashTable { }
        Mock Get-ADObject {
            @(
                [PSCustomObject]@{
                    name                        = 'TestPartition'
                    nCName                      = 'DC=test,DC=com'
                    'msDS-NC-Replica-Locations' = 'CN=Server1'
                }
            )
        }
        Mock Write-Error { }
    }

    Context 'Privilege Validation' {
        It 'Should require elevated privileges' {
            Mock Test-AdPrivileges { $false }
            Set-AdDirectoryReplication -Group 'TestGroup'
            Should -Invoke Write-Error -ParameterFilter {
                $Message -like '*privileges required*'
            }
        }
    }

    Context 'Parameter Validation' {
        It 'Should validate group existence' {
            Mock Get-AdObjectType { $null }
            Set-AdDirectoryReplication -Group 'NonExistentGroup'
            Should -Invoke Write-Error -ParameterFilter {
                $Message -like '*not found*'
            }
        }
    }

    Context 'Permission Assignment' {
        It 'Should process all replication rights' {
            Set-AdDirectoryReplication -Group 'TestGroup' -Force
            Should -Invoke Set-AclConstructor4 -Times 6
        }

        It 'Should handle RemoveRule parameter' {
            Set-AdDirectoryReplication -Group 'TestGroup' -RemoveRule -Force
            Should -Invoke Set-AclConstructor4 -ParameterFilter {
                $RemoveRule -eq $true
            }
        }
    }

    Context 'Error Handling' {
        It 'Should handle Set-AclConstructor4 failures' {
            Mock Set-AclConstructor4 { throw 'Access Denied' }
            Set-AdDirectoryReplication -Group 'TestGroup' -Force
            Should -Invoke Write-Error
        }
    }
}
