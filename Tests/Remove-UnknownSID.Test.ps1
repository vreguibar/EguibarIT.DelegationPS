Describe 'Remove-UnknownSID' {
    BeforeAll {
        # Mock DirectoryEntry and its properties
        $mockDirectoryEntry = @{
            ObjectSecurity = @{
                GetAccessRules   = {
                    @(
                        @{
                            IdentityReference = @{
                                Value    = 'S-1-5-21-123456789-123456789-123456789-1234'
                                ToString = { 'S-1-5-21-123456789-123456789-123456789-1234' }
                            }
                        }
                    )
                }
                RemoveAccessRule = { }
            }
            CommitChanges  = { }
            Dispose        = { }
        }

        Mock New-Object { $mockDirectoryEntry } -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectoryEntry' }
        Mock Get-AdWellKnownSID { $false }
        Mock Convert-SidToName { $false }
        Mock Write-Warning { }
        Mock Write-Error { }
    }

    Context 'Parameter Validation' {
        It 'Should require LDAPpath parameter' {
            { Remove-UnknownSID } | Should -Throw
        }

        It 'Should validate LDAPpath format' {
            Mock Test-IsValidDN { $false }
            { Remove-UnknownSID -LDAPpath 'Invalid DN' } | Should -Throw
        }
    }

    Context 'SID Processing' {
        It 'Should identify unresolvable SIDs' {
            Remove-UnknownSID -LDAPpath 'OU=Test,DC=EguibarIT,DC=local'
            Should -Invoke Write-Warning -Times 1
        }

        It 'Should remove unresolvable SIDs when RemoveSID is specified' {
            Remove-UnknownSID -LDAPpath 'OU=Test,DC=EguibarIT,DC=local' -RemoveSID -Force
            Should -Invoke Write-Warning -Times 0
        }
    }

    Context 'Error Handling' {
        It 'Should handle DirectoryEntry creation failures' {
            Mock New-Object { throw 'Access Denied' }
            Remove-UnknownSID -LDAPpath 'OU=Test,DC=EguibarIT,DC=local'
            Should -Invoke Write-Error
        }

        It 'Should handle CommitChanges failures' {
            Mock CommitChanges { throw 'Commit failed' }
            Remove-UnknownSID -LDAPpath 'OU=Test,DC=EguibarIT,DC=local' -RemoveSID -Force
            Should -Invoke Write-Error
        }
    }
}
