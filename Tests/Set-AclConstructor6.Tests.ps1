# Set-AclConstructor6.Tests.ps1
#Requires -Modules @{ModuleName='Pester'; ModuleVersion='5.0.0'}

BeforeAll {
    # Import the module containing the function
    $ModulePath = Split-Path -Parent $PSScriptRoot
    Import-Module $ModulePath -Force

    # Set up mock data
    $TestGuid1 = [System.Guid]::NewGuid()
    $TestGuid2 = [System.Guid]::NewGuid()
    $TestSID = 'S-1-5-21-1234567890-123456789-123456789-1001'
    $TestDN = 'OU=TestOU,DC=contoso,DC=com'
    $TestIdentity = 'TestGroup'

    # Mock AD cmdlets and supporting functions
    Mock -CommandName Get-AdObjectType -MockWith {
        return @{
            SID         = $TestSID
            ObjectClass = 'group'
        }
    }

    Mock -CommandName Get-ADObject -MockWith {
        return @{
            DistinguishedName = $TestDN
            ObjectClass       = 'organizationalUnit'
        }
    }

    Mock -CommandName Get-Acl -MockWith {
        $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
        return $acl
    }

    Mock -CommandName Set-Acl -MockWith {
        return $true
    }

    Mock -CommandName Test-IsValidDN -MockWith {
        return $true
    }

    # Mock Write-Verbose to avoid output during tests
    Mock -CommandName Write-Verbose -MockWith {}
    Mock -CommandName Write-Debug -MockWith {}
}

Describe 'Set-AclConstructor6' {
    Context 'Parameter Validation' {
        It 'Should throw when Id is null or empty' {
            $params = @{
                Id                    = $null
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }

        It 'Should throw when LDAPPath is invalid' {
            Mock -CommandName Test-IsValidDN -MockWith { return $false }

            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = 'Invalid DN'
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }

        It 'Should accept valid parameters' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Not -Throw
        }
    }

    Context 'Identity Resolution' {
        It 'Should handle Well-Known SIDs' {
            # Set up test Variables for Well-Known SIDs
            $Global:Variables = @{
                WellKnownSIDs    = @{
                    'S-1-5-32-544' = 'Administrators'
                }
                HeaderDelegation = 'Test Header {0} {1} {2}'
                FooterDelegation = 'Test Footer {0} {1}'
            }

            $params = @{
                Id                    = 'Administrators'
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Not -Throw
            Should -Invoke -CommandName Get-AdObjectType -Times 0
        }

        It 'Should resolve AD objects' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            Set-AclConstructor6 @params
            Should -Invoke -CommandName Get-AdObjectType -Times 1 -Exactly
        }
    }

    Context 'ACL Operations' {
        It 'Should add access rule when RemoveRule is not specified' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            Set-AclConstructor6 @params
            Should -Invoke -CommandName Set-Acl -Times 1 -Exactly
        }

        It 'Should remove access rule when RemoveRule is specified' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
                RemoveRule            = $true
            }
            Set-AclConstructor6 @params
            Should -Invoke -CommandName Set-Acl -Times 1 -Exactly
        }
    }

    Context 'Error Handling' {
        It 'Should handle Get-ADObject errors' {
            Mock -CommandName Get-ADObject -MockWith { throw 'AD Error' }

            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }

        It 'Should handle Get-Acl errors' {
            Mock -CommandName Get-Acl -MockWith { throw 'ACL Error' }

            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }

        It 'Should handle Set-Acl errors' {
            Mock -CommandName Set-Acl -MockWith { throw 'Set ACL Error' }

            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }
    }

    Context 'GUID Conversion' {
        It 'Should handle string GUIDs for ObjectType' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1.ToString()
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Not -Throw
        }

        It 'Should handle string GUIDs for InheritedObjectType' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid1
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2.ToString()
            }
            { Set-AclConstructor6 @params } | Should -Not -Throw
        }

        It 'Should throw on invalid GUIDs' {
            $params = @{
                Id                    = $TestIdentity
                LDAPPath              = $TestDN
                AdRight               = 'CreateChild'
                AccessControlType     = 'Allow'
                ObjectType            = 'Invalid GUID'
                AdSecurityInheritance = 'All'
                InheritedObjectType   = $TestGuid2
            }
            { Set-AclConstructor6 @params } | Should -Throw
        }
    }
}
