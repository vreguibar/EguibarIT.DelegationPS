# filepath: Private/Convert-GUIDToName.Tests.ps1
BeforeAll {
    # Import module (assuming it's already built)
    $ModulePath = Split-Path -Parent $PSCommandPath | Split-Path -Parent
    Import-Module $ModulePath -Force

    # Mock the Variables object used in the function
    $Global:Variables = @{
        SchemaNamingContext        = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
        HeaderDelegation           = 'Test Header {0} {1} {2}'
        FooterDelegation           = 'Test Footer {0} {1}'
    }
}

Describe 'Convert-GUIDToName' {
    BeforeEach {
        # Setup common mocks
        Mock Get-ADObject {
            param($SearchBase, $Filter, $Properties)

            # Return different results based on the search
            if ($SearchBase -eq $Variables.SchemaNamingContext) {
                switch ($Filter.ToString()) {
                    '{ schemaIDGUID -eq bf967aba-0de6-11d0-a285-00aa003049e2 }' {
                        return [PSCustomObject]@{
                            ObjectClass     = 'classSchema'
                            lDAPDisplayName = 'user'
                        }
                    }
                    '{ schemaIDGUID -eq bf967915-0de6-11d0-a285-00aa003049e2 }' {
                        return [PSCustomObject]@{
                            ObjectClass     = 'attributeSchema'
                            lDAPDisplayName = 'AccountExpires'
                        }
                    }
                }
            } elseif ($SearchBase -like '*Extended-Rights*') {
                if ($Filter.ToString() -like '*68b1d179-0d15-4d4f-ab71-46152e79a7bc*') {
                    return [PSCustomObject]@{
                        DisplayName = 'Allowed to Authenticate'
                        rightsGUID  = '68b1d179-0d15-4d4f-ab71-46152e79a7bc'
                    }
                }
            }
            return $null
        }
    }

    Context 'Parameter validation' {
        It 'Should accept valid GUID format' {
            { Convert-GUIDToName -Guid 'bf967aba-0de6-11d0-a285-00aa003049e2' } | Should -Not -Throw
        }

        It 'Should reject invalid GUID format' {
            { Convert-GUIDToName -Guid 'invalid-guid' } | Should -Throw
        }

        It 'Should handle null GUID correctly' {
            $result = Convert-GUIDToName -Guid '00000000-0000-0000-0000-000000000000'
            $result | Should -Be 'All [GuidNULL]'
        }
    }

    Context 'ClassSchema conversion' {
        It 'Should convert known classSchema GUID' {
            $result = Convert-GUIDToName -Guid 'bf967aba-0de6-11d0-a285-00aa003049e2'
            $result | Should -Be 'user [classSchema]'
        }
    }

    Context 'AttributeSchema conversion' {
        It 'Should convert known attributeSchema GUID' {
            $result = Convert-GUIDToName -Guid 'bf967915-0de6-11d0-a285-00aa003049e2'
            $result | Should -Be 'AccountExpires [attributeSchema]'
        }
    }

    Context 'Extended Rights conversion' {
        It 'Should convert known Extended Right GUID' {
            $result = Convert-GUIDToName -Guid '68b1d179-0d15-4d4f-ab71-46152e79a7bc'
            $result | Should -Be 'Allowed to Authenticate [ExtendedRight]'
        }
    }

    Context 'Unknown GUID handling' {
        It 'Should handle unknown GUID' {
            $result = Convert-GUIDToName -Guid '11111111-1111-1111-1111-111111111111'
            $result | Should -Be 'Unknown GUID: 11111111-1111-1111-1111-111111111111'
        }
    }

    Context 'Pipeline input' {
        It 'Should accept pipeline input' {
            $result = 'bf967aba-0de6-11d0-a285-00aa003049e2' | Convert-GUIDToName
            $result | Should -Be 'user [classSchema]'
        }
    }

    Context 'Error handling' {
        It 'Should handle Get-ADObject errors' {
            Mock Get-ADObject { throw 'AD Error' }
            Convert-GUIDToName -Guid 'bf967aba-0de6-11d0-a285-00aa003049e2' -ErrorVariable err 2>$null
            $err.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Verbose output' {
        It 'Should provide verbose output' {
            $result = Convert-GUIDToName -Guid 'bf967aba-0de6-11d0-a285-00aa003049e2' -Verbose 4>&1
            $result | Should -Contain '*Converting string*'
        }
    }
}

AfterAll {
    Remove-Variable -Name Variables -Scope Global
}
