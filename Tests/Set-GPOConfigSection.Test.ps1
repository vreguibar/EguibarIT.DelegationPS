# Import the module containing the function
Import-Module -Name 'c:\Users\RODRIGUEZEGUIBARVice\OneDrive - Vicente Rodriguez Eguibar\_Scripts\LabSetup\SourceDC\Modules\EguibarIT.DelegationPS\EguibarIT.DelegationPS.psm1'

# Mock dependencies
Mock -CommandName Convert-SidToName -MockWith {
    param ($SID)
    return @("User1")
}

Mock -CommandName Get-AdObjectType -MockWith {
    param ($Identity)
    return [PSCustomObject]@{ SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1234567890-123456789-123456789-1001") }
}

Mock -CommandName SetKeyValue -MockWith {
    param ($Section, $Key, $Value)
    return $null
}

Mock -CommandName SectionExists -MockWith {
    param ($Section)
    return $true
}

Mock -CommandName AddSection -MockWith {
    param ($Section)
    return $null
}

Mock -CommandName GetKeyValue -MockWith {
    param ($Section, $Key)
    return "*S-1-5-21-1234567890-123456789-123456789-1001"
}

Describe 'Set-GPOConfigSection' {
    Context 'When setting a GPO configuration section' {
        It 'Should add new members to the specified section and key' {
            # Arrange
            $CurrentSection = "User Rights Assignment"
            $CurrentKey = "SeDenyNetworkLogonRight"
            $Members = @("User1", "Group1")
            $GptTmpl = [PSCustomObject]@{
                SectionExists = $true
                GetKeyValue = { param ($Section, $Key) return "*S-1-5-21-1234567890-123456789-123456789-1001" }
                AddSection = { param ($Section) return $null }
                SetKeyValue = { param ($Section, $Key, $Value) return $null }
            }

            # Act
            $result = Set-GPOConfigSection -CurrentSection $CurrentSection -CurrentKey $CurrentKey -Members $Members -GptTmpl $GptTmpl

            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
            $result.SectionExists($CurrentSection) | Should -Be $true
            $result.GetKeyValue($CurrentSection, $CurrentKey) | Should -Contain "*S-1-5-21-1234567890-123456789-123456789-1001"
        }

        It 'Should handle null members correctly' {
            # Arrange
            $CurrentSection = "User Rights Assignment"
            $CurrentKey = "SeDenyNetworkLogonRight"
            $Members = $null
            $GptTmpl = [PSCustomObject]@{
                SectionExists = $true
                GetKeyValue = { param ($Section, $Key) return $null }
                AddSection = { param ($Section) return $null }
                SetKeyValue = { param ($Section, $Key, $Value) return $null }
            }

            # Act
            $result = Set-GPOConfigSection -CurrentSection $CurrentSection -CurrentKey $CurrentKey -Members $Members -GptTmpl $GptTmpl

            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
            $result.SectionExists($CurrentSection) | Should -Be $true
            $result.GetKeyValue($CurrentSection, $CurrentKey) | Should -BeNullOrEmpty
        }

        It 'Should create a new section if it does not exist' {
            # Arrange
            $CurrentSection = "User Rights Assignment"
            $CurrentKey = "SeDenyNetworkLogonRight"
            $Members = @("User1", "Group1")
            $GptTmpl = [PSCustomObject]@{
                SectionExists = $false
                GetKeyValue = { param ($Section, $Key) return $null }
                AddSection = { param ($Section) return $null }
                SetKeyValue = { param ($Section, $Key, $Value) return $null }
            }

            # Act
            $result = Set-GPOConfigSection -CurrentSection $CurrentSection -CurrentKey $CurrentKey -Members $Members -GptTmpl $GptTmpl

            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
            $result.SectionExists($CurrentSection) | Should -Be $true
            $result.GetKeyValue($CurrentSection, $CurrentKey) | Should -BeNullOrEmpty
        }
    }
}
