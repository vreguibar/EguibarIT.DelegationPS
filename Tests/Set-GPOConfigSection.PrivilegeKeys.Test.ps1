$VerbosePreference = 'Continue'

Describe 'Set-GPOConfigSection - Privilege Key Handling' {
    BeforeAll {
        # Import the module to test
        Import-Module "$PSScriptRoot\..\EguibarIT.DelegationPS.psm1" -Force

        # Create mock IniFileHandler.IniFile
        $mockGptTmpl = [IniFileHandler.IniFile]::new()
        $mockGptTmpl.AddSection('Privilege Rights')

        # Add a section with a key that contains a privilege key as its value (the bug scenario)
        $mockGptTmpl.SetKeyValue('Privilege Rights', 'SeTcbPrivilege', 'SeTcbPrivilege')

        # For testing privilege keys that appear as values
        $mockGptTmpl.SetKeyValue('Privilege Rights', 'SeBackupPrivilege', 'SeRestorePrivilege')
    }

    Context 'When handling edge cases with privilege keys' {
        It 'Should properly handle a privilege key that appears as its own value' {
            # This simulates the bug scenario where a privilege key is set as its own value
            $result = Set-GPOConfigSection -CurrentSection 'Privilege Rights' -CurrentKey 'SeTcbPrivilege' `
                      -Members @('Everyone') -GptTmpl $mockGptTmpl

            # The function should replace the invalid value with proper SIDs
            $newValue = $result.GetKeyValue('Privilege Rights', 'SeTcbPrivilege')
            $newValue | Should -Match '\*S-1-1-0'  # Everyone SID
            $newValue | Should -Not -Be 'SeTcbPrivilege'  # Should not keep the invalid value
        }

        It 'Should properly handle a privilege key that appears as another key value' {
            # This simulates the bug scenario where a privilege key is set as a value for another key
            $result = Set-GPOConfigSection -CurrentSection 'Privilege Rights' -CurrentKey 'SeBackupPrivilege' `
                      -Members @('Administrators') -GptTmpl $mockGptTmpl

            # The function should replace the invalid value with proper SIDs
            $newValue = $result.GetKeyValue('Privilege Rights', 'SeBackupPrivilege')
            $newValue | Should -Match '\*S-1-5-32-544'  # Administrators SID
            $newValue | Should -Not -Be 'SeRestorePrivilege'  # Should not keep the invalid value
        }
    }

    Context 'When handling privilege rights with empty collections' {
        It 'Should properly handle null members' {
            $members = $null
            $result = Set-GPOConfigSection -CurrentSection 'Privilege Rights' -CurrentKey 'SeSystemtimePrivilege' `
                      -Members $members -GptTmpl $mockGptTmpl

            $newValue = $result.GetKeyValue('Privilege Rights', 'SeSystemtimePrivilege')
            $newValue | Should -BeNullOrEmpty
        }
    }
}
