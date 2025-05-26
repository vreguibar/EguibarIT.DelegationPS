# Set-GpoPrivilegeRight.EmptyMembers.Tests.ps1

Describe 'Set-GpoPrivilegeRight with empty members' {
    BeforeAll {
        # Add namespace for IniFileHandler to handle type if it doesn't already exist
        if (-not ([System.Management.Automation.PSTypeName]'IniFileHandler.IniFile').Type) {
            Add-Type -TypeDefinition @'
                namespace IniFileHandler {
                    public class IniFile {
                        public bool SectionExists(string section) { return true; }
                        public string GetKeyValue(string section, string key) { return ""; }
                        public void SetKeyValue(string section, string key, string value) { }
                        public void AddSection(string section) { }
                        public void SaveFile() { }
                        public void Dispose() { }
                    }
                }
'@
        }

        # Mock the required functions
        function Get-GPO {
        }
        function Get-GptTemplate {
            # Create a mock GptTmpl object using the actual IniFileHandler.IniFile type
            return New-Object IniFileHandler.IniFile
        }

        function Get-FunctionDisplay {
            param([hashtable]$HashTable)
            return 'Function display mock'
        }

        # Mock additional required functions
        function Update-GpoVersion {
        }
        function Test-IsValidDN {
            return $true 
        }

        function Set-GPOConfigSection {
            param (
                [Parameter(Mandatory = $true)]
                [string]$CurrentSection,

                [Parameter(Mandatory = $true)]
                [string]$CurrentKey,

                [Parameter(Mandatory = $true)]
                $Members,

                [Parameter(Mandatory = $true)]
                $GptTmpl
            )

            # This is the critical validation - ensure Members has a Count property
            $membersType = $Members.GetType().FullName
            $hasCountProperty = $Members.PSObject.Properties.Name -contains 'Count'
            $count = if ($hasCountProperty) {
                $Members.Count 
            } else {
                'N/A' 
            }

            # Report back the properties of Members
            [PSCustomObject]@{
                Type             = $membersType
                HasCountProperty = $hasCountProperty
                Count            = $count
                IsSuccess        = $hasCountProperty
            }
        }

        # Define global variables that might be needed
        $script:Variables = @{
            HeaderDelegation = 'Header {0} {1} {2}'
            FooterDelegation = 'Footer {0} {1}'
        }

        # Mock the Test-MembersProperty function if it's not found
        if (-not (Get-Command -Name Test-MembersProperty -ErrorAction SilentlyContinue)) {
            # Source the Test-MembersProperty function first since it's needed by Set-GpoPrivilegeRight
            . "$PSScriptRoot\..\Private\Test-MembersProperty.ps1"
        }

        # Source the script we're testing
        . "$PSScriptRoot\..\Public\GPO\Set-GpoPrivilegeRight.ps1"
    }

    It 'Should handle empty rights without errors' {
        # Mock the function to isolate our test
        Mock Set-GPOConfigSection {
            param($CurrentSection, $CurrentKey, $Members, $GptTmpl)

            # Verify Members has a Count property
            $hasCountProperty = $Members.PSObject.Properties.Name -contains 'Count'
            $Count = if ($hasCountProperty) {
                $Members.Count 
            } else {
                'N/A' 
            }

            # Return test result
            return [PSCustomObject]@{
                HasCountProperty = $hasCountProperty
                Count            = $Count
                MemberType       = $Members.GetType().FullName
            }
        }

        # Call the function with parameters that would trigger empty members
        $result = Set-GpoPrivilegeRight -GpoToModify 'TestGPO' -TrustedCredMan @()

        # Verify the mock was called with a Members parameter that has Count property
        $result.HasCountProperty | Should -Be $true
        $result.MemberType | Should -Match 'System.Collections.Generic.List'
    }

    It 'Should handle null rights without errors' {
        # Call function with null members
        $result = Set-GpoPrivilegeRight -GpoToModify 'TestGPO' -TrustedCredMan $null

        # Verify the mock was called with a Members parameter that has Count property
        $result.HasCountProperty | Should -Be $true
        $result.MemberType | Should -Match 'System.Collections.Generic.List'
    }

    It 'Should handle single member correctly' {
        # Call function with a single member
        $result = Set-GpoPrivilegeRight -GpoToModify 'TestGPO' -TrustedCredMan 'TestUser'

        # Verify the mock was called with a Members parameter that has Count property
        $result.HasCountProperty | Should -Be $true
        $result.MemberType | Should -Match 'System.Collections.Generic.List'
        $result.Count | Should -Be 1
    }
}
