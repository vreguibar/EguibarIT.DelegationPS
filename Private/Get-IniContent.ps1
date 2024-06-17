Function Get-IniContent {
    <#
        .SYNOPSIS
            Gets the content of an INI file
        .Description
            Gets the content of an INI file and returns it as a hashtable
        .PARAMETER FilePath
            Full path to the INI file.
        .Inputs
            System.String
        .Outputs
            System.Collections.Specialized.OrderedDictionary
        .Example
            $FileContent = Get-IniContent "C:\myinifile.ini"
            -----------
            Description
            Saves the content of the c:\myinifile.ini in a hashtable called $FileContent
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]

    Param(
        # Specifies the path to the input file.
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the INI file.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]
        $FilePath
    )

    Begin {
        $sectionRegex = '^\s*\[(.+)\]\s*$'
        $keyRegex = "^\s*(.+?)\s*=\s*(['`"]?)(.*)\2\s*$"

        #$ini = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
        [System.Collections.Hashtable]$ini = [ordered]@{}
    }

    Process {


        switch -regex -file $FilePath {
            $sectionRegex {
                # Section
                $section = $matches[1]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding section : $section"
                #$ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                Try {
                    $ini.add($Section, [ordered]@{})
                } Catch {
                    Throw
                    Continue
                }
                continue
            }

            $keyRegex {
                # Key
                if (!(Test-Path 'variable:local:section')) {
                    $section = $script:NoSection
                    $ini.add($Section, [ordered]@{})

                }
                $name, $value = $matches[1, 3]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name with value: $value"
                if (-not ($ini.$section.$name)) {
                    #$ini.$section = @{$name = $value}
                    $ini[$section].add($name, $value)
                } else {
                    if ($ini.$section.$name -is [string]) {
                        $firstValue = $ini.$section.$name
                        $ini.$section.$name = [System.Collections.ArrayList]::new()
                        $ini.$section.$name.Add($firstValue) | Out-Null
                        $ini.$section.$name.Add($value) | Out-Null
                    } else {
                        $ini.$section.$name.Add($value) | Out-Null
                    }
                }
                continue
            } #end KeyRegex
        } #end Switch
    }

    End {
        Write-Output $ini
    }
}
