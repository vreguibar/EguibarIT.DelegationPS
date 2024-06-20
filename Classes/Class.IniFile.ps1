
class IniKeyValuePair {
    [hashtable] $KeyValues

    IniKeyValuePair() {
        $this.KeyValues = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
    }

    [void] Add([string]$key, [string]$value) {
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $this.KeyValues[$key] = $value
        } else {
            Write-Error -Message 'Key cannot be null or whitespace.'
        } #end If-Else
    }

    [bool] ContainsKey([string]$key) {
        return $this.KeyValues.ContainsKey($key)
    }

    [string] GetValue([string]$key) {
        if ($this.ContainsKey($key)) {
            return $this.KeyValues[$key]
        } else {
            return $null
        } #end If-Else
    }

    [void] SetValue([string]$key, [string]$value) {
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $this.KeyValues[$key] = $value
        } else {
            Write-Error -Message 'Key cannot be null or whitespace.'
        } #end If-Else
    }
} #end Class

################################################################################

class IniSection {
    [string] $SectionName
    [IniKeyValuePair] $KeyValuePair

    IniSection([string]$sectionName) {
        $this.SectionName = $sectionName
        $this.KeyValuePair = [IniKeyValuePair]::new()
    }
} #end Class

################################################################################

class IniSections {
    [hashtable] $Sections

    IniSections() {
        $this.Sections = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
    }

    [void] Add([IniSection]$section) {
        if (-not [string]::IsNullOrWhiteSpace($section.SectionName)) {
            $this.Sections[$section.SectionName] = $section
        } else {
            Write-Error -Message 'Section name cannot be null or whitespace.'
        } #end If-Else
    }

    [bool] ContainsKey([string]$key) {
        return $this.Sections.ContainsKey($key)
    }

    [IniSection] GetSection([string]$key) {
        if ($this.ContainsKey($key)) {
            return $this.Sections[$key]
        } else {
            return $null
        }
    }
} #end Class

################################################################################

class IniFile {
    [string] $FilePath
    [IniSections] $Sections
    [IniKeyValuePair] $KeyValuePair

    IniFile() {
        $this.Sections = [IniSections]::new()
        $this.KeyValuePair = [IniKeyValuePair]::new()
        $this.FilePath = ''
    }

    IniFile([string]$filePath) {
        $this.Sections = [IniSections]::new()
        $this.KeyValuePair = [IniKeyValuePair]::new()
        $this.ReadFile($filePath)
    }

    [void] ReadFile([string]$filePath) {
        Try {
            $this.FilePath = $filePath
            $iniLines = Get-Content -Path $filePath

            $currentSection = $this.KeyValuePair

            foreach ($line in $iniLines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    if ($line.StartsWith('[') -and $line.EndsWith(']')) {
                        $sectionName = $line.Trim('[', ']')
                        $section = [IniSection]::new($sectionName)
                        $currentSection = $section.KeyValuePair
                        $this.Sections.Add($section)
                    } elseif (-not ($line.StartsWith(';') -or $line.StartsWith('#'))) {
                        $keyPair = $line -split '=', 2
                        $key = $keyPair[0].Trim()
                        $value = if ($keyPair.Length -gt 1) {
                            $keyPair[1].Trim()
                        } else {
                            $null
                        } #end If-Else
                        $currentSection.Add($key, $value)
                    }#end If-ElseIf
                } #end If
            } #end Foreach
        } catch {
            Write-Error -Message ('Failed to read the INI file: {0}' -f $_)
        } #end Try-Catch
    }

    [void] SaveFile(
        [string]$filePath
    ) {
        $this.SaveFile($filePath, 'UTF-8')
    }


    [void] SaveFile(
        [string]$filePath,
        [string]$encoding
    ) {
        try {
            $lines = [System.Collections.Generic.List[string]]::new()

            if ($this.KeyValuePair.KeyValues.Count -gt 0) {
                foreach ($param in $this.KeyValuePair.KeyValues.GetEnumerator()) {
                    if ($null -eq $param.Value) {
                        $lines.Add($param.Key)
                    } else {
                        $lines.Add("$($param.Key)=$($param.Value)")
                    } #end If-Else
                } #end Foreach
            } #end If

            foreach ($section in $this.Sections.Sections.Values) {
                $lines.Add("[$($section.SectionName)]")
                foreach ($param in $section.KeyValuePair.KeyValues.GetEnumerator()) {
                    if ($null -eq $param.Value) {
                        $lines.Add($param.Key)
                    } else {
                        $lines.Add("$($param.Key)=$($param.Value)")
                    } #end If-Else
                } #end Foreach
                $lines.Add([string]::Empty)
            } #end Foreach

            Set-Content -Path $filePath -Value $lines.ToArray() -Encoding $encoding
        } catch {
            Write-Error -Message ('Failed to save the INI file: {0}' -f $_)
        } #end Try-Catch
    }

    [string] GetSectionName([string]$sectionName) {
        if ($this.Sections.ContainsKey($sectionName)) {
            return $this.Sections.GetSection($sectionName).SectionName
        } else {
            return 'Section does not exist'
        }
    }

    [string] GetKeyValue([string]$sectionName, [string]$key) {
        if ($this.Sections.ContainsKey($sectionName)) {
            return $this.Sections.GetSection($sectionName).KeyValuePair.GetValue($key)
        } else {
            return $null
        }
    }

    [void] AddSection([string]$sectionName) {
        if (-not [string]::IsNullOrWhiteSpace($sectionName)) {
            $section = [IniSection]::new($sectionName)
            $this.Sections.Add($section)
        } else {
            Write-Error -Message 'Section name cannot be null or whitespace.'
        } #end If-Else
    }

    [void] AddKeyValue([string]$sectionName, [string]$key, [string]$value) {
        if ($this.Sections.ContainsKey($sectionName)) {
            $this.Sections.GetSection($sectionName).KeyValuePair.Add($key, $value)
        } else {
            Write-Error -Message ('Section {0} does not exist.' -f $sectionName)
        } #end If-Else
    }

    [void] SetKeyValue([string]$sectionName, [string]$key, [string]$value) {
        if ($this.Sections.ContainsKey($sectionName)) {
            $this.Sections.GetSection($sectionName).KeyValuePair.SetValue($key, $value)
        } else {
            Write-Error -Message ('Section {0} does not exist.' -f $sectionName)
        } #end If-Else
    }

    [string] GetItem([string]$sectionName, [string]$key) {
        if ($this.Sections.ContainsKey($sectionName)) {
            return $this.Sections.GetSection($sectionName).KeyValuePair.GetValue($key)
        } else {
            return $null
        }
    }

    [void] SetItem([string]$sectionName, [string]$key, [string]$value) {
        $this.SetKeyValue($sectionName, $key, $value)
    }

    [string] GetGlobalItem([string]$key) {
        return $this.KeyValuePair.GetValue($key)
    }

    [void] SetGlobalItem([string]$key, [string]$value) {
        $this.KeyValuePair.SetValue($key, $value)
    }
} #end Class
