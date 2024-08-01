# Class to manage key-value pairs for INI files
class IniKeyValuePair {
    [hashtable] $KeyValues

    # Constructor
    IniKeyValuePair() {
        $this.KeyValues = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
    }

    # Adds a key-value pair to the hashtable
    [void] Add([string]$key, [string]$value) {
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $this.KeyValues[$key] = $value
        } else {
            Write-Error -Message 'Key cannot be null or whitespace.'
        } #end If-Else
    }

    # Checks if the key exists in the hashtable
    [bool] ContainsKey([string]$key) {
        return $this.KeyValues.ContainsKey($key)
    }

    # Retrieves the value for the given key
    [string] GetValue([string]$key) {
        if ($this.ContainsKey($key)) {
            return $this.KeyValues[$key]
        } else {
            return $null
        } #end If-Else
    }

    # Sets the value for the given key
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

    # Adds a section to the hashtable
    [void] Add([IniSection]$section) {
        if (-not [string]::IsNullOrWhiteSpace($section.SectionName)) {
            $this.Sections[$section.SectionName] = $section
        } else {
            Write-Error -Message 'Section name cannot be null or whitespace.'
        } #end If-Else
    }

    # Checks if the section exists
    [bool] ContainsKey([string]$key) {
        return $this.Sections.ContainsKey($key)
    }

    # Retrieves the section by name
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

    # Default constructor
    IniFile() {
        $this.Sections = [IniSections]::new()
        $this.KeyValuePair = [IniKeyValuePair]::new()
        $this.FilePath = ''
    }

    # Constructor with file path
    IniFile([string]$filePath) {
        $this.Sections = [IniSections]::new()
        $this.KeyValuePair = [IniKeyValuePair]::new()
        $this.ReadFile($filePath)
    }

    # Reads an INI file and populates sections and key-value pairs
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

    # Saves the file with the appropriate encoding based on the file path
    [void] SaveFile() {
        # Check if instance been initialized and has FilePath
        If ($this.FilePath) {
            If ($this.FilePath.Contains('GptTmpl.inf')) {
                # Save the file as unicode
                $this.SaveFile($This.FilePath, 'unicode')
            } else {
                # Save the file as UTF-8
                $this.SaveFile($This.FilePath, 'utf8')
            }
        } else {
            Write-Error -Message 'There is no path or file name. please provide one.'
        }
    }

    # Saves the file with specified encoding
    [void] SaveFile(
        [string]$filePath
    ) {
        $this.SaveFile($filePath, 'utf8')
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

    # Retrieves the value for a key in a section
    [string] GetKeyValue([string]$sectionName, [string]$key) {
        if ($this.Sections.ContainsKey($sectionName)) {
            return $this.Sections.GetSection($sectionName).KeyValuePair.GetValue($key)
        } else {
            return $null
        }
    }

    # Adds a new section
    [void] AddSection([string]$sectionName) {
        if (-not [string]::IsNullOrWhiteSpace($sectionName)) {
            $section = [IniSection]::new($sectionName)
            $this.Sections.Add($section)
        } else {
            Write-Error -Message 'Section name cannot be null or whitespace.'
        } #end If-Else
    }

    # Adds a new key-value pair to a section
    [void] AddKeyValue([string]$sectionName, [string]$key, [string]$value) {
        if ($this.Sections.ContainsKey($sectionName)) {
            $this.Sections.GetSection($sectionName).KeyValuePair.Add($key, $value)
        } else {
            Write-Error -Message ('Section {0} does not exist.' -f $sectionName)
        } #end If-Else
    }

    # Sets the value for a key in a section
    [void] SetKeyValue([string]$sectionName, [string]$key, [string]$value) {
        if ($this.Sections.ContainsKey($sectionName)) {
            $this.Sections.GetSection($sectionName).KeyValuePair.SetValue($key, $value)
        } else {
            Write-Error -Message ('Section {0} does not exist.' -f $sectionName)
        } #end If-Else
    }

    # Gets the value of a key from a section or global settings
    [string] GetItem([string]$sectionName, [string]$key) {
        if ($this.Sections.ContainsKey($sectionName)) {
            return $this.Sections.GetSection($sectionName).KeyValuePair.GetValue($key)
        } else {
            return $null
        }
    }

    # Sets a key-value pair in a section
    [void] SetItem([string]$sectionName, [string]$key, [string]$value) {
        $this.SetKeyValue($sectionName, $key, $value)
    }

    # Gets a global key-value pair
    [string] GetGlobalItem([string]$key) {
        return $this.KeyValuePair.GetValue($key)
    }

    # Sets a global key-value pair
    [void] SetGlobalItem([string]$key, [string]$value) {
        $this.KeyValuePair.SetValue($key, $value)
    }
} #end Class

<#

# Sample usage:

$PathToFile = 'C:\Users\RODRIGUEZEGUIBARVice\OneDrive - Vicente Rodriguez Eguibar\Desktop\GptTmpl.inf'

$ini = [IniFile]::new($PathToFile)

# Enumerate all sections and key/values
foreach ($section in $ini.Sections.Sections.Values) {
    Write-Output "Section: $($section.SectionName)"
    foreach ($keyValue in $section.KeyValuePair.KeyValues.GetEnumerator()) {
        Write-Output "Key: $($keyValue.Key) Value: $($keyValue.Value)"
    }
}

# Check section exists
if ($ini.Sections.ContainsKey('Asasa')) {
    Write-Output "Section Name: $($ini.Sections.GetSection('Version').SectionName)"
} else {
    Write-Output 'Section does not exist'
}

# Get existing Section
Write-Output $ini.Sections.GetSection('Version').SectionName

# Check if a Key exist in a given section
$ini.Sections.GetSection('Version').KeyValuePair.ContainsKey('Revision')
$ini.Sections.GetSection('Version').KeyValuePair.ContainsKey('signature')
$ini.Sections.GetSection('Unicode').KeyValuePair.ContainsKey('Unicode')

# Gets the KeyValuePair with name key in the specified section
Write-Output $ini.Sections.GetSection('Version').KeyValuePair.GetValue('Revision')
Write-Output $ini.Sections.GetSection('Version').KeyValuePair.GetValue('signature')
Write-Output $ini.Sections.GetSection('Unicode').KeyValuePair.GetValue('Unicode')

# Add a new section
$ini.AddSection('Delegation Model')
$ini.AddSection('To Be Deleted')

# Add a new Key/Value pair within a given section
$ini.AddKeyValue('Delegation Model', 'T0Admin', 'TheGood')

# Change value of an existing key
$ini.SetKeyValue('Delegation Model', 'T0Admin', 'TheUgly')
$ini.SetKeyValue('Unicode', 'Unicode', 'yes')
$ini.SetKeyValue('Version', 'Revision', '1')
$ini.SetKeyValue('Version', 'signature', '$CHICAGO$')

# Save file
#$ini.SaveFile($PathToFile)
$ini.SaveFile($PathToFile, 'unicode')


#>
