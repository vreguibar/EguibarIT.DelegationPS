# Function to check if a class is already loaded
function Test-ClassExist {
    param(
        [string]$ClassName
    )

    # Try to get the type by its full name
    $type = [Type]::GetType($ClassName, $false, $false)

    # Return true if the type exists, otherwise false
    return [bool]$type
} #end Function

# Define the class only if it doesn't already exist
if ((-not (Test-ClassExist 'EventIdInfo')) -or
    (-not (Test-ClassExist 'EventIDs')) -or
    (-not (Test-ClassExist 'EventID')) -or
    (-not (Test-ClassExist 'EventSeverity')) -or
    (-not (Test-ClassExist 'EventCategory'))
) {
    Write-Verbose -Message 'Event Info class not loaded. Proceed to load...!'
    #$EventsFileCS = Get-Content -Path "$PSScriptRoot\Class.Events.cs" -Raw
    $EventsFileCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Class.Events.cs")
    Add-Type -Language CSharp -TypeDefinition $EventsFileCS
} #end If








#$IniFileCS = Get-Content -Path "$PSScriptRoot\Class.IniFile.cs" -Raw
$IniFileCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Class.IniFile.cs")
Add-Type -Language CSharp -TypeDefinition $IniFileCS

<## Examples of usage

# Check if a Section Exists
$sectionExists = $iniFile.SectionExists("SectionName")

# Add a New Section
$iniFile.AddSection("NewSectionName")

# Check if a Key Exists in a Section
$section = $null
$keyExists = $iniFile.Sections.TryGetValue("SectionName", [ref]$section) -and $section.KeyValuePair.KeyValues.ContainsKey("KeyName")

# Checking if a Key Exists in a Section
IniSection section;
bool sectionExists = iniFile.Sections.TryGetValue("SectionName", out section);
bool keyExists = section?.KeyValuePair.ContainsKey("KeyName") ?? false;

# Add or Update a Key-Value Pair in a Section
$iniFile.SetKeyValuePair("SectionName", "KeyName", "Value")

# Get the Value of a Key
$value = $iniFile.GetKeyValue("SectionName", "KeyName")

# Save the INI File
$iniFile.SaveFile("Path\To\File.ini")

# Load an INI File
$iniFile = [IniFile]::new("Path\To\File.ini")

# Get All Sections
$allSections = $iniFile.Sections.Values

# Get All Keys in a Section
$section = $null
$iniFile.Sections.TryGetValue("SectionName", [ref]$section)
$allKeys = $section.KeyValuePair.KeyValues.Keys

#>
