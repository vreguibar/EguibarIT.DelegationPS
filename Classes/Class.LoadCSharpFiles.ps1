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








# Define the class only if it doesn't already exist
if ((-not (Test-ClassExist 'IniFile')) -or
    (-not (Test-ClassExist 'IniSections'))
) {
    $IniFileCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Class.IniFile.cs")
    Add-Type -Language CSharp -TypeDefinition $IniFileCS
} #end If

<## Examples of usage

################################################################################
# Create New File
$GptTmpl = [IniFileHandler.IniFile]::New()

# Load an INI File
$GptTmpl = [IniFileHandler.IniFile]::New("Path\To\File.ini")

# Don't forget to dispose when done
$GptTmpl.Dispose()

# Better: Using PowerShell automatic disposal
try {
    $GptTmpl = [IniFileHandler.IniFile]::New()
    # Work with $GptTmpl here
}
finally {
    if ($GptTmpl -is [System.IDisposable]) {
        $GptTmpl.Dispose()
    }
}



################################################################################
# Add a New Section
$GptTmpl.AddSection("NewSectionName")

# Check if a Section Exists
$sectionExists = $GptTmpl.SectionExists("SectionName")

 # Get specific section
$section = $GptTmpl.Sections.GetSection("General")

# Add or Update a Key-Value Pair in a Section
$GptTmpl.SetKeyValuePair("SectionName", "KeyName", "Value")

# Get the Value of a Key
$value = $GptTmpl.GetKeyValue("SectionName", "KeyName")

# Get All Sections
$allSections = $iniFile.Sections.Values



################################################################################
# Check if a Key Exists in a Section
$section = $null
$keyExists = $GptTmpl.Sections.TryGetValue("SectionName", [ref]$section) -and $section.KeyValuePair.KeyValues.ContainsKey("KeyName")

# Checking if a Key Exists in a Section
IniSection section;
bool sectionExists = $GptTmpl.Sections.TryGetValue("SectionName", out section);
bool keyExists = section?.KeyValuePair.ContainsKey("KeyName") ?? false;

# Get All Keys in a Section
$section = $null
$GptTmpl.Sections.TryGetValue("SectionName", [ref]$section)
$allKeys = $section.KeyValuePair.KeyValues.Keys



################################################################################
# Add security section
$GptTmpl.AddSection("File Security")

# Add security descriptors
$GptTmpl.AddSimpleString("File Security", "C:\Windows\System32\* D:PAI(A;;FA;;;BA)")
$GptTmpl.AddSimpleString("File Security", "C:\Program Files\* D:PAI(A;;FA;;;BA)")

# Read all entries
$securityEntries = $GptTmpl.GetSimpleStrings("File Security")
$securityEntries | ForEach-Object {
    Write-Host "Security Entry: $_"
}



################################################################################
# Save the INI File
$GptTmpl.SaveFile("Path\To\File.ini")

#>
