Add-Type -Language CSharp -TypeDefinition @'

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IniFileHandler
{
    //################################################################################
    // Represents a collection of key-value pairs in an INI section.
    // Properties:
    //      KeyValues: Stores key-value pairs in a case-insensitive dictionary.
    // Methods:
    //      Add(string key, string value): Adds or updates a key-value pair.
    //      ContainsKey(string key): Checks if a key exists.
    //      GetValue(string key): Retrieves the value for a key.
    //      SetValue(string key, string value): Sets the value for a key.

    /// <summary>
    /// Represents a collection of key-value pairs within an INI file section.
    /// </summary>
    public class IniKeyValuePair
    {
        /// <summary>
        /// Gets the dictionary of key-value pairs.
        /// </summary>
        public Dictionary<string, string> KeyValues { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniKeyValuePair"/> class.
        /// </summary>
        public IniKeyValuePair()
        {
            KeyValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Adds or updates a key-value pair in the dictionary.
        /// </summary>
        /// <param name="key">The key to add or update.</param>
        /// <param name="value">The value associated with the key.</param>
        public void Add(string key, string value) { if (!string.IsNullOrWhiteSpace(key)) KeyValues[key] = value; }

        /// <summary>
        /// Checks if the dictionary contains a specific key.
        /// </summary>
        /// <param name="key">The key to check for existence.</param>
        /// <returns>True if the key exists, otherwise false.</returns>
        public bool ContainsKey(string key) { return KeyValues.ContainsKey(key); }

        /// <summary>
        /// Gets the value associated with a specific key.
        /// </summary>
        /// <param name="key">The key to retrieve the value for.</param>
        /// <returns>The value associated with the key, or null if the key does not exist.</returns>
        public string GetValue(string key) { KeyValues.TryGetValue(key, out var value); return value; }

        /// <summary>
        /// Sets the value for a specific key.
        /// </summary>
        /// <param name="key">The key to set the value for.</param>
        /// <param name="value">The value to set.</param>
        public void SetValue(string key, string value) { if (!string.IsNullOrWhiteSpace(key)) KeyValues[key] = value; }

    } //end Class



    //################################################################################
    // Represents a section in an INI file containing a name and key-value pairs.
    // Properties:
    //      SectionName: The name of the section.
    //      KeyValuePair: The key-value pairs within the section.


    /// <summary>
    /// Represents a section in an INI file.
    /// </summary>
    public class IniSection
    {
        /// <summary>
        /// Gets the name of the section.
        /// </summary>
        public string SectionName { get; }

        /// <summary>
        /// Gets the collection of key-value pairs in the section.
        /// </summary>
        public IniKeyValuePair KeyValuePair { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniSection"/> class.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        public IniSection(string sectionName)
        {
            SectionName = sectionName;
            KeyValuePair = new IniKeyValuePair();
        }
    } //end Class



    //################################################################################
    // Represents a collection of INI sections. Manages multiple INI sections.
    // Properties:
    //      _sections: The internal dictionary holding section names and their corresponding IniSection objects.
    // Methods:
    //      Add(IniSection section): Adds a section to the collection.
    //      ContainsKey(string sectionName): Checks if a section exists.
    //      GetSection(string sectionName): Retrieves a section.
    //      Values: Returns all sections.

    /// <summary>
    /// Manages a collection of <see cref="IniSection"/> objects.
    /// </summary>
    public class IniSections
    {
        private Dictionary<string, IniSection> _sections;

        /// <summary>
        /// Initializes a new instance of the <see cref="IniSections"/> class.
        /// </summary>
        public IniSections()
        {
            _sections = new Dictionary<string, IniSection>(StringComparer.OrdinalIgnoreCase);
        }

         /// <summary>
        /// Adds a new section to the collection.
        /// </summary>
        /// <param name="section">The section to add.</param>
        public void Add(IniSection section)
        {
            if (!string.IsNullOrWhiteSpace(section.SectionName))
                _sections[section.SectionName] = section;
        }

        /// <summary>
        /// Checks if a section exists in the collection.
        /// </summary>
        /// <param name="sectionName">The name of the section to check.</param>
        /// <returns>True if the section exists, otherwise false.</returns>
        public bool ContainsKey(string sectionName) {
            return _sections.ContainsKey(sectionName);
        }

        /// <summary>
        /// Gets a section from the collection by name.
        /// </summary>
        /// <param name="sectionName">The name of the section to retrieve.</param>
        /// <returns>The <see cref="IniSection"/> object, or null if the section does not exist.</returns>
        public IniSection GetSection(string sectionName) {
            _sections.TryGetValue(sectionName, out var section); return section;
        }

        /// <summary>
        /// Try to get existing section name.
        /// </summary>
        /// <param name="sectionName">The name of the section to retrieve.</param>
        public bool TryGetValue(string sectionName, out IniSection section)
        {
            return _sections.TryGetValue(sectionName, out section);
        }

        /// <summary>
        /// Gets an enumerable collection of all sections.
        /// </summary>
        public IEnumerable<IniSection> Values => _sections.Values;
    } //end Class



    //################################################################################
    // Represents an INI file with sections and key-value pairs.
    // Properties:
    //      FilePath: The path to the INI file.
    //      Sections: Collection of sections in the file.
    //      KeyValuePair: Global key-value pairs not associated with any section.
    // Methods:
    //      ReadFile(string filePath): Reads and parses the INI file.
    //      SaveFile(): Saves the INI file with the default encoding.
    //      SaveFile(string filePath): Saves the INI file with the specified encoding.
    //      SaveFile(string filePath, Encoding encoding): Saves the INI file with a specific encoding.
    //      DetermineEncoding(string filePath): Determines the encoding based on the file name.
    //      AddSection(string sectionName): Adds a section.
    //      SectionExists(string sectionName): Checks if a section exists.
    //      SetKeyValue(string sectionName, string key, string value): Adds or updates a key-value pair.
    //      GetKeyValue(string sectionName, string key): Retrieves the value of a key.

    /// <summary>
    /// Provides functionality to read, write, and manage INI files.
    /// </summary>
    public class IniFile
    {

        /// <summary>
        /// Gets the file path of the INI file.
        /// </summary>
        public string FilePath { get; private set; }

        /// <summary>
        /// Gets the collection of sections in the INI file.
        /// </summary>
        public IniSections Sections { get; private set; }

         /// <summary>
        /// Gets the global key-value pairs (not associated with any section).
        /// </summary>
        public IniKeyValuePair KeyValuePair { get; private set; }

         /// <summary>
        /// Initializes a new instance of the <see cref="IniFile"/> class.
        /// </summary>
        public IniFile()
        {
            Sections = new IniSections();
            KeyValuePair = new IniKeyValuePair();
            FilePath = string.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniFile"/> class and loads the specified file.
        /// </summary>
        /// <param name="filePath">The path of the INI file to load.</param>
        public IniFile(string filePath) : this()
        {
            ReadFile(filePath);
        }

        /// <summary>
        /// Reads the INI file from the specified path.
        /// </summary>
        /// <param name="filePath">The path of the INI file to read.</param>
        public void ReadFile(string filePath)
        {
            try
            {
                FilePath = filePath;
                var iniLines = File.ReadAllLines(filePath);
                IniKeyValuePair currentSection = KeyValuePair;

                foreach (var line in iniLines)
                {
                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        if (line.StartsWith("[") && line.EndsWith("]"))
                        {
                            var sectionName = line.Trim('[', ']');
                            var section = new IniSection(sectionName);
                            currentSection = section.KeyValuePair;
                            Sections.Add(section);
                        }
                        else if (!line.StartsWith(";") && !line.StartsWith("#"))
                        {
                            var keyPair = line.Split('=', 2);
                            var key = keyPair[0].Trim();
                            var value = keyPair.Length > 1 ? keyPair[1].Trim() : null;
                            currentSection.Add(key, value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to read the INI file: {ex.Message}");
            }
        }

         /// <summary>
        /// Saves the INI file to the default file path using the appropriate encoding.
        /// </summary>
        public void SaveFile()
        {
            if (string.IsNullOrEmpty(FilePath))
            {
                throw new InvalidOperationException("FilePath is not specified.");
            }

            SaveFile(FilePath, DetermineEncoding(FilePath));
        }

         /// <summary>
        /// Saves the INI file to the specified file path using the appropriate encoding.
        /// </summary>
        /// <param name="filePath">The file path to save the INI file to.</param>
        public void SaveFile(string filePath)
        {
            SaveFile(filePath, DetermineEncoding(filePath));
        }

        /// <summary>
        /// Saves the INI file to the specified file path using the specified encoding.
        /// </summary>
        /// <param name="filePath">The file path to save the INI file to.</param>
        /// <param name="encoding">The encoding to use when saving the file.</param>
        public void SaveFile(string filePath, Encoding encoding)
        {
            try
            {
                var lines = new List<string>();

                // Global key-value pairs (no section)
                foreach (var kvp in KeyValuePair.KeyValues)
                {
                    if (kvp.Value == null)
                    {
                        lines.Add(kvp.Key);
                    }
                    else
                    {
                        lines.Add($"{kvp.Key}={kvp.Value}");
                    }
                }

                // Sections
                foreach (var section in Sections.Values)
                {
                    lines.Add($"[{section.SectionName}]");
                    foreach (var kvp in section.KeyValuePair.KeyValues)
                    {
                        if (kvp.Value == null)
                        {
                            lines.Add(kvp.Key);
                        }
                        else
                        {
                            lines.Add($"{kvp.Key}={kvp.Value}");
                        }
                    }
                    lines.Add(string.Empty);
                }

                File.WriteAllLines(filePath, lines, encoding);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to save the INI file: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines the encoding to be used based on the file name.
        /// </summary>
        /// <param name="filePath">The path of the file.</param>
        /// <returns>The encoding to use for the file.</returns>
        private Encoding DetermineEncoding(string filePath)
        {
            // If the file is named 'GptTmpl.inf', use Unicode (UTF-16 LE); otherwise, use UTF-8.
            if (Path.GetFileName(filePath).Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase))
            {
                return Encoding.Unicode; // UTF-16 LE
            }
            else
            {
                return Encoding.UTF8;
            }
        }

        /// <summary>
        /// Adds a new section to the INI file. If the section already exists, it will not be added.
        /// </summary>
        /// <param name="sectionName">The name of the section to be added.</param>
        public void AddSection(string sectionName)
        {
            if (!Sections.ContainsKey(sectionName))
            {
                var section = new IniSection(sectionName);
                Sections.Add(section);
            }
        }

        /// <summary>
        /// Checks if a section with the specified name exists in the INI file.
        /// </summary>
        /// <param name="sectionName">The name of the section to be checked.</param>
        /// <returns>True if the section exists; otherwise, false.</returns>
        public bool SectionExists(string sectionName)
        {
            return Sections.ContainsKey(sectionName);
        }

        /// <summary>
        /// Adds or updates a key-value pair in the specified section.
        /// </summary>
        /// <param name="sectionName">The name of the section where the key-value pair is to be added or updated.</param>
        /// <param name="key">The key to be added or updated.</param>
        /// <param name="value">The value to be associated with the key.</param>
        /// <exception cref="KeyNotFoundException">Thrown if the section does not exist.</exception>
        public void SetKeyValue(string sectionName, string key, string value)
        {
            if (Sections.ContainsKey(sectionName))
            {
                Sections.GetSection(sectionName).KeyValuePair.Add(key, value);
            }
            else
            {
                throw new KeyNotFoundException($"Section '{sectionName}' does not exist.");
            }
        }

        /// <summary>
        /// Retrieves the value associated with the specified key in the given section.
        /// </summary>
        /// <param name="sectionName">The name of the section from which the key-value pair is to be retrieved.</param>
        /// <param name="key">The key whose value is to be retrieved.</param>
        /// <returns>The value associated with the key, or null if the key does not exist.</returns>
        public string GetKeyValue(string sectionName, string key)
        {
            if (Sections.TryGetValue(sectionName, out IniSection section))
            {
                return section.KeyValuePair.GetValue(key);
            }
            return null;
        }
    } //end Class
} //end Namespace

'@


<#
# Examples of usage

# Check if a Section Exists
$sectionExists = $iniFile.SectionExists("SectionName")

# Add a New Section
$iniFile.AddSection("NewSectionName")

# Check if a Key Exists in a Section
$section = $null
$keyExists = $iniFile.Sections.TryGetValue("SectionName", [ref]$section) -and $section.KeyValuePair.KeyValues.ContainsKey("KeyName")

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
