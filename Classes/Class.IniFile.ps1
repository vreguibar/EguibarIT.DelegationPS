﻿Add-Type -Language CSharp -TypeDefinition @'

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IniFileHandler
{

/*################################################################################
       Represents a collection of key-value pairs in an INI section.
       Properties:
            KeyValues: Stores key-value pairs in a case-insensitive dictionary.
       Methods:
            Add(string key, string value): Adds or updates a key-value pair.
            ContainsKey(string key): Checks if a key exists.
            GetValue(string key): Retrieves the value for a key.
            SetValue(string key, string value): Sets the value for a key.
    */

    /// <summary>
    /// Represents a collection of key-value pairs in an INI file.
    /// </summary>
    public class IniKeyValuePair
    {

        /// <summary>
        /// Gets the dictionary containing the key-value pairs.
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
        /// Adds a new key-value pair or updates the value if the key exists.
        /// </summary>
        /// <param name="key">The key to add or update.</param>
        /// <param name="value">The value associated with the key.</param>
        public void Add(string key, string value)
        {
            if (!string.IsNullOrWhiteSpace(key))
                KeyValues[key] = value;
        }

        /// <summary>
        /// Checks if the specified key exists in the collection.
        /// </summary>
        /// <param name="key">The key to check for.</param>
        /// <returns><c>true</c> if the key exists; otherwise, <c>false</c>.</returns>
        public bool ContainsKey(string key)
        {
            return KeyValues.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key to retrieve the value for.</param>
        /// <returns>The value associated with the specified key, or <c>null</c> if the key does not exist.</returns>
        public string GetValue(string key)
        {
            KeyValues.TryGetValue(key, out var value);
            return value;
        }

        /// <summary>
        /// Sets the value for a specified key.
        /// </summary>
        /// <param name="key">The key to set the value for.</param>
        /// <param name="value">The value to set.</param>
        public void SetValue(string key, string value)
        {
            if (!string.IsNullOrWhiteSpace(key))
                KeyValues[key] = value;
        }
    } //end class IniKeyValuePair






    /*################################################################################
       Represents a section in an INI file containing a name and key-value pairs.
       Properties:
            SectionName: The name of the section.
            KeyValuePair: The key-value pairs within the section.
    */

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
        /// Gets the key-value pairs associated with this section.
        /// </summary>
        public IniKeyValuePair KeyValuePair { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniSection"/> class with a specified section name.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        public IniSection(string sectionName)
        {
            SectionName = sectionName;
            KeyValuePair = new IniKeyValuePair();
        }
    } //end class IniSection






    /*################################################################################
       Represents a collection of INI sections. Manages multiple INI sections.
       Properties:
            _sections: The internal dictionary holding section names and their corresponding IniSection objects.
       Methods:
            Add(IniSection section): Adds a section to the collection.
            ContainsKey(string sectionName): Checks if a section exists.
            GetSection(string sectionName): Retrieves a section.
            Values: Returns all sections.
    */

    /// <summary>
    /// Represents a collection of INI sections.
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
        /// Adds a new section to the collection or updates an existing section.
        /// </summary>
        /// <param name="section">The section to add or update.</param>
        public void Add(IniSection section)
        {
            if (!string.IsNullOrWhiteSpace(section.SectionName))
                _sections[section.SectionName] = section;
        }

         /// <summary>
        /// Checks if a section with the specified name exists in the collection.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        /// <returns><c>true</c> if the section exists; otherwise, <c>false</c>.</returns>
        public bool ContainsKey(string sectionName)
        {
            return _sections.ContainsKey(sectionName);
        }

        /// <summary>
        /// Gets the section with the specified name.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        /// <returns>The <see cref="IniSection"/> with the specified name, or <c>null</c> if the section does not exist.</returns>
        public IniSection GetSection(string sectionName)
        {
            _sections.TryGetValue(sectionName, out var section);
            return section;
        }

        /// <summary>
        /// Tries to get the section with the specified name.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        /// <param name="section">When this method returns, contains the <see cref="IniSection"/> with the specified name, if found; otherwise, <c>null</c>.</param>
        /// <returns><c>true</c> if the section exists; otherwise, <c>false</c>.</returns>
        public bool TryGetValue(string sectionName, out IniSection section)
        {
            return _sections.TryGetValue(sectionName, out section);
        }

        /// <summary>
        /// Gets the collection of all sections.
        /// </summary>
        public IEnumerable<IniSection> Values => _sections.Values;
    } //end class IniSections






    /*################################################################################
       Represents an INI file with sections and key-value pairs.
       Properties:
            FilePath: The path to the INI file.
            Sections: Collection of sections in the file.
            KeyValuePair: Global key-value pairs not associated with any section.
       Methods:
            ReadFile(string filePath): Reads and parses the INI file.
            SaveFile(): Saves the INI file with the default encoding.
            SaveFile(string filePath): Saves the INI file with the specified encoding.
            SaveFile(string filePath, Encoding encoding): Saves the INI file with a specific encoding.
            DetermineEncoding(string filePath): Determines the encoding based on the file name.
            AddSection(string sectionName): Adds a section.
            SectionExists(string sectionName): Checks if a section exists.
            SetKeyValue(string sectionName, string key, string value): Adds or updates a key-value pair.
            GetKeyValue(string sectionName, string key): Retrieves the value of a key.
    */

    /// <summary>
    /// Represents an INI file.
    /// </summary>
    public class IniFile
    {

        /// <summary>
        /// Gets or sets the file path of the INI file.
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// Gets the sections in the INI file.
        /// </summary>
        public IniSections Sections { get; }

        /// <summary>
        /// Gets the key-value pairs outside of any section.
        /// </summary>
        public IniKeyValuePair KeyValuePair { get; }

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
        /// Initializes a new instance of the <see cref="IniFile"/> class with the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the INI file.</param>
        /// <exception cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        public IniFile(string filePath) : this()
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            ReadFile(filePath);
        }

        /// <summary>
        /// Reads the INI file at the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the INI file.</param>
        /// <exception cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the specified INI file is not found.</exception>
        public void ReadFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("The specified INI file was not found.", filePath);

            FilePath = filePath;
            var encoding = DetermineEncoding(filePath);
            string[] iniLines = File.ReadAllLines(filePath, encoding);
            IniKeyValuePair currentSection = KeyValuePair;

            foreach (string line in iniLines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    string sectionName = line.Trim('[', ']');
                    IniSection section = new IniSection(sectionName);
                    currentSection = section.KeyValuePair;
                    Sections.Add(section);
                }
                else if (!line.StartsWith(";") && !line.StartsWith("#"))
                {
                    string[] keyPair = line.Split(new char[] { '=' }, 2);
                    string key = keyPair[0].Trim();
                    string value = keyPair.Length > 1 ? keyPair[1].Trim() : null;

                    currentSection.Add(key, value);
                }
            }
        }

        /// <summary>
        /// Saves the current state of the INI file to the associated file path.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when there is no associated file path.</exception>
        public void SaveFile()
        {
            if (string.IsNullOrEmpty(FilePath))
            {
                throw new InvalidOperationException("This INI record has no associated file.");
            }

            SaveFile(FilePath, DetermineEncoding(FilePath));
        }

        public void SaveFile(string filePath)
        {
            SaveFile(filePath, DetermineEncoding(filePath));
        }

        /// <summary>
        /// Saves the current state of the INI file to the specified file path.
        /// </summary>
        /// <param name="filePath">The file path to save the INI file to.</param>
        /// <param name="encoding">The encoding to use when saving the file.</param>
        /// <exception cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        public void SaveFile(string filePath, Encoding encoding)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            var lines = new List<string>();

            foreach (var kvp in KeyValuePair.KeyValues)
            {
                lines.Add(kvp.Value == null ? kvp.Key : $"{kvp.Key}={kvp.Value}");
            }

            foreach (var section in Sections.Values)
            {
                lines.Add($"[{section.SectionName}]");
                foreach (var kvp in section.KeyValuePair.KeyValues)
                {
                    lines.Add(kvp.Value == null ? kvp.Key : $"{kvp.Key}={kvp.Value}");
                }
                lines.Add(string.Empty); // Add an empty line after each section
            }

            File.WriteAllLines(filePath, lines, encoding);
        }

        /// <summary>
        /// Determines the encoding of the specified INI file based on its name.
        /// </summary>
        /// <param name="filePath">The path to the INI file.</param>
        /// <returns>The encoding of the file.</returns>
        private Encoding DetermineEncoding(string filePath)
        {
            return Path.GetFileName(filePath).Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase)
                ? Encoding.Unicode  // UTF-16 LE
                : Encoding.UTF8;
        }

        /// <summary>
        /// Adds a new section to the INI file.
        /// </summary>
        /// <param name="sectionName">The name of the section to add.</param>
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
        /// <param name="sectionName">The name of the section to check for.</param>
        /// <returns><c>true</c> if the section exists; otherwise, <c>false</c>.</returns>
        public bool SectionExists(string sectionName)
        {
            return Sections.ContainsKey(sectionName);
        }

        /// <summary>
        /// Sets the value for a specified key in a specified section.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        /// <param name="key">The key to set the value for.</param>
        /// <param name="value">The value to set.</param>
        /// <exception cref="KeyNotFoundException">Thrown when the section does not exist.</exception>
        public void SetKeyValue(string sectionName, string key, string value)
        {
            if (Sections.ContainsKey(sectionName))
            {
                Sections.GetSection(sectionName).KeyValuePair.SetValue(key, value);
            }
            else
            {
                throw new KeyNotFoundException($"Section '{sectionName}' does not exist.");
            }
        }

        /// <summary>
        /// Gets the value associated with the specified key in the specified section.
        /// </summary>
        /// <param name="sectionName">The name of the section.</param>
        /// <param name="key">The key to retrieve the value for.</param>
        /// <returns>The value associated with the specified key, or <c>null</c> if the key does not exist.</returns>
        public string GetKeyValue(string sectionName, string key)
        {
            if (Sections.TryGetValue(sectionName, out IniSection section))
            {
                return section.KeyValuePair.GetValue(key);
            }
            return null;
        }
    } //end class IniFile

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
