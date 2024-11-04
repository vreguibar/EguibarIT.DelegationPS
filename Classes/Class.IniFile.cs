using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IniFileHandler
{
    /// <summary>
    /// Represents an entry in an INI section that can be either a key-value pair or a simple string.
    /// </summary>
    public class IniEntry
    {
        /// <summary>
        /// Gets or sets the key if this is a key-value pair entry.
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the value. For key-value pairs, this is the value part.
        /// For simple strings, this contains the entire string.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Gets or sets whether this entry is a simple string rather than a key-value pair.
        /// </summary>
        public bool IsSimpleString { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniEntry"/> class as a key-value pair.
        /// </summary>
        public IniEntry(string key, string value)
        {
            Key = key;
            Value = value;
            IsSimpleString = false;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IniEntry"/> class as a simple string.
        /// </summary>
        public IniEntry(string value)
        {
            Value = value;
            IsSimpleString = true;
        }
    } //end class IniEntry





    /// <summary>
    /// Represents a collection of entries in an INI section.
    /// </summary>
    public class IniEntryCollection
    {
        private readonly Dictionary<string, IniEntry> _keyValueEntries;
        private readonly List<IniEntry> _simpleEntries;

        /// <summary>
        /// Gets all entries in this collection.
        /// </summary>
        public IEnumerable<IniEntry> AllEntries
        {
            get
            {
                foreach (var entry in _keyValueEntries.Values)
                    yield return entry;
                foreach (var entry in _simpleEntries)
                    yield return entry;
            }
        }

        public IniEntryCollection()
        {
            _keyValueEntries = new Dictionary<string, IniEntry>(StringComparer.OrdinalIgnoreCase);
            _simpleEntries = new List<IniEntry>();
        }

        /// <summary>
        /// Adds a key-value pair entry.
        /// </summary>
        public void AddKeyValue(string key, string value)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or empty.", nameof(key));
            _keyValueEntries[key] = new IniEntry(key, value);
        }

        /// <summary>
        /// Adds a simple string entry.
        /// </summary>
        public void AddSimpleString(string value)
        {
            _simpleEntries.Add(new IniEntry(value));
        }

        /// <summary>
        /// Gets the value for a specific key.
        /// </summary>
        public string GetValue(string key)
        {
            return _keyValueEntries.TryGetValue(key, out var entry) ? entry.Value : null;
        }

        /// <summary>
        /// Checks if a key exists in the key-value pairs.
        /// </summary>
        public bool ContainsKey(string key)
        {
            return _keyValueEntries.ContainsKey(key);
        }

        /// <summary>
        /// Gets all simple string entries.
        /// </summary>
        public IEnumerable<string> GetSimpleStrings()
        {
            return _simpleEntries.ConvertAll(e => e.Value);
        }
    } //end class IniEntryCollection





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
        public string SectionName { get; set; }

        /// <summary>
        /// Gets the entries associated with this section.
        /// </summary>
        public IniEntryCollection Entries { get; private set; }

        public IniSection(string sectionName)
        {
            if (string.IsNullOrWhiteSpace(sectionName))
                throw new ArgumentException("Section name cannot be null or empty.", nameof(sectionName));
            SectionName = sectionName;
            Entries = new IniEntryCollection();
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
        /// <summary>
        /// Gets the dictionary of sections.
        /// </summary>
        public Dictionary<string, IniSection> Sections { get; private set; }

        /// <summary>
        /// Initializes a new instance of the cref="IniSections"/> class.
        /// </summary>
        public IniSections()
        {
            Sections = new Dictionary<string, IniSection>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Adds a new section to the collection or updates an existing section.
        /// </summary>
        /// name="section">The section to add or update.</param>
        public void Add(IniSection section)
        {
            if (section == null || string.IsNullOrWhiteSpace(section.SectionName))
                throw new ArgumentException("Section cannot be null and must have a name.", nameof(section));
            Sections[section.SectionName] = section;
        }

        /// <summary>
        /// Checks if a section with the specified name exists in the collection.
        /// </summary>
        /// name="sectionName">The name of the section.</param>
        /// if the section exists; otherwise, <c>false</c>.</returns>
        public bool ContainsKey(string sectionName)
        {
            return Sections.ContainsKey(sectionName);
        }

        /// <summary>
        /// Gets the section with the specified name.
        /// </summary>
        /// name="sectionName">The name of the section.</param>
        /// cref="IniSection"/> with the specified name, or if the section does not exist.</returns>
        public IniSection GetSection(string sectionName)
        {
            return Sections.TryGetValue(sectionName, out IniSection section) ? section : null;
        }

        /// <summary>
        /// Tries to get the section with the specified name.
        /// </summary>
        /// name="sectionName">The name of the section.</param>
        /// name="section">When this method returns, contains the cref="IniSection"/> with the specified name, if found; otherwise, <c>null</c>.</param>
        /// if the section exists; otherwise, <c>false</c>.</returns>
        public bool TryGetValue(string sectionName, out IniSection section)
        {
            return Sections.TryGetValue(sectionName, out section);
        }

        /// <summary>
        /// Gets the collection of all sections.
        /// </summary>
        public IEnumerable<IniSection> Values => Sections.Values;
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
    public class IniFile : IDisposable
    {
        /// <summary>
        /// Gets or sets the file path of the INI file.
        /// </summary>
        public string FilePath { get; private set; }

        /// <summary>
        /// Gets the sections in the INI file.
        /// </summary>
        public IniSections Sections { get; private set; }


        public IniEntryCollection GlobalEntries { get; private set; }
        private bool _disposed = false;


        /// <summary>
        /// Initializes a new instance of the cref="IniFile"/> class.
        /// </summary>
        public IniFile()
        {
            Sections = new IniSections();
            GlobalEntries = new IniEntryCollection();
            FilePath = string.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the cref="IniFile"/> class with the specified file path.
        /// </summary>
        /// name="filePath">The path to the INI file.</param>
        /// cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        public IniFile(string filePath) : this()
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            ReadFile(filePath);
        }

        /// <summary>
        /// Reads the INI file at the specified file path.
        /// </summary>
        /// name="filePath">The path to the INI file.</param>
        /// cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        /// cref="FileNotFoundException">Thrown when the specified INI file is not found.</exception>
        public void ReadFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("The specified INI file was not found.", filePath);

            FilePath = filePath;
            var encoding = DetermineEncoding(filePath);

            using (var reader = new StreamReader(filePath, encoding))
            {
                IniEntryCollection currentCollection = GlobalEntries;
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    if (line.StartsWith(";") || line.StartsWith("#")) continue;

                    if (line.StartsWith("[") && line.EndsWith("]"))
                    {
                        string sectionName = line.Trim('[', ']');
                        IniSection section = new IniSection(sectionName);
                        currentCollection = section.Entries;
                        Sections.Add(section);
                    }
                    else
                    {
                        int separatorIndex = line.IndexOf('=');
                        if (separatorIndex != -1)
                        {
                            string key = line.Substring(0, separatorIndex).Trim();
                            string value = separatorIndex < line.Length - 1 ?
                                line.Substring(separatorIndex + 1).Trim() : null;
                            currentCollection.AddKeyValue(key, value);
                        }
                        else
                        {
                            currentCollection.AddSimpleString(line);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Saves the current state of the INI file to the associated file path.
        /// </summary>
        /// cref="InvalidOperationException">Thrown when there is no associated file path.</exception>
        public void SaveFile()
        {
            if (string.IsNullOrEmpty(FilePath))
                throw new InvalidOperationException("This INI record has no associated file.");

            SaveFile(FilePath, DetermineEncoding(FilePath));
        }

        public void SaveFile(string filePath)
        {
            SaveFile(filePath, DetermineEncoding(filePath));
        }

        /// <summary>
        /// Saves the current state of the INI file to the specified file path.
        /// </summary>
        /// name="filePath">The file path to save the INI file to.</param>
        /// name="encoding">The encoding to use when saving the file.</param>
        /// cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        public void SaveFile(string filePath, Encoding encoding)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            using (var writer = new StreamWriter(filePath, false, encoding))
            {
                // Write global entries
                foreach (var entry in GlobalEntries.AllEntries)
                {
                    WriteEntry(writer, entry);
                }

                // Write sections
                foreach (var section in Sections.Values)
                {
                    writer.WriteLine();
                    writer.WriteLine($"[{section.SectionName}]");
                    foreach (var entry in section.Entries.AllEntries)
                    {
                        WriteEntry(writer, entry);
                    }
                }
            }
        }


        private void WriteEntry(StreamWriter writer, IniEntry entry)
        {
            if (entry.IsSimpleString)
            {
                writer.WriteLine(entry.Value);
            }
            else
            {
                writer.WriteLine(entry.Value == null ? entry.Key : $"{entry.Key}={entry.Value}");
            }
        }

        /// <summary>
        /// Determines the encoding of the specified INI file based on its name.
        /// </summary>
        /// name="filePath">The path to the INI file.</param>
        /// encoding of the file.</returns>
        private Encoding DetermineEncoding(string filePath)
        {
            return Path.GetFileName(filePath).Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase)
                ? Encoding.Unicode  // UTF-16 LE
                : Encoding.UTF8;
        }

        /// <summary>
        /// Adds a new section to the INI file.
        /// </summary>
        /// name="sectionName">The name of the section to add.</param>
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
        /// name="sectionName">The name of the section to check for.</param>
        /// if the section exists; otherwise, <c>false</c>.</returns>
        public bool SectionExists(string sectionName)
        {
            return Sections.ContainsKey(sectionName);
        }

        public void AddSimpleString(string sectionName, string value)
        {
            if (Sections.TryGetValue(sectionName, out var section))
            {
                section.Entries.AddSimpleString(value);
            }
            else
            {
                throw new KeyNotFoundException($"Section '{sectionName}' does not exist.");
            }
        }

        /// <summary>
        /// Sets the value for a specified key in a specified section.
        /// </summary>
        /// name="sectionName">The name of the section.</param>
        /// name="key">The key to set the value for.</param>
        /// name="value">The value to set.</param>
        /// cref="KeyNotFoundException">Thrown when the section does not exist.</exception>
        public void SetKeyValue(string sectionName, string key, string value)
        {
            if (Sections.TryGetValue(sectionName, out var section))
            {
                section.Entries.AddKeyValue(key, value);
            }
            else
            {
                throw new KeyNotFoundException($"Section '{sectionName}' does not exist.");
            }
        }

        /// <summary>
        /// Gets the value associated with the specified key in the specified section.
        /// </summary>
        /// name="sectionName">The name of the section.</param>
        /// name="key">The key to retrieve the value for.</param>
        /// value associated with the specified key, or if the key does not exist.</returns>
        public string GetKeyValue(string sectionName, string key)
        {
            if (Sections.TryGetValue(sectionName, out IniSection section))
            {
                return section.Entries.GetValue(key);
            }
            return null;
        }

        public IEnumerable<string> GetSimpleStrings(string sectionName)
        {
            if (Sections.TryGetValue(sectionName, out IniSection section))
            {
                return section.Entries.GetSimpleStrings();
            }
            return new List<string>();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources if any
                }
                _disposed = true;
            }
        }
    } //end class IniFile
} //end Namespace IniFileHandler
