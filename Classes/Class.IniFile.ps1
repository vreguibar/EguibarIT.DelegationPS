# Load the assembly containing the IniFile class
Add-Type -Language CSharp -TypeDefinition @'


using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IniFileHandler
{
    //################################################################################

    public class IniKeyValuePair
    {
        public Dictionary<string, string> KeyValues { get; private set; }
        public IniKeyValuePair()
        {
            KeyValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        public void Add(string key, string value) { if (!string.IsNullOrWhiteSpace(key)) KeyValues[key] = value; }
        public bool ContainsKey(string key) { return KeyValues.ContainsKey(key); }
        public string GetValue(string key) { KeyValues.TryGetValue(key, out var value); return value; }
        public void SetValue(string key, string value) { if (!string.IsNullOrWhiteSpace(key)) KeyValues[key] = value; }
    } //end Class



    //################################################################################

    public class IniSection
    {
        public string SectionName { get; }
        public IniKeyValuePair KeyValuePair { get; }
        public IniSection(string sectionName)
        {
            SectionName = sectionName;
            KeyValuePair = new IniKeyValuePair();
        }
    } //end Class



    //################################################################################

    public class IniSections
    {
        private Dictionary<string, IniSection> _sections;
        public IniSections()
        {
            _sections = new Dictionary<string, IniSection>(StringComparer.OrdinalIgnoreCase);
        }
        public void Add(IniSection section) { if (!string.IsNullOrWhiteSpace(section.SectionName)) _sections[section.SectionName] = section; }
        public bool ContainsKey(string sectionName) { return _sections.ContainsKey(sectionName); }
        public IniSection GetSection(string sectionName) { _sections.TryGetValue(sectionName, out var section); return section; }
        public IEnumerable<IniSection> Values => _sections.Values;
    } //end Class



    //################################################################################

    public class IniFile
    {
        public string FilePath { get; private set; }
        public IniSections Sections { get; private set; }
        public IniKeyValuePair KeyValuePair { get; private set; }

        public IniFile()
        {
            Sections = new IniSections();
            KeyValuePair = new IniKeyValuePair();
            FilePath = string.Empty;
        }

        public IniFile(string filePath) : this()
        {
            ReadFile(filePath);
        }

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

        public void SaveFile()
        {
            if (string.IsNullOrEmpty(FilePath))
            {
                throw new InvalidOperationException("FilePath is not specified.");
            }

            SaveFile(FilePath, DetermineEncoding(FilePath));
        }

        public void SaveFile(string filePath)
        {
            SaveFile(filePath, DetermineEncoding(filePath));
        }

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
                foreach (var section in Sections.Sections.Values)
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

        // Existing methods like SectionExists, AddSection, GetKeyValue, etc.
        public void AddSection(string sectionName)
        {
            if (!Sections.ContainsKey(sectionName))
            {
                var section = new IniSection(sectionName);
                Sections.Add(section);
            }
        }

        public bool SectionExists(string sectionName)
        {
            return Sections.ContainsKey(sectionName);
        }

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
