# Helper Function: Update-GpoVersion
function Update-GpoVersion {
    param (
        [string]$GpoName
    )
    $gpo = Get-Gpo -Name $GpoName -ErrorAction Stop
    $gpoId = $gpo.Id
    $sysVolPath = '\\' + $env:USERDNSDOMAIN + '\SYSVOL\' + $env:USERDNSDOMAIN
    $pathToGpt = '{0}\Policies\{1}\gpt.ini' -f $sysVolPath, $gpoId

    try {
        # Get the GPO object
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN={$gpoId},CN=Policies,CN=System,$env:USERDNSDOMAIN")

        # Get the VersionObject of the DirectoryEntry (the GPO)
        $versionObject = [Int64]($de.Properties['VersionNumber'].Value.ToString())

        Write-Verbose -Message ('Old GPO Version Number: {0}' -f $versionObject)

        # Convert the value into a 8 digit HEX string
        $hexValue = $versionObject.ToString('x8')

        # Top 16 bits HEX UserVersionNumber - first 4 characters (complete with zero to the left)
        # This is the UserVersion
        $hexUserVN = $hexValue.Substring(0, 4)

        # Lower 16 bits HEX ComputerVersionNumber - last 4 characters (complete with zero to the left)
        # This is the ComputerVersion
        $hexComputerVN = $hexValue.Substring(4)

        # Lower 16 bits as Integer ComputerVersionNumber
        $computerVN = [Convert]::ToInt64($hexComputerVN, 16)

        # Increment Computer Version Number by 3
        $computerVN += 3

        # Concatenate '0x' and 'HEX UserVersionNumber having 4 digits' and 'HEX ComputerVersionNumber having 4 digits'
        $newHex = '0x{0}{1}' -f $hexUserVN, $computerVN.ToString('x4')

        # Convert the New Hex number to integer
        $newVersionObject = [Convert]::ToInt64($newHex, 16)

        # Update the GPO VersionNumber with the new value
        $de.Properties['VersionNumber'].Value = $newVersionObject.ToString()

        # Save the information on the DirectoryObject
        $de.CommitChanges()

        # Close the DirectoryEntry
        $de.Close()

        # Write new version value to GPT (Including Section Name)
        if (Test-Path -Path $pathToGpt) {
            # Create Hashtable with corresponding data
            $gpt = @{'General' = @{'Version' = $newVersionObject.ToString() } }

            # Save Hashtable to the GPT.INI file
            $gpt | Out-IniFile -FilePath $pathToGpt -Force

            Write-Verbose -Message ('Saving new Version of GPO to file {0}' -f $pathToGpt)
        }

    } catch {
        throw "The GPTs.ini file could not be modified: $_. Message is $($_.Exception.Message)"
    } finally {
        Write-Verbose -Message ('Version of GPO updated. Original Number: {0}. New Number: {1}' -f $versionObject.ToString(), $newVersionObject.ToString())
    }
}
