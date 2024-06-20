# Helper Function: Update-GpoVersion
function Update-GpoVersion {

    <#
        .SYNOPSIS
            Updates the version number of a specified Group Policy Object (GPO).

        .DESCRIPTION
            The Update-GpoVersion function increments the computer version number of a specified GPO by 3. It updates both the directory object and the GPT.INI file in the SYSVOL share.

        .PARAMETER GpoName
            The name of the GPO to be updated.

        .EXAMPLE
            Update-GpoVersion -GpoName "Default Domain Policy"

        .INPUTS
            GPO Name.

        .OUTPUTS
            None.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name of the GPO.',
            Position = 0)]
        [string]
        $GpoName
    )

    Begin {

        [Int64]$versionObject = $null

        Import-Module -Name GroupPolicy -Verbose:$False

        # Retrieve the GPO object by name
        [GroupPolicy]$gpo = Get-GPO -Name $PsBoundParameters['GpoName'] -ErrorAction Stop
        # Get the GPO ID
        $gpoId = $gpo.Id
        # Build SYSVOL path
        $sysVolPath = '\\' + $env:USERDNSDOMAIN + '\SYSVOL\' + $env:USERDNSDOMAIN
        $pathToGpt = '{0}\Policies\{1}\gpt.ini' -f $sysVolPath, ('{' + $gpoId + '}')

    } #end Begin

    Process {

        Try {
            # Get the GPO object
            $url = 'LDAP://CN={0},CN=Policies,CN=System,{1}' -f ('{' + $gpoId + '}'), $Variables.defaultNamingContext
            $de = [System.DirectoryServices.DirectoryEntry]::New($url)
        } catch {
            Write-Error -Message ('Error accessing GPO through DirectoryEntry' -f $Gpo.Name)
        } #end Try-Catch

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


        try {

            if ($PSCmdlet.ShouldProcess($GpoName, 'Update GPO version')) {
                # Update the GPO VersionNumber with the new value
                $de.Properties['VersionNumber'].Value = $newVersionObject.ToString()

                # Save the information on the DirectoryObject
                $de.CommitChanges()

                # Close the DirectoryEntry
                $de.Close()

                # Write new version value to GPT (Including Section Name)
                if (Test-Path -Path $pathToGpt) {

<<<<<<< HEAD
                    # New instance of IniFile class
                    $Gpt = [IniFile]::new($pathToGpt)

                    # Check section exists
                    if ($Gpt.Sections.ContainsKey('General')) {
                        Write-Output "Section Name: $($ini.Sections.GetSection('General').SectionName)"

                        # Change value of an existing key
                        $Gpt.SetKeyValue('General', 'Version', $newVersionObject.ToString())

                    } else {
                        Write-Verbose -Message 'Section [General] does not exist. Creating it with Key=Value.'
                        # Add a new Key/Value pair within a given section
                        $Gpt.AddKeyValue('General', 'Version', $newVersionObject.ToString())
                    } #end If-Else

                    # Save file using default encoding UTF-8
                    $Gpt.SaveFile($PathToFile)

                    Write-Verbose -Message ('Saving new Version of GPO to file {0}' -f $pathToGpt)
                } #end If
            } #end If
        } catch {
            throw "The GPTs.ini file could not be modified: $_. Message is $($_.Exception.Message)"
        } #end Try-Catch

    } #end Process

    End {
        [string]$msg = ('Version of GPO updated. Original Number: {0}. New Number: {1}' -f $versionObject, $newVersionObject)
        Write-Verbose -Message $msg
    } #end End
=======
    } catch {
        Write-Error -Message "The GPTs.ini file could not be modified: $_. Message is $($_.Exception.Message)"

        throw
    } finally {
        Write-Verbose -Message ('Version of GPO updated. Original Number: {0}. New Number: {1}' -f $versionObject.ToString(), $newVersionObject.ToString())
    }
>>>>>>> f81291f8630e407ea33664afbf57598ec6425985
}
