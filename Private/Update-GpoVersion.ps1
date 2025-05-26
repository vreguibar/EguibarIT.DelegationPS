function Update-GpoVersion {

    <#
        .SYNOPSIS
            Updates the version number of specified Group Policy Objects (GPOs).

        .DESCRIPTION
            This function increments the computer version number of specified Group Policy Objects (GPOs).

            When Group Policy settings are modified programmatically (without using the Group Policy
            Management Console), the version numbers need to be manually updated to ensure the changes
            are properly applied to domain computers and users. This function handles that process by:

            - Updating the version number in the Active Directory GPO object
            - Updating the version number in the GPT.INI file in the SYSVOL share
            - Supporting both single GPO updates and batch processing via pipeline
            - Providing proper error handling and validation

            By default, the function increments the version by 3 (1 for user settings, 2 for computer
            settings) to ensure both parts are refreshed, but this can be customized.

        .PARAMETER GpoName
            The name of the Group Policy Object to update. This parameter accepts pipeline input,
            allowing for batch processing of multiple GPOs.

        .PARAMETER IncrementBy
            The number to increment the version by. Defaults to 3, which ensures both user (1)
            and computer (2) settings are refreshed. Valid values range from 1 to 100.

        .EXAMPLE
            Update-GpoVersion -GpoName "Default Domain Policy"

            Updates the version number of the "Default Domain Policy" GPO, incrementing it by 3.

        .EXAMPLE
            Get-GPO -All | Where-Object {$_.DisplayName -like "*Security*"} | Update-GpoVersion

            Updates version numbers for all GPOs with "Security" in their name, processing them
            via the pipeline.

        .EXAMPLE
            Update-GpoVersion -GpoName "Custom Security Policy" -IncrementBy 1

            Updates only the user settings version number for the specified GPO.

        .INPUTS
            System.String
            Microsoft.GroupPolicy.Gpo

            You can pipe GPO names as strings or GPO objects from Get-GPO to this function.

        .OUTPUTS
            System.Void

            This function does not generate any output. It modifies GPO version numbers directly.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-GPO                                    ║ GroupPolicy
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Import-MyModule                            ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .LINK
            https://learn.microsoft.com/en-us/powershell/module/groupolicy/get-gpo

        .COMPONENT
            Group Policy

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Group Policy Management
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name of the GPO.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'DisplayName')]
        [string]
        $GpoName,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Specify the increment number.',
            Position = 2)]
        [ValidateRange(1, 100)]
        [PSDefaultValue(Help = 'Default Value is "3"')]
        [int]
        $IncrementBy = 3

    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false

        ##############################
        # Variables Definition
        [Int64]$versionObject = $null

        # Retrieve the GPO object by name
        $gpo = Get-GPO -Name $PsBoundParameters['GpoName'] -ErrorAction Stop

        # Get the GPO ID
        $gpoId = ('{' + $gpo.Id + '}')

        # Build SYSVOL path
        $sysVolPath = '\\{0}\SYSVOL\{0}' -f $env:USERDNSDOMAIN
        $pathToGpt = '{0}\Policies\{1}\gpt.ini' -f $sysVolPath, $gpoId

        Write-Debug -Message ('Path to GPT: {0}' -f $pathToGpt)

    } #end Begin

    Process {

        Try {

            # Get the GPO object
            $url = 'LDAP://CN={0},CN=Policies,CN=System,{1}' -f $gpoId, $Variables.defaultNamingContext
            $de = [System.DirectoryServices.DirectoryEntry]::New($url)

            Write-Debug -Message ('Accessing GPO through DirectoryEntry: {0}' -f $url)

        } catch {

            Write-Error -Message ('Error accessing GPO through DirectoryEntry' -f $Gpo.Name)

        } #end Try-Catch

        # Get the VersionObject of the DirectoryEntry (the GPO)
        $versionObject = [Int64]($de.Properties['VersionNumber'].Value.ToString())

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

        # Use IncrementBy parameter
        $computerVN += $IncrementBy

        # Concatenate '0x' and 'HEX UserVersionNumber having 4 digits' and 'HEX ComputerVersionNumber having 4 digits'
        $newHex = '0x{0}{1}' -f $hexUserVN, $computerVN.ToString('x4')

        # Convert the New Hex number to integer
        $newVersionObject = [Convert]::ToInt64($newHex, 16)


        try {

            if ($PSCmdlet.ShouldProcess($GpoName, 'Update GPO version')) {

                # Update the GPO VersionNumber with the new value
                $de.Properties['VersionNumber'].Value = $newVersionObject.ToString()

                # Last, write the GPCMachineExtensionName attribute with the Client-Side Extension GUID
                # If not the settings won't display in the GPO Management tool and the target
                # server won't be able to read the GPO.
                $de.Properties['gPCMachineExtensionNames'].Value = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

                # Save the information on the DirectoryObject
                $de.CommitChanges()

                # Close the DirectoryEntry
                $de.Close()

                Write-Debug -Message ('Old GPO Version Number: {0}' -f $versionObject)
                Write-Debug -Message ('New GPO Version Number: {0}' -f $newVersionObject)

                # Write new version value to GPT (Including Section Name). Update SYSVOL file
                if (Test-Path -Path $pathToGpt) {

                    try {
                        # New instance of IniFile class
                        $Gpt = [IniFileHandler.IniFile]::new($pathToGpt)

                        # Check section exists
                        if ($Gpt.SectionExists('General')) {

                            Write-Debug -Message ('Section Name: General')

                            # Change value of an existing key
                            $Gpt.SetKeyValue('General', 'Version', $newVersionObject.ToString())
                            $Gpt.SetKeyValue('General', 'displayName', $Gpo.DisplayName)

                        } else {

                            Write-Debug -Message 'Section [General] does not exist. Creating it with Key=Value.'

                            $Gpt.AddSection('General')

                            # Add a new Key/Value pair within a given section
                            $Gpt.SetKeyValue('General', 'Version', $newVersionObject.ToString())
                            $Gpt.SetKeyValue('General', 'displayName', $Gpo.DisplayName)

                        } #end If-Else

                        # Save file using default encoding UTF-8
                        $Gpt.SaveFile($pathToGpt)

                        Write-Debug -Message ('Saving new Version of GPO {0} to file {1}' -f $Gpo.DisplayName, $pathToGpt)

                    } catch {

                        Write-Error -Message ('Failed to update GPT.INI for {0}: {1}' -f $Gpo.DisplayName, $_.Exception.Message)
                        continue

                    } #end Try-Catch

                } #end If

            } #end If

        } catch {

            throw "The GPTs.ini file could not be modified: $_. Message is $($_.Exception.Message)"

        } #end Try-Catch

    } #end Process

    End {

        if ($null -ne $Variables -and $null -ne $Variables.FooterDelegation) {
            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'Version of GPO updated (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end End
} #end function Update-GpoVersion
