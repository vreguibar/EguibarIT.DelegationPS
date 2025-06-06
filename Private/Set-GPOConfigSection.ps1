function Set-GPOConfigSection {

    <#
        .SYNOPSIS
            Configures a specific section and key in a GPT template (GptTmpl.inf) file with specified members.

        .DESCRIPTION
            This function creates a new key or updates an existing key within a specified section of a GPT template
            (GptTmpl.inf represented by [IniFileHandler.IniFile] class) file. It processes and merges existing values
            (if the key exists) with new members, ensuring correct resolution of SIDs and avoiding duplicates.
            A single Null-string is considered a valid value.

            The function properly handles cases where privilege right keys appear as values in the GPT template
            and avoids attempting to resolve them as SIDs. It also gracefully handles empty/null values
            and properly formats the output for the GPT template format.

            1.- Check if the provided section (Parameter CurrentSection) exist on the [IniFileHandler.IniFile]$GptTmpl
                variable (Parameter GptTmpl)
            2.- Section exists (GptTmpl does contains the section)
            3.- Check if Key exist. If key does not exist, just create it and continue with step 4
                A.- If key exist, get the values contained.
                    Value can be a single $null string
                    comma delimited string being each item a member represented by its SID and * prefix

                    (for example,
                        Administrators would be *S-1-5-32-544,
                        Event Log Readers would be *S-1-5-32-573,
                        Server Operators would be *S-1-5-32-549...
                        full string value would be *S-1-5-32-544,*S-1-5-32-573,*S-1-5-32-549 ).

                E.- Get value as array and strip prefix "*", just having pure SID.
                F.- Iterate through all members, except if just 1 value and this is null.
                G.- Each member or iteration has to be resolved (first remove * prefix, otherwise will throw an error),
                    either a Well-Known SID or a "normal" SID. Excluding WellKnownSids, have SID translated to an
                    account to ensure that it continues to exist on ActiveDirectory. If the account is successfully
                    translated, meaning it does exist in AD, and it can be added to the OK list with an * prefix.
                    Skip duplicated. WellKnownSids can be added directly with * prefix.
                H.- If the account does not exist, it should be skipped and a warning should be displayed.
            4.- Key did not exist, so no values exist either. Key was created earlier.
                A.- Get new members from Parameter Members (This parameter can accept $null and should be treated as
                    a single null string)
                B.- Each member or iteration has to be resolved, either a Well-Known SID or a "normal" SID. Having SID
                    translated to an account to ensure that it continues to exist on ActiveDirectory. If the account is
                    successfully translated, meaning it does exist in AD, it can be added to the OK list with an * prefix.
                    Skip duplicated. WellKnownSids can be added directly with * prefix.
            5.- Convert the List to a comma-delimited string (except if nullString single instance).
                trim end comma, period or space.
            6. Add key and value the $GptTmpl
            7.- Return updated $GptTmpl

        .PARAMETER CurrentSection
             The section in the GPT template file to be configured (e.g., "Privilege Rights" or "Registry Values").
             This section is assumed to exist.

        .PARAMETER CurrentKey
             The key within the given section (e.g., "SeAuditPrivilege" or "SeBatchLogonRight").

        .PARAMETER Members
            An array of members to be added to the key. Can be null, which will be treated as a single null string.

        .PARAMETER GptTmpl
            The GPT template object representing the GptTmpl.inf file of type [IniFileHandler.IniFile].

        .OUTPUTS
            [IniFileHandler.IniFile]

        .EXAMPLE
            Set-GPOConfigSection -CurrentSection "User Rights Assignment" `
                -CurrentKey "SeDenyNetworkLogonRight" `
                -Members @("TheUgly", "SG_AdAdmins") `
                -GptTmpl $GptTmpl

        .EXAMPLE
            Set-GPOConfigSection -CurrentSection "Privilege Rights" `
                -CurrentKey "SeAuditPrivilege" `
                -Members @("TheGood", "SG_InfraAdmins") `
                -GptTmpl $GptTmpl

        .NOTES
            Required modules/prerequisites:
                - ActiveDirectory
                - GroupPolicy
                - EguibarIT
                - EguibarIT.DelegationPS

            Used Functions:
                Name                                        ║ Module/Namespace
                ════════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                               ║ Microsoft.PowerShell.Utility
                Write-Warning                               ║ Microsoft.PowerShell.Utility
                Write-Error                                 ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                         ║ EguibarIT.DelegationPS
                Convert-SidToName                           ║ EguibarIT.DelegationPS
                Get-AdObjectType                            ║ EguibarIT.DelegationPS
                IniFileHandler.IniFile                      ║ EguibarIT.DelegationPS

        .NOTES
            Version:         1.4
            DateModified:    27/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([IniFileHandler.IniFile])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The section in the GPT template file to be configured (ex. [Privilege Rights] or [Registry Values]).',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CurrentSection,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The KEY within given section (ex. SeAuditPrivilege or SeBatchLogonRight).',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CurrentKey,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Member of given KEY. This value can be Empty or Null',
            Position = 2)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]
        $Members,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Object representing the INI file values.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [IniFileHandler.IniFile]
        $GptTmpl
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderDelegation) {

            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $resolvedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        # Regular expression to validate SID format - Fixed to allow well-known SIDs
        $sidRegex = '^S-\d+-\d+(-\d+)*$'

        # Regular expression to detect privilege right keys that might appear as values
        $privilegeKeyRegex = '^Se[A-Za-z]+Privilege$|^Se[A-Za-z]+Right$'

    } #end Begin

    Process {

        try {

            # Ensure Members is properly initialized
            if ($null -eq $Members) {

                Write-Debug -Message 'Members is null, creating new empty list'
                $Members = [System.Collections.Generic.List[object]]::new()

            } elseif ($Members -is [hashtable]) {

                Write-Debug -Message 'Members is hashtable, converting to list'
                $tempList = [System.Collections.Generic.List[object]]::new()

                foreach ($key in $Members.Keys) {

                    $tempList.Add($Members[$key])

                } #end foreach

                $Members = $tempList

            } elseif ($Members -is [string] -or
                $Members -isnot [System.Collections.IEnumerable]) {

                # If Members is a single string or not enumerable, wrap in a list
                Write-Debug -Message 'Members is single string or not enumerable, creating wrapper list'
                $tmpList = [System.Collections.Generic.List[object]]::new()

                if ($null -ne $Members) {
                    $tmpList.Add($Members)
                } #end if
                $Members = $tmpList

            } elseif ($Members -isnot [System.Collections.Generic.List[object]]) {

                # If Members is not a List, convert it to one
                Write-Debug -Message 'Members is not a List, converting to List'
                $tempList = [System.Collections.Generic.List[object]]::new()

                try {

                    foreach ($item in $Members) {

                        if ($null -ne $item) {
                            $tempList.Add($item)
                        } #end if

                    } #end foreach

                } catch {
                    Write-Debug -Message ('Error iterating Members collection: {0}' -f $_.Exception.Message)
                } #end try-catch

                $Members = $tempList
            } #end if-elseif-else

            # Check if Members is empty or has only empty strings
            $hasValidMembers = $false
            if ($Members.Count -gt 0) {

                foreach ($member in $Members) {

                    if (-not [string]::IsNullOrWhiteSpace($member)) {

                        $hasValidMembers = $true
                        break
                    } #end if

                } #end foreach

            } #end if

            # If no valid members, use empty list
            if (-not $hasValidMembers) {

                Write-Debug -Message 'No valid members found, using empty list'
                $Members = [System.Collections.Generic.List[object]]::new()

            } #end if

            # Ensure section exists (e.g., "Privilege Rights" or "Registry Values")
            if (-not $GptTmpl.SectionExists($CurrentSection)) {

                Write-Debug -Message ('Creating missing section: {0}' -f $CurrentSection)
                $GptTmpl.AddSection($CurrentSection)

            } #end if

            # Get existing Value from current Key from $GptTmpl.
            # Value can ONLY be Null, or String (*S-1-5-32-546,*S-1-5-21-1913705174-2885708358-485712852-2125)
            $currentValue = $GptTmpl.GetKeyValue($CurrentSection, $CurrentKey)

            Write-Debug -Message ('Current value for {0}.{1}: {2}' -f $CurrentSection, $CurrentKey,
                $(if ([string]::IsNullOrEmpty($currentValue)) {
                        '<empty>'
                    } else {
                        $currentValue
                    })
            )

            # Parse existing members.
            $existingMembers = [System.Collections.Generic.List[string]]::new()

            if (-not [string]::IsNullOrEmpty($currentValue)) {

                # Check if the value is the same as the key (e.g., "SeAuditPrivilege")
                if ($currentValue -eq $CurrentKey) {

                    Write-Debug -Message 'Current value matches key name, treating as empty'

                } elseif ($currentValue -match $privilegeKeyRegex) {

                    Write-Debug -Message ('Value matches privilege key pattern: {0}, treating as empty' -f $currentValue)

                } else {

                    # Split by comma and add non-empty entries to existingMembers
                    $valueItems = $currentValue.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)

                    foreach ($item in $valueItems) {

                        # remove leading asterix '*'
                        $sid = $item.TrimStart('*')

                        # add to existingMembers
                        $existingMembers.Add($sid.Trim())

                    } #end foreach
                    Write-Debug -Message ('Parsed {0} existing member(s) from value' -f $existingMembers.Count)

                } #end if-elseif-else

            } #end if

            # Process existing members. Verify if they are valid SIDs.
            # add to resolvedMembers HashSet
            foreach ($member in $existingMembers) {

                # Skip if member is empty
                if ([string]::IsNullOrWhiteSpace($member)) {
                    continue
                } #end if

                # Remove leading asterisk if present
                $sid = $member.TrimStart('*')

                # Skip if member name matches a privilege key pattern
                if ($sid -match $privilegeKeyRegex) {

                    Write-Debug -Message ('Skipping member that looks like a privilege key: {0}' -f $sid)
                    continue

                } #end if

                # Validate SID format using regex pattern if it's not empty
                if (-not [string]::IsNullOrEmpty($sid) -and
                    -not ($sid -match $sidRegex)) {

                    Write-Warning -Message ('Value does not match SID format: {0}. Skipping.' -f $sid)
                    continue

                } #end if

                # Try to resolve the SID to confirm it's valid
                try {

                    $resolvedAccount = $null

                    # Only try to resolve non-empty SIDs
                    if (-not [string]::IsNullOrEmpty($sid)) {

                        $resolvedAccount = Convert-SidToName -SID $sid -ErrorAction SilentlyContinue

                    } #end if

                    # If resolved successfully, add to resolvedMembers with asterisk prefix
                    if ($resolvedAccount) {

                        # Add with asterisk prefix for GptTmpl format
                        [void]$resolvedMembers.Add('*' + $sid)
                        Write-Debug -Message ('Resolved existing member: {0} to SID: {1}' -f $resolvedAccount, $sid)

                    } else {

                        Write-Warning -Message ('Could not resolve existing SID: {0}. It may not exist anymore.' -f $sid)

                    } #end if

                } catch {

                    Write-Warning -Message ('Failed to process existing member {0}: {1}' -f $sid, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            # Process new members from parameter Members
            foreach ($member in $Members) {

                # Skip if member is empty
                if ([string]::IsNullOrWhiteSpace($member)) {
                    continue
                } #end if

                try {
                    # Get AD object information
                    $adObject = Get-AdObjectType -Identity $member -ErrorAction SilentlyContinue

                    if ($null -eq $adObject) {
                        Write-Warning -Message ('Could not resolve member: {0}' -f $member)
                        continue
                    } #end if

                    # Extract SID based on type
                    $sid = $null

                    # Handle different object types to extract SID
                    if ($adObject -is [string] -and
                        $adObject -match $sidRegex) {

                        # Already a SID string
                        $sid = $adObject
                        Write-Debug -Message ('Member {0} is a SID string: {1}' -f $member, $sid)

                    } elseif ($adObject -is [System.Security.Principal.SecurityIdentifier]) {

                        # SecurityIdentifier object
                        $sid = $adObject.Value
                        Write-Debug -Message ('Member {0} is a SecurityIdentifier: {1}' -f $member, $sid)

                    } elseif ($null -ne $adObject.SID -and
                        $adObject.SID -is [System.Security.Principal.SecurityIdentifier]) {

                        # AD object with SID property that is a SecurityIdentifier
                        $sid = $adObject.SID.Value
                        Write-Debug -Message ('Member {0} has ObjectSID: {1}' -f $member, $sid)

                    } elseif ($null -ne $adObject.ObjectSID -and
                        $adObject.ObjectSID -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {

                        # Handle AD objects with ObjectSID as ADPropertyValueCollection
                        if ($adObject.ObjectSID.Count -gt 0) {

                            $sidValue = $adObject.ObjectSID[0]
                            if ($sidValue -is [System.Security.Principal.SecurityIdentifier]) {

                                $sid = $sidValue.Value

                            } else {

                                $sid = $sidValue.ToString()

                            } #end if-else

                            Write-Debug -Message ('Member {0} has ADPropertyValueCollection ObjectSID: {1}' -f $member, $sid)

                        } else {

                            Write-Warning -Message ('Member {0} has empty ObjectSID collection' -f $member)
                            continue

                        } #end if-else

                    } elseif ($null -ne $adObject.ObjectSID) {

                        # AD object with ObjectSID property that is a string
                        $sid = $adObject.ObjectSID
                        Write-Debug -Message ('Member {0} has string ObjectSID: {1}' -f $member, $sid)

                    } elseif ($null -ne $adObject.PSObject -and
                        $adObject.PSObject.Properties -and
                        $adObject.PSObject.Properties['Value'] -and
                        $adObject.PSObject.Properties['Value'].Value -match $sidRegex) {

                        # Object with Value property that is a SID
                        $sid = $adObject.Value
                        Write-Debug -Message ('Member {0} has Value property with SID: {1}' -f $member, $sid)

                    } else {

                        Write-Warning -Message ('Could not extract SID from member: {0}' -f $member)
                        continue

                    } #end if-elseif-else

                    # Validate extracted SID
                    if (-not [string]::IsNullOrEmpty($sid) -and
                        $sid -match $sidRegex) {

                        # Add to collection (with * prefix for GptTmpl format)
                        [void]$resolvedMembers.Add('*' + $sid)
                        Write-Debug -Message ('Added member {0} with SID: {1}' -f $member, $sid)

                    } else {

                        Write-Warning -Message ('Invalid SID extracted for member {0}: {1}' -f $member, $sid)

                    } #end if

                } catch {

                    Write-Warning -Message ('Error processing member {0}: {1}' -f $member, $_.Exception.Message)

                } #end try-catch
            } #end foreach

            # Create the final value for GptTmpl.inf format
            $finalValue = [string]::Empty
            if ($resolvedMembers.Count -gt 0) {
                $finalValue = $resolvedMembers -join ','
            } #end if

            # Update the GPO template
            if ($PSCmdlet.ShouldProcess("$CurrentSection -> $CurrentKey", 'Updating GptTmpl')) {

                $GptTmpl.SetKeyValue($CurrentSection, $CurrentKey, $finalValue)

                $memberDisplay = if ([string]::IsNullOrEmpty($finalValue)) {
                    '<empty>'
                } else {
                    $finalValue
                }

                Write-Verbose -Message (
                    'GPO section updated:
                        Section: {0}
                        Key:     {1}
                        Members: {2}' -f
                    $CurrentSection, $CurrentKey, $memberDisplay
                )
            } #end if

        } catch {

            Write-Error -Message ('Error in Set-GPOConfigSection processing {0}: {1}' -f $CurrentKey, $_.Exception.Message)
            Write-Debug -Message ('Stack trace: {0}' -f $_.Exception.StackTrace)
        } #end try-catch
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'configuration of GptTmpl object section (Private Function).')
            Write-Verbose -Message $txt
        } #end if
        return $GptTmpl
    } #end End
} #end function Set-GPOConfigSection
