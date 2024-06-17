# Helper Function: Confirm-GptMember
function Confirm-GptMember {

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Collections.Hashtable])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Hashtable containing the values from IniHashtable.inf file',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $iniContent,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'String representing the section to configure/Change on the file',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Section,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'String representing the KEY to configure/Change on the file',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Key,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'List of members to be configured as a value for the KEY.',
            Position = 3)]
        [System.Collections.Generic.List[object]]
        $Members
    )

    Begin {

        # Initialize an empty list to hold valid SIDs
        $ValidSids = [System.Collections.Generic.List[object]]::new()


        # Helper function to resolve a name to a SID
        function Resolve-Sid {
            param (
                [string]$Name
            )
            try {
                $sid = ([System.Security.Principal.NTAccount]::New($Name.Trim('*'))).Translate([System.Security.Principal.SecurityIdentifier])
                return $sid.Value
            } catch {
                Write-Verbose -Message ('Failed to resolve SID for {0}' -f $Name)
                return $null
            }
        }

    } #end Begin

    Process {

        # Get existing members (get members from $iniContent)
        If ($iniContent[$Section].Contains($Key)) {
            Write-Verbose -Message ('Key "{0}" found. Getting existing values.' -f $Key)

            # Get existing value and split it into a list
            $ExistingMembers = ($iniContent.$Section.$Key).Split(',')

        } #end If

        # Check if there are ExistingMembers
        If ($ExistingMembers) {
            # Iterate Existing Members
            Foreach ($Item in $ExistingMembers) {
                # Skip empty lines
                if ([string]::IsNullOrWhiteSpace($Item)) {
                    continue
                } #end If

                # Check if the member is already a valid SID
                #if (Test-IsValidSID -ObjectSID $Item) {

                # Resolve the member to a SID
                $resolvedSid = Resolve-Sid -Name $Item

                if ($null -ne $resolvedSid) {
                    $ValidSids.Add('*{0}' -f $resolvedSid)
                } else {
                    Write-Verbose -Message ('Skipping invalid member: {0}' -f $Item)
                } #end If-Else
                #} #end If
            } #end Foreach
        } #end If

        # Check for NewMembers
        foreach ($member in $Members) {

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($member)) {
                continue
            } #end If

            # Check if the member is already a valid SID
            #if (Test-IsValidSID -ObjectSID $member) {

            # Resolve the member to a SID
            $resolvedSid = Resolve-Sid -Name $member

            if ($null -ne $resolvedSid) {
                $ValidSids.Add('*{0}' -f $resolvedSid)
            } else {
                Write-Verbose -Message ('Skipping invalid member: {0}' -f $member)
            } #end If-Else
            #} #end If
        } #end Foreach

    } #end Process

    End {
        # Return a single string with valid SIDs, each prefixed with an asterisk, separated by commas
        if ($ValidSids.Count -eq 0) {
            return [string]::Empty
        } else {
            return $ValidSids -join ','
        }
    } #end End
}
