# Helper Function: Confirm-GptMember
function Confirm-GptMember {

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([string])]

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
        $ValidSids = [System.Collections.Generic.List[string]]::new()

    } #end Begin

    Process {

        # Get existing members (get members from $iniContent)
        If ($iniContent[$Section].Contains($Key)) {
            Write-Verbose -Message ('Key "{0}" found. Getting existing values.' -f $Key)

            # Get existing value and split it into a list
            $ExistingMembers = ($iniContent.$Section.$Key).Split(',')

        } #end If

        # Check if there are ExistingMembers
        # Existing members are ONLY on SID form.
        If ($ExistingMembers) {
            # Iterate Existing Members
            Foreach ($Item in $ExistingMembers) {
                # Skip empty lines
                if ([string]::IsNullOrWhiteSpace($Item)) {
                    continue
                } #end If

                # Check if the member is already a valid SID
                #if (Test-IsValidSID -ObjectSID $Item) {

                If ($Item -contains '*') {
                    $item = $item.trim('*')
                }
                # Resolve the member to a SID
                If (Convert-SidToName -SID $item) {
                    $resolvedSid = $Item
                }


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
            If ($member -is [string]) {

                # Check if WellKnownSid
                If ($Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $member }) {

                    $resolvedSid = $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $member }

                } elseIf (Test-NameIsWellKnownSid -Name $member) {

                    $resolvedSid = (Test-NameIsWellKnownSid -Name $member).Value

                } elseIf (Convert-SidToName -SID $member) {

                    $resolvedSid = $member

                } #end If

            } else {
                $member = Get-AdObjectType -Identity $member

                $resolvedSid = $member.sid.Value
            } #end If-Else


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
            return [System.String]::Join(',', $ValidSids)
        }
    } #end End
}
