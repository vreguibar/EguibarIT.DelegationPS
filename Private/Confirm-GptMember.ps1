# Helper Function: Confirm-GptMember
function Confirm-GptMember {

    [Parameter(Mandatory = $true)]

    param (
        [string[]]$Members
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
                $sid = (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier])
                return $sid.Value
            } catch {
                Write-Verbose -Message ('Failed to resolve SID for {0}' -f $Name)
                return $null
            }
        }

    } #end Begin

    Process {

        foreach ($member in $Members) {

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($member)) {
                continue
            }

            # Check if the member is already a valid SID
            if (Test-IsValidSID -ObjectSID $member) {
                $ValidSids.Add('*{0}' -f $member)
            } else {
                # Resolve the member to a SID
                $resolvedSid = Resolve-Sid -Name $member

                if ($null -ne $resolvedSid) {
                    $ValidSids.Add('*{0}' -f $resolvedSid)
                } else {
                    Write-Verbose -Message ('Skipping invalid member: {0}' -f $member)
                }
            }
        }

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
