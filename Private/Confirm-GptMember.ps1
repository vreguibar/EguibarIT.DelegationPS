Validate-GptMembers

# Helper Function: Confirm-GptMember
function Confirm-GptMember {
    param (
        [string[]]$Members
    )
    Write-Verbose "Validating AD members: $($Members -join ', ')"
    $validMembers = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $Members) {
        try {
            $adMember = Get-ADUser -Identity $member -ErrorAction Stop
            $validMembers.Add($adMember.SamAccountName)
        } catch {
            Write-Warning "Member $member not found in AD."
        }
    }
    return $validMembers
}
