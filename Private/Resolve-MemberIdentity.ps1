function Resolve-MemberIdentity {
    <#
        .SYNOPSIS
            Resolves a member's identity, converting it to a SID.
        .DESCRIPTION
            Takes a member and converts it into a Security Identifier (SID) if applicable.
        .PARAMETER Member
            The member to be resolved (e.g., user or group name).
        .OUTPUTS
            [string] The resolved SID as a string.
        .NOTES
            The function checks if the member is a well-known SID or an AD account.
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Member to be resolver to existing Identity',
            Position = 0)]
        $Member

    )

    Begin {
        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

    } #end Begin

    Process {
        try {

            # Check if Identity exists in Well-Known SIDs hashtable
            if ($Variables.WellKnownSIDs.Values.Contains($Member)) {

                Write-Verbose -Message ('Identity {0} found Well-Known SID table. Returning cached value.' -f $Member)
                return $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $Member }

            } #end If

            # If not found in cache, proceed with the normal resolution process
            if ($PSCmdlet.ShouldProcess("Resolve Identity $Member")) {

                # Check if the member is a well-known SID or AD object
                if ($Member -is [Microsoft.ActiveDirectory.Management.ADPrincipal] -or
                    $Member -is [Microsoft.ActiveDirectory.Management.ADAccount] -or
                    $Member -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                    $Member -is [Microsoft.ActiveDirectory.Management.ADUser]) {

                    return $Member.SID.Value

                } else {

                    $identity = Test-NameIsWellKnownSid -Name $Member

                    if ($null -eq $identity) {
                        return (ConvertTo-SID -AccountName $Member).Value
                    } else {
                        return $identity.Value
                    } #end If-Else

                } #end If-Else

            } else {
                Write-Verbose -Message ('Skipping resolution of {0} due to WhatIf condition.' -f $Member)
            }
        } catch {
            Write-Error -Message ('Error resolving identity for member: {0}' -f $Member)
            return $null
        } #end Try-Catch
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'resolving member identity (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Resolve-MemberIdentity
