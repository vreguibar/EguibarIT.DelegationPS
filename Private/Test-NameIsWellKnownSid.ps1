Function Test-NameIsWellKnownSid {

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]

    Param (
        $name
    )

    Begin {

        #$Identity = [System.Security.Principal.SecurityIdentifier]::new()

        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).ToLower()

        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('built-in\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('builtin\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('built in\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('nt authority\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('ntauthority\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('ntservice\', '')
        $PSBoundParameters['Name'] = ($PSBoundParameters['Name']).replace('nt service\', '')

    } #end Begin

    Process {

        Try {
            if ($Variables.WellKnownSIDs.Values -contains $PSBoundParameters['Name']) {

                #return found object as System.Security.Principal.SecurityIdentifier
                $SID = $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $PSBoundParameters['Name'] }

                $Identity = [System.Security.Principal.SecurityIdentifier]::new($SID)
            } #end If
        } catch {
            Write-Error -Message 'Error found when translating WellKnownSid'
        }
    } #end Process

    End {
        return $Identity
    } #end End
}
