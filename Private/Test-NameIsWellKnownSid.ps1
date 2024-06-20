Function Test-NameIsWellKnownSid {

    <#
        .SYNOPSIS
            Checks if a given name corresponds to a well-known SID and returns the SID.

        .DESCRIPTION
            This function takes a name as input, processes it to remove common prefixes,
            and checks if it corresponds to a well-known SID.
            If found, it returns the SID as a [System.Security.Principal.SecurityIdentifier] object.

        .PARAMETER Name
            The name to check against the well-known SIDs.

        .EXAMPLE
            PS> Test-NameIsWellKnownSid -Name 'NT AUTHORITY\SYSTEM'

        .INPUTS
            [String] Name

        .OUTPUTS
            [System.Security.Principal.SecurityIdentifier]
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the SID name.',
            Position = 0)]
        [string]
        $Name
    )

    Begin {

        $Identity = $null

        $cleanedName = ($PSBoundParameters['Name']).ToLower()

        $cleanedName = $cleanedName -replace 'built-in\\', ''
        $cleanedName = $cleanedName -replace 'builtin\\', ''
        $cleanedName = $cleanedName -replace 'built in\\', ''
        $cleanedName = $cleanedName -replace 'nt authority\\', ''
        $cleanedName = $cleanedName -replace 'ntauthority\\', ''
        $cleanedName = $cleanedName -replace 'ntservice\\', ''
        $cleanedName = $cleanedName -replace 'nt service\\', ''

    } #end Begin

    Process {

        Try {
            if ($Variables.WellKnownSIDs.Values -contains $cleanedName) {

                #return found object as System.Security.Principal.SecurityIdentifier
                $SID = $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $cleanedName }

                if ($SID) {
                    # Create the SecurityIdentifier object
                    $Identity = [System.Security.Principal.SecurityIdentifier]::new($SID)
                } else {
                    Write-Verbose -Message ('The name {0} does not correspond to a well-known SID.' -f $cleanedName)
                } #end If-Else
            } #end If
        } catch {
            Write-Error -Message 'Error found when translating WellKnownSid'
            Write-Error -Message ('An error occurred while retrieving the identity: {0}' -f $_)
        }
    } #end Process

    End {
        return $Identity
    } #end End
}
