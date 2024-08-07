﻿Function Test-NameIsWellKnownSid {

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
        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

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
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'testing Well-Known SID (Private Function).'
        )
        Write-Verbose -Message $txt

        return $Identity
    } #end End
}
