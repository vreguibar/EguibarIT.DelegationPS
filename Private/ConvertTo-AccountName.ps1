function ConvertTo-AccountName {
    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to an account name.

        .DESCRIPTION
            This function takes a Security Identifier (SID) as input and translates it to the corresponding NT account name.
            It uses the System.Security.Principal.SecurityIdentifier class to perform the translation.

        .PARAMETER SID
            The Security Identifier (SID) to be converted to an account name.

        .EXAMPLE
            PS> ConvertTo-AccountName -SID "S-1-5-21-3623811015-3361044348-30300820-1013"
            EguibarIT\davade

        .INPUTS
            [string] - The SID that you want to convert to an account name.

        .OUTPUTS
            [string] - The NT account name corresponding to the given SID.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.NTAccount])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Enter the Security Identifier (SID) to be converted to an account name.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SID
    )

    Begin {
        Write-Verbose -Message 'Starting function ConvertTo-AccountName'
    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess("SID: $SID", 'Convert to account name')) {
            try {
                Write-Verbose -Message ('Attempting to convert SID: {0} to account name' -f $PSBoundParameters['SID'])

                # Create a SecurityIdentifier object from the SID string
                $tmpSid = [System.Security.Principal.SecurityIdentifier]::New($PSBoundParameters['SID'])

                # Translate the SID to an NTAccount object
                $accountName = $tmpSid.Translate([System.Security.Principal.NTAccount])

                # Return the account name as a string
                $accountName.Value
            } catch {
                Write-Error -Message ('Failed to convert SID: {0} to account name. {1}' -f $PSBoundParameters['SID'], $_)
                return $null
            }
        } else {
            Write-Verbose -Message ('Conversion of SID: {0} to account name was skipped due to ShouldProcess.' -f $PSBoundParameters['SID'])
        }
    } #end Process

    End {
        Write-Verbose -Message 'Function ConvertTo-AccountName completed.'
        return $accountName.Value
    } #end End
}
