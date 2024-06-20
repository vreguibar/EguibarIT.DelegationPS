function ConvertTo-SID {
    <#
        .SYNOPSIS
            Converts an account name to a Security Identifier (SID).

        .DESCRIPTION
            This function takes an account name (e.g., domain\username) and converts it to
            its corresponding Security Identifier (SID).

        .PARAMETER AccountName
            The account name to be converted to a SID. This should be in the format
            domain\username or just username for local accounts.

        .EXAMPLE
            PS C:\> ConvertTo-SID -AccountName "EguibarIT\davade"

        .INPUTS
            [string] - Account name.

        .OUTPUTS
            [System.Security.Principal.SecurityIdentifier] - The SID corresponding to the account name.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Enter the account name in the format domain\username or username.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AccountName
    )

    Begin {
        Write-Verbose 'Starting ConvertTo-SID function.'
    } #end Begin

    Process {
        try {
            if ($PSCmdlet.ShouldProcess("Account Name: $AccountName", 'Convert to SID')) {
                Write-Verbose -Message ('Converting {0} to SID.' -f $PSBoundParameters['AccountName'])

                $tmpAccount = [System.Security.Principal.NTAccount]::new($PSBoundParameters['AccountName'])

                $sid = $tmpAccount.Translate([System.Security.Principal.SecurityIdentifier])

                Write-Verbose -Message ('Successfully converted {0} to SID: {1}.' -f $PSBoundParameters['AccountName'], $sid)

            } else {
                Write-Verbose 'Operation was cancelled by user or not approved by ShouldProcess.'
            }
        } catch {
            Write-Error -Message ('Failed to convert {0} to SID. Error: {1}' -f $PSBoundParameters['AccountName'], $_.Exception.Message)
            return $null
        }
    } #end Process

    End {
        Write-Verbose -Message 'Ending ConvertTo-SID function.'
        return $sid
    } #end End
}
