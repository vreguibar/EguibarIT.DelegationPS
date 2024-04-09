Function Convert-SidToName {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER

        .EXAMPLE
            Convert-SidToName

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADRootDSE                          | ActiveDirectory
                Get-ADObject                           | ActiveDirectory
        .NOTES
            Version:         1.0
            DateModified:    14/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([String])]

    param (
        # PARAM1 STRING representing the GUID
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $true,
            HelpMessage = 'SID of the object to be translated',
            Position = 0)]
        [ValidateScript({ Test-IsValidSID -ObjectSID $_ })]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    Begin {

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        $FoundName = $null

    } #end Begin

    Process {

        try {

            # Attempt to translate the SID to a name
            $FoundName = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Warning 'Identity Not Mapped Exception'
            $FoundName = $null
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) Finished translating SID."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $FoundName
    } #end End
}
