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
        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $Identity = $null

        $cleanedName = ($PSBoundParameters['Name']).ToLower()

        $cleanedName = $Name -replace '^(built-in\\|builtin\\|built in\\|nt authority\\|ntauthority\\|ntservice\\|nt service\\)', ''

    } #end Begin

    Process {

        Try {
            #return found object as System.Security.Principal.SecurityIdentifier

            $SID = $Variables.WellKnownSIDs.Keys.Where{ $Variables.WellKnownSIDs[$_] -eq $cleanedName }

            if ($SID) {

                try {
                    # Create the SecurityIdentifier object
                    $Identity = [System.Security.Principal.SecurityIdentifier]::new($SID)
                    Write-Verbose -Message ('Matched SID: {0}' -f $matchingSid)
                } catch {

                    $FormatError = [System.Text.StringBuilder]::new()
                    $FormatError.AppendLine('Error creating SecurityIdentifier object.')
                    $FormatError.AppendLine('Message: {0}' -f $_.Message)
                    $FormatError.AppendLine('CategoryInfo: {0}' -f $_.CategoryInfo)
                    $FormatError.AppendLine('ErrorDetails: {0}' -f $_.ErrorDetails)
                    $FormatError.AppendLine('Exception: {0}' -f $_.Exception)
                    $FormatError.AppendLine('FullyQualifiedErrorId: {0}' -f $_.FullyQualifiedErrorId)
                    $FormatError.AppendLine('InvocationInfo: {0}' -f $_.InvocationInfo)
                    $FormatError.AppendLine('PipelineIterationInfo: {0}' -f $_.PipelineIterationInfo)
                    $FormatError.AppendLine('ScriptStackTrace: {0}' -f $_.ScriptStackTrace)
                    $FormatError.AppendLine('TargetObject: {0}' -f $_.TargetObject)
                    $FormatError.AppendLine('PSMessageDetails: {0}' -f $_.PSMessageDetails)

                    Write-Error -Message $FormatError
                }
            } else {
                Write-Verbose -Message ('The name {0} does not correspond to a well-known SID.' -f $cleanedName)
            } #end If-Else

        } catch {

            $FormatError = [System.Text.StringBuilder]::new()
            $FormatError.AppendLine('Error found when translating WellKnownSid.')
            $FormatError.AppendLine('Message: {0}' -f $_.Message)
            $FormatError.AppendLine('CategoryInfo: {0}' -f $_.CategoryInfo)
            $FormatError.AppendLine('ErrorDetails: {0}' -f $_.ErrorDetails)
            $FormatError.AppendLine('Exception: {0}' -f $_.Exception)
            $FormatError.AppendLine('FullyQualifiedErrorId: {0}' -f $_.FullyQualifiedErrorId)
            $FormatError.AppendLine('InvocationInfo: {0}' -f $_.InvocationInfo)
            $FormatError.AppendLine('PipelineIterationInfo: {0}' -f $_.PipelineIterationInfo)
            $FormatError.AppendLine('ScriptStackTrace: {0}' -f $_.ScriptStackTrace)
            $FormatError.AppendLine('TargetObject: {0}' -f $_.TargetObject)
            $FormatError.AppendLine('PSMessageDetails: {0}' -f $_.PSMessageDetails)

            Write-Error -Message $FormatError
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'testing Well-Known SID (Private Function).'
        )
        Write-Verbose -Message $txt

        return $Identity
    } #end End
}
