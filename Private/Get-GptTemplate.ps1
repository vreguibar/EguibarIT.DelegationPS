# GptTmpl on file GpoPrivilegeRights.cs
function Get-GptTemplate {
    <#
        .SYNOPSIS
            Retrieves the GPT template path for a specified GPO name.

        .DESCRIPTION
            This function retrieves the GPT template path for a specified GPO name.
            It ensures the necessary module is imported, handles errors gracefully,
            and provides verbose output for better troubleshooting and logging.

        .PARAMETER GpoName
            The name of the Group Policy Object (GPO) for which the GPT template path is to be retrieved.

        .EXAMPLE
            Get-GptTemplate -GpoName "Default Domain Policy"

        .INPUTS
            [string] The name of the Group Policy Object (GPO).

        .OUTPUTS
            [IniFileHandler.IniFile] Returns an object representing the GPT template if successful.
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([IniFileHandler.IniFile])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name of the GPO.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $GpoName
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

        Import-MyModule -Name 'GroupPolicy' -Verbose:$false

        ##############################
        # Variables Definition

        $gpo = Get-GPO -Name $PSBoundParameters['GpoName'] -ErrorAction Stop
        Write-Verbose -Message ('GPO object retrieved successfully: {0}' -f $gpo.DisplayName)

    } #end Begin

    Process {
        try {

            # Construct the GPT template path
            $DomainPath = '\\{0}\SYSVOL\{0}' -f $env:USERDNSDOMAIN
            $gpoPath = '{0}\Policies\{1}\Machine\Microsoft\Windows NT\SecEdit\' -f $DomainPath, ('{' + $($gpo.Id) + '}')
            $gpoPathFile = '{0}GptTmpl.inf' -f $gpoPath

            Write-Verbose -Message ('Constructed GPT template path: {0}' -f $gpoPath)


            if (-not (Test-Path -Path $gpoPath -PathType Container)) {
                Write-Verbose -Message ('GPT template path does not exist. Creating new folder path: {0}' -f $gpoPath)

                try {
                    # Create the directory
                    New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
                } catch {
                    Write-Error -Message ('
                        Error while trying to create the folder for {0}' -f
                        $gpo.DisplayName
                    )
                } #end Try-Catch

            } #end if

            If (-Not (Test-Path -Path $gpoPathFile -PathType Leaf)) {
                Write-Verbose -Message ('GPT template file does not exist. Creating new file: {0}' -f $gpoPathFile)

                # Create the file with encoding on specific GPO path
                try {
                    [System.IO.File]::WriteAllText($gpoPathFile, '', [System.Text.Encoding]::Unicode)
                } catch {
                    Write-Error -Message ('
                        Error while trying to create GptTmpl.inf file within folder for {0}' -f
                        $gpo.DisplayName
                    )
                } #end Try-Catch

            } #end if

            # $GptTmpl = [IniFileHandler.IniFile]::new($gpoPathFile)

            $GptTmpl = [IniFileHandler.IniFile]::new()
            $GptTmpl.ReadFile($gpoPathFile)

            Write-Verbose -Message 'GPT template object created successfully.'

            # Ensure we're returning an IniFileHandler.IniFile object
            if ($GptTmpl -is [IniFileHandler.IniFile]) {
                return $GptTmpl
            } else {
                throw 'Failed to create an IniFileHandler.IniFile object'
            } #end If-Else

        } catch {
            $FormatError = [System.Text.StringBuilder]::new()
            $FormatError.AppendLine('An error occurred while handling the GPT template path.')
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

            return $null
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'Returning GptTmpl object (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
}
