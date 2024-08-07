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

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'low')]
    [OutputType([IniFileHandler.IniFile])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name of the GPO.',
            Position = 0)]
        [string]
        $GpoName
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

        Import-Module -Name GroupPolicy -SkipEditionCheck -Verbose:$false | Out-Null

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        try {
            # Retrieve the GPO object by name
            if ($PSCmdlet.ShouldProcess("Retrieving GPO path for GPO name: $PSBoundParameters['GpoName']")) {
                $gpo = Get-GPO -Name $PSBoundParameters['GpoName'] -ErrorAction Stop
                Write-Verbose -Message ('GPO object retrieved successfully: {0}' -f $gpo.DisplayName)

                # Construct the GPT template path
                $DomainPath = '\\{0}\SYSVOL\{0}' -f $env:USERDNSDOMAIN
                $gpoPath = '{0}\Policies\{1}\Machine\Microsoft\Windows NT\SecEdit\' -f $DomainPath, ('{' + $($gpo.Id) + '}')
                $gpoPathFile = '{0}GptTmpl.inf' -f $gpoPath

                Write-Verbose -Message ('Constructed GPT template path: {0}' -f $gpoPath)
            } #end if

            if (-not (Test-Path $gpoPath)) {
                Write-Verbose -Message ('GPT template path does not exist. Creating new file: {0}' -f $gpoPath)

                # Create the directory
                New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null

                # Create the file with encoding
                [System.IO.File]::WriteAllText($gpoPathFile, '', [System.Text.Encoding]::Unicode)
            } #end if

            $GptTmpl = [IniFileHandler.IniFile]::new($gpoPathFile)

            Write-Verbose -Message 'GPT template object created successfully.'

            return $GptTmpl

        } catch {
            Write-Error -Message ('An error occurred while handling the GPT template path. Error: {0}' -f $_)
            return $null
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message 'Returning GptTmpl object.'

    } #end End
}
