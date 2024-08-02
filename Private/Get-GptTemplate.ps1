# GptTemplate on file GpoPrivilegeRights.cs

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
        Write-Verbose -Message 'Starting function Get-GptTemplatePath'

        Import-Module -Name GroupPolicy -Verbose:$false

    } #end Begin

    Process {
        try {
            # Retrieve the GPO object by name
            if ($PSCmdlet.ShouldProcess("Retrieving GPO path for GPO name: $PSBoundParameters['GpoName']")) {
                $gpo = Get-GPO -Name $PSBoundParameters['GpoName'] -ErrorAction Stop
                Write-Verbose -Message ('GPO object retrieved successfully: {0}' -f $gpo.DisplayName)

                # Construct the GPT template path
                $DomainPath = '\\{0}\SYSVOL\{0}' -f $env:USERDNSDOMAIN
                $gpoPath = "$DomainPath\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                Write-Verbose -Message ('Constructed GPT template path: {0}' -f $gpoPath)
            } #end if
        } catch {
            Write-Error -Message ('Failed to retrieve GPT template path for GPO {0}. Error: {1}' -f $GpoName, $_)
        } #end Try-Catch

        try {
            if (-not (Test-Path $gpoPath)) {
                Write-Verbose -Message ('GPT template path does not exist. Creating new file: {0}' -f $gpoPath)
                New-Item -ItemType File -Path $gpoPath -Force
            } #end if

            $GptTemplate = [IniFileHandler.IniFile]::new($gpoPath)
            Write-Verbose -Message 'GPT template object created successfully.'
        } catch {
            Write-Error -Message ('An error occurred while handling the GPT template path. Error: {0}' -f $_)
            throw
        } #end Try-Catch

    } #end Process

    End {
        return $GptTemplate
    } #end End
}
