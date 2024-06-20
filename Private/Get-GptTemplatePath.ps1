# Helper Function: Get-GptTemplatePath
function Get-GptTemplatePath {
    <#
        .SYNOPSIS
            Retrieves the path to the GPT template for a specified Group Policy Object (GPO).

        .DESCRIPTION
            This function fetches the path to the GPT (Group Policy Template) for the specified GPO name.
            It constructs the path using the domain and GPO ID.

        .PARAMETER GpoName
            The name of the Group Policy Object (GPO) for which to retrieve the GPT template path.

        .EXAMPLE
            PS C:\> Get-GptTemplatePath -GpoName "Default Domain Policy"

        .INPUTS
            [string] The GPO name.

        .OUTPUTS
            [string] The path to the GPT template file.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'low')]
    [OutputType([string])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The name of the Group Policy Object (GPO) for which to retrieve the GPT template path',
            Position = 0)]
        [string]
        $GpoName
    )

    begin {
        Write-Verbose 'Starting function Get-GptTemplatePath'
    } #end Begin

    process {
        try {
            # Retrieve the GPO object by name
            if ($PSCmdlet.ShouldProcess("Retrieving GPO path for GPO name: $GpoName")) {
                $gpo = Get-Gpo -Name $GpoName -ErrorAction Stop
                Write-Verbose -Message ('GPO object retrieved successfully: {0}' -f $gpo.DisplayName)

                # Construct the GPT template path
                $DomainPath = '\\{0}\SYSVOL\{0}' -f $env:USERDNSDOMAIN
                $gpoPath = "$DomainPath\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                Write-Verbose -Message ('Constructed GPT template path: {0}' -f $gpoPath)
            } #end if
        } catch {
            Write-Error -Message ('Failed to retrieve GPT template path for GPO {0}. Error: {1}' -f $GpoName, $_)
        } #end Try-Catch
    } #end Process

    end {
        Write-Verbose -Message 'Ending function Get-GptTemplatePath'
        return $gpoPath
    } #end End
}
