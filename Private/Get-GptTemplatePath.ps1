# Helper Function: Get-GptTemplatePath
function Get-GptTemplatePath {
    param (
        [string]$GpoName
    )
    $gpo = Get-Gpo -Name $GpoName -ErrorAction Stop
    $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    return $gpoPath
}
