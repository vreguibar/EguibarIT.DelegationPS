﻿Function Remove-PreWin2000 {
    <#
        .SYNOPSIS
            Remove Pre-Windows 2000 Compatible Access built-in group from the given object.
        .DESCRIPTION
            Remove the built-in group Pre-Windows 2000 Compatible Access from the given object
        .EXAMPLE
            Remove-PreWin2000 -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the permissions are going to be removed.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    29/Sep/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            HelpMessage = 'Force the operation without confirmation.')]
        [switch]
        $Force
    )

    begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Get 'Pre-Windows 2000 Compatible Access' group by SID
        $PreWin2000 = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-554' }

    } #end Begin

    process {
        $Splat = @{
            Id                    = $PreWin2000
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing Pre-Windows 2000 Compatible Access.'
        )
        Write-Verbose -Message $txt
    } #end END
}
