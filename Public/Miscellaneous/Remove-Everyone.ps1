﻿# Remove Everyone ('S-1-1-0') Built-In Group from object
Function Remove-Everyone {
    <#
        .SYNOPSIS
            Remove the built-in group EVERYONE from the given object.
        .DESCRIPTION
            Remove the built-in group EVERYONE from the given object
        .EXAMPLE
            Remove-Everyone -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
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

    } #end Begin

    process {
        <#
            ACENumber              : 2
            IdentityReference      : Everyone
            ActiveDirectoryRights : ReadProperty, WriteProperty, GenericExecute
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = 'EVERYONE'
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'ReadProperty', 'WriteProperty', 'GenericExecute'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.GuidNULL
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "EVERYONE"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing EVERYONE.'
        )
        Write-Verbose -Message $txt
    } #end END
}
