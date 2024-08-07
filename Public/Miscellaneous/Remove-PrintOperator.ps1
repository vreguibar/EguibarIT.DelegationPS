﻿Function Remove-PrintOperator {
    <#
        .SYNOPSIS
            Remove Print Operators built-in group from the given object.
        .DESCRIPTION
            Remove the built-in group Print Operators from the given object.
        .EXAMPLE
            Remove-PrintOperator -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the permissions are going to be removed.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.2
            DateModified:    01/Feb/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath
    )

    begin {

        $txt = ($constants.Header -f (Get-Date).ToShortDateString(), $MyInvocation.Mycommand, (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)


        # Get 'Print Operators' group by SID
        $PrintOperators = Get-AdGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-550' }


        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

    } #end Begin

    process {
        <#
            ACENumber              : 1
            IdentityReference      : BUILTIN\Print Operators
            ActiveDirectoryRightst : CreateChild, DeleteChild
            AccessControlType      : Allow
            ObjectType             : printQueue [ClassSchema]
            InheritanceType        : None
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $PrintOperators
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['printQueue']
            AdSecurityInheritance = 'None'
            RemoveRule            = $true
        }
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Print Operators"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) removed Print Operators."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}
