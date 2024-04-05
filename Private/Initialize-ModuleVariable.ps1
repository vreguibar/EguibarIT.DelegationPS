Function Initialize-ModuleVariable {
    <#
        .SYNOPSIS


        .DESCRIPTION


        .PARAMETER


        .NOTES
            Version:         1.0
            DateModified:    05/Apr/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([void])]

    Param ()

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

    } #end Begin

    Process {

        # Active Directory DistinguishedName
        $Variables.AdDN = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

        # Configuration Naming Context
        $Variables.configurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

        # Active Directory DistinguishedName
        $Variables.defaultNamingContext = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

        # Get current DNS domain name
        $Variables.DnsFqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

        # Hashtable containing the mappings between SchemaExtendedRights and GUID's
        Get-ExtendedRightHashTable

        # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
        Get-AttributeSchemaHashTable

        # Naming Contexts
        $Variables.namingContexts = ([ADSI]'LDAP://RootDSE').namingContexts

        # Partitions Container
        $Variables.PartitionsContainer = (([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString())

        # Root Domain Naming Context
        $Variables.rootDomainNamingContext = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

        # Schema Naming Context
        $Variables.SchemaNamingContext = ([ADSI]'LDAP://RootDSE').SchemaNamingContext.ToString()

        # Well-Known SIDs
        . "$PSScriptRoot\Private\Get-AdWellKnownSID.ps1"

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished initializing Variables."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}
