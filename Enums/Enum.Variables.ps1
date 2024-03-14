$Variables = [ordered] @{

    # Active Directory DistinguishedName
    AdDN                       = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

    # Configuration Naming Context
    configurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

    # Active Directory DistinguishedName
    defaultNamingContext       = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

    # Get current DNS domain name
    DnsFqdn                    = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    # Hashtable containing the mappings between SchemaExtendedRights and GUID's
    ExtendedRightsMap          = $null

    # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
    GuidMap                    = $null

    # Naming Contexts
    namingContexts             = ([ADSI]'LDAP://RootDSE').namingContexts

    # Partitions Container
    PartitionsContainer        = (([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString())

    # Root Domain Naming Context
    rootDomainNamingContext    = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

    # Schema Naming Context
    SchemaNamingContext        = ([ADSI]'LDAP://RootDSE').SchemaNamingContext.ToString()

    # Well-Known SIDs
    WellKnownSIDs              = $null
}
New-Variable -Name Variables -Value $Variables -Scope Script -Force
