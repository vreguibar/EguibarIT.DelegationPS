﻿$Variables = [ordered] @{

    # Active Directory DistinguishedName
    AdDN                       = $null

    # Configuration Naming Context
    configurationNamingContext = $null

    # Active Directory DistinguishedName
    defaultNamingContext       = $null

    # Get current DNS domain name
    DnsFqdn                    = $null

    # Hashtable containing the mappings between SchemaExtendedRights and GUID's
    ExtendedRightsMap          = $null

    # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
    GuidMap                    = $null

    # Naming Contexts
    namingContexts             = $null

    # Partitions Container
    PartitionsContainer        = $null

    # Root Domain Naming Context
    rootDomainNamingContext    = $null

    # Schema Naming Context
    SchemaNamingContext        = $null

    # Well-Known SIDs
    WellKnownSIDs              = $null
}
New-Variable -Name Variables -Value $Variables -Scope Script -Force

# Create variable with $Nulls, then call Initialize-ModuleVariable to fill it up.
