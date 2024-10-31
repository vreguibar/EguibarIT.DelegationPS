[System.FlagsAttribute]
public enum ServiceAccessFlags : uint
{
    SERVICE_QUERY_CONFIG         = 1,
    SERVICE_CHANGE_CONFIG        = 2,
    SERVICE_QUERY_STATUS         = 4,
    SERVICE_ENUMERATE_DEPENDENTS = 8,
    SERVICE_START                = 16,
    SERVICE_STOP                 = 32,
    SERVICE_PAUSE_CONTINUE       = 64,
    SERVICE_INTERROGATE          = 128,
    SERVICE_USER_DEFINED_CONTROL = 256,
    DELETE                       = 65536,
    READ_CONTROL                 = 131072,
    WRITE_DAC                    = 262144,
    WRITE_OWNER                  = 524288,
    SERVICE_ALL_ACCESS           = 983103,
    Synchronize          = 1048576,
    AccessSystemSecurity = 16777216,
    GenericAll           = 268435456,
    GenericExecute       = 536870912,
    GenericWrite         = 1073741824,
    GenericRead          = 2147483648
}

// Service Security and Access Rights
// https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?ranMID=46133&ranEAID=wizKxmN8no4&ranSiteID=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&epi=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&irgwc=1&OCID=AIDcmm549zy227_aff_7791_1243925&tduid=(ir__uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00)(7791)(1243925)(wizKxmN8no4-IeZwvoh43192JZrq0xrt5A)()&irclickid=_uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00
