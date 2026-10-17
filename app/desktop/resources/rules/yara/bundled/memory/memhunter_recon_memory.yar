/*
 * MemHunter original Signature Detection rules (Apache-2.0).
 * AD reconnaissance tooling commonly found in memory during DFIR.
 * Not copied from a third-party YARA repository.
 */

rule memhunter_recon_sharphound_memory : recon memory
{
    meta:
        author = "MemHunter"
        license = "Apache-2.0"
        category = "recon"
        severity = "medium"
        target = "memory"
        description = "SharpHound / BloodHound collector strings in raw memory"
        mitre_attack = "T1087.002, T1482"
        origin = "original"
    strings:
        $s1 = "SharpHound" ascii wide
        $s2 = "BloodHound" ascii wide
        $s3 = "CollectionMethod" ascii wide
        $s4 = "Invoke-BloodHound" ascii wide nocase
    condition:
        2 of them
}

rule memhunter_recon_seatbelt_memory : recon memory
{
    meta:
        author = "MemHunter"
        license = "Apache-2.0"
        category = "recon"
        severity = "medium"
        target = "memory"
        description = "GhostPack Seatbelt command type names in raw memory"
        mitre_attack = "T1082, T1087"
        origin = "original"
    strings:
        $s1 = "Seatbelt.Commands" ascii wide
        $s2 = "Seatbelt.Util" ascii wide
    condition:
        1 of them
}

rule memhunter_recon_powerview_memory : recon memory
{
    meta:
        author = "MemHunter"
        license = "Apache-2.0"
        category = "recon"
        severity = "medium"
        target = "memory"
        description = "PowerView AD reconnaissance cmdlet names in raw memory"
        mitre_attack = "T1087.002, T1059.001"
        origin = "original"
    strings:
        $s1 = "Invoke-UserHunter" ascii wide nocase
        $s2 = "Find-LocalAdminAccess" ascii wide nocase
        $s3 = "Get-NetForestDomain" ascii wide nocase
    condition:
        1 of them
}
