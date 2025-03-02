import "pe"

rule diceloader {
    meta:
        description = "Identifies diceloader"

   strings:
      // Mod 31 for key length 
      //  C1 FA 04                                sar     edx, 4
      //  8B C2                                   mov     eax, edx
      //  C1 E8 1F                                shr     eax, 1Fh
      //  03 D0                                   add     edx, eax
      //  6B C2 1F                                imul    eax, edx, 1Fh
      $mod =  { C1 FA 04 8B C2 C1 E8 1F 03 D0 6B C2 1F }

      // Reflective loader - not in all versions
      // B8 4D 5A 00 00                          mov     eax, 'ZM'
      // 66 41 39 07                             cmp     [r15], ax
      // 75 1B                                   jnz     short loc_18000106D
      // 49 63 57 3C                             movsxd  rdx, dword ptr [r15+3Ch]
      // 48 8D 4A C0                             lea     rcx, [rdx-40h]
      // 48 81 F9 BF 03 00 00                    cmp     rcx, 3BFh
      // 77 0A                                   ja      short loc_18000106D
      // 42 81 3C 3A 50 45 00 00                 cmp     dword ptr [rdx+r15], 'EP'
      // 74 05                                   jz      short loc_180001072
      $reflective = { B8 4D 5A 00 00 66 41 39 07 75 ?? 49 63 57 3C 48 8D 4A C0 48 81 F9 BF 03 00 00 77 ?? 42 81 3C 3A 50 45 00 00 }

      // Fnv1 Algrithm - only in new versions
      $fnv1 = {33 ?? 69 ?? 93 01 00 01}


   condition:
       pe.is_64bit() and
       $mod and 
       ($reflective or $fnv1)

}
