rule Essai { strings: $a = "vanguard" $b = { 4D 5A ?? 4? [1-3] ( 01 | 02 03 ) 99 } condition: uint16(0) == 0x5A4D and all of them }
