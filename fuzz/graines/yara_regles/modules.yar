import "pe"
import "elf"
rule P { strings: $e = { 55 8B EC } condition: $e at pe.entry_point and pe.number_of_signatures > 0 }
rule E { strings: $e = { 31 ED } $t = "x.tmp" wide ascii condition: uint32(0) == 0x464C457F and $e at elf.entry_point and $t }
rule Q { strings: $a = "a" $b = "b" condition: any of ($a, $b) or none of them }
