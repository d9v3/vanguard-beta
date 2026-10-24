private rule A { condition: true }
rule B { strings: $a = "x" xor condition: #a > 1 }
rule C { strings: $a = /re+/ condition: $a in (0..10) }
rule D { condition: ( true 
