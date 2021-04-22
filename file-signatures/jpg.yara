rule jpg_signature{
	meta:
		description="JPG Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={FF D8 FF DB}
		$b={FF D8 FF E0 00 10 4A 46 49 46 00 01}
		$c={FF D8 FF EE}
		$d={FF D8 FF E1 ?? ?? 45 78 69 66 00 00}
	condition:
		uint32(0) == $a
		or $b at 0
		or uint32(0) == $c
		or $d at 0
}
