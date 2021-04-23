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
		$a at 0
		or $b at 0
		or $c at 0
		or $d at 0
}
