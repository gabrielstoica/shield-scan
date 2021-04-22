rule rar_signature{
	meta:
		description="RAR Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={52 61 72 21 1A 07 00}
		$b={52 61 72 21 1A 07 01 00}
	condition:
		$a in (0..6)
		or $b in (0..7)
}
