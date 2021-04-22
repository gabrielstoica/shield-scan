rule aar_signature{
	meta:
		description="AAR Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={50 4B 03 04}
		$b={50 4B 05 06}
		$c={50 4B 07 08}
	condition:
		uint32(0) == $a
		or uint32(0) == $b
		or uint32(0) == $c
}
