rule tif_signature{
	meta:
		description="TIF Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={49 49 2A 00}
		$b={4D 4D 00 2A}
	condition:
		uint32(0) == $a
		or uint32(0) == $b

}
