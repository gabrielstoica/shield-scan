rule tif_signature{
	meta:
		description="TIF Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={49 49 2A 00}
		$b={4D 4D 00 2A}
	condition:
		$a at 0
		or $b at 0

}
