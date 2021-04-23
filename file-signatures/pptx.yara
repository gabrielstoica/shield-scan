rule pptx_signature{
	meta:
		description="PPTX Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={50 4B 03 04}
		$b={50 4B 05 06}
		$c={50 4B 07 08}
	condition:
		$a at 0 or
		$b at 0 or
		$c at 0
}
