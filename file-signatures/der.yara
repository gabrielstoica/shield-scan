rule der_signature{
	meta:
		description="DER Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={30 82}
	condition:
		uint16(0) == $a
}
