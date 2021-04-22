rule xml_signature{
	meta:
		description="XML Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={3c 3f 78 6d 6c 20}
	condition:
		$a at 0
}
