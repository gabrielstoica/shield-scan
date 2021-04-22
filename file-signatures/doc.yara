rule doc_signature{
	meta:
		description="DOC Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={D0 CF 11 E0 A1 B1 1A E1}
	condition:
		$a at 0
}
