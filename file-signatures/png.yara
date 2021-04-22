rule png_signature{
	meta:
		description="PNG Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={89 50 4E 47 0D 0A 1A 0A}
	condition:
		$a at 0
}
