rule avi_signature{
	meta:
		description="AVI Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={52 49 46 46 ?? ?? ?? ?? 41 56 49 20}
	condition:
		$a at 0
}
