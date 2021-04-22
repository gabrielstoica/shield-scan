rule vhd_signature{
	meta:
		description="VHD Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={63 6F 6E 6E 65 63 74 69 78}
	condition:
		$a at 0
}
