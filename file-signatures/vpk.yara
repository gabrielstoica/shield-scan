rule vpk_signature{
	meta:
		description="VPK Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={34 12 AA 55}
	condition:
		uint32(0) == $a
}
