rule bmp_signature{
	meta:
		description="BMP Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={42 4D}
	condition:
		uint16(0) == $a
}
