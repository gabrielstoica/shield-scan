rule bmp_signature{
	meta:
		description="BMP Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={42 4D}
	condition:
		$a at 0
}
