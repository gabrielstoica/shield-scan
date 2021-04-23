rule pdf_signature{
	meta:
		description="PDF Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={25 50 44 46 2d}
	condition:
		$a at 0
}
