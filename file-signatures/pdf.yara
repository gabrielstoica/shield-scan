rule pdf_signature{
	meta:
		description="PDF Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$pdf_string={25 50 44 46 2d}
	condition:
		$pdf_strings at 0
}
