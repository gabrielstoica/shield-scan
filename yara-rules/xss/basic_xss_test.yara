rule basic_xss_test
{
	meta:
		description="Rule for detecting XSS in a file"
		author="Stoica Gabriel-Marius"
		date="18-04-2021"
	strings:
		$word="xss" nocase
		$onmouseover="onmouseover" nocase
		$alert="alert" nocase
		$onerror="onerror" nocase
		$document="document" nocase
		$cookie="cookie" nocase
		$javascript="javascript" nocase
	condition:
		any of them
		
}
