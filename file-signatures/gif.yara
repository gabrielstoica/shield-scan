rule gif_signature{
	meta:
		description="GIF Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={47 49 46 38 37 61}
		$b={47 49 46 38 39 61}
	condition:
		$a at 0
		or $b at 0
}
