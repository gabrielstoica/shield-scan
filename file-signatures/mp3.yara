rule mp3_signature{
	meta:
		description="MP3 Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={FF FB}
		$b={FF F3}
		$c={FF F2}
		$d={49 44 33}
	condition:
		$a at 0
		or $b at 0
		or $c at 0
		or $d at 0
}
