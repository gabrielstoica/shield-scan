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
		uint16(0) == $a
		or uint16(0) == $b
		or uint16(0) == $c
		or $d at 0
}
