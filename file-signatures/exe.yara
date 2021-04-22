rule exe_dll_signature{
	meta:
		description="EXE/DLL Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={4D 5A}
	condition:
		uint16(0) == $a
}
