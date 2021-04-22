rule wav_signature{
	meta:
		description="WAV Magic bytes"
		author="Stoica Gabriel-Marius"
	strings:
		$a={52 49 46 46 ?? ?? ?? ?? 57 41 56 45}
	condition:
		$a at 0
}
