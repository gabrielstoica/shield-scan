rule pw0ny{
	meta:
		description = "Detect pw0nyshell webshell"
		author = "Stoica Gabriel"
		reference = "https://github.com/GabrielStoica/shield-scan"
		date = "2021-04-26"
		hash = " "
	strings:
		$a1 = "featureHint($_POST['filename'], $_POST['cwd'], $_POST['type'])"
		$a2 = "echo json_encode($response);"
		$a3 = "preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/, $cmd, $match)"
		$a4 = "preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/', $cmd)"
		$a5 = "preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match)"
		$a6 = "preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)"
		$a7 = "exec($cmd, $stdout);"	
	condition:
		2 of them
}
