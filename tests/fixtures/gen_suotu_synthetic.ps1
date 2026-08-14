$ErrorActionPreference = 'Stop'
$src = 'SuotuFx2026'
if (-not ([System.Diagnostics.EventLog]::SourceExists($src))) {
    New-EventLog -LogName Application -Source $src
    Start-Sleep -Seconds 2
}
Write-EventLog -LogName Application -Source $src -EventId 1001 -EntryType Information -Message 'synthetic evtx fixture event alpha'
Write-EventLog -LogName Application -Source $src -EventId 1002 -EntryType Warning -Message 'synthetic evtx fixture event beta'
Write-EventLog -LogName Application -Source $src -EventId 4625 -EntryType FailureAudit -Message 'synthetic failed logon user=bob ws=TEST-WS ip=203.0.113.7 port=5150'
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force -Path 'E:\suotu\tests\fixtures' | Out-Null
$out = 'E:\suotu\tests\fixtures\suotu_synthetic.evtx'
if (Test-Path $out) { Remove-Item $out -Force }
$xpath = "*[System[Provider[@Name='$src']]]"
wevtutil epl Application $out "/q:$xpath"
Remove-EventLog -Source $src
Write-Host "OK"
