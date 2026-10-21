# VhennCoin ENET end-to-end test:
#   1. create client wallets (genesis wallet first)
#   2. start node1 -> genesis block + genesis wallet funded
#   3. start node2 -> verifies it syncs from node1
#   4. transfer genesis -> user wallets, blocks produced and synced
#   5. more wallets/transactions; alternate which node proposes
#   6. genesis funds staker wallets; stake deposits to the system wallet
#   7. final verification of the transfer/staking chain across both nodes
#   8. node profiles: per-node keystores (seed phrase -> identity keys),
#      profile configs, identity shown in /status, admin sets stake_address,
#      nodes auto-submit validator registrations once the stake is confirmed
#   9. both nodes' validator registries agree (node key, stake wallet, amount)
$ErrorActionPreference = "Stop"

$root = "C:\Users\david john\Documents\Projects\vhennus\vhenncoin_enet"
$walletExe = Join-Path $root "target\debug\examples\wallet.exe"
$nodeExe = Join-Path $root "target\release\vhenncoin_enet.exe"
$node1Log = Join-Path $root "node1_out.txt"
$node2Log = Join-Path $root "node2_out.txt"
$api1 = "http://127.0.0.1:8545"
$api2 = "http://127.0.0.1:8546"
$COIN = [long]100000000   # [long]: int32 overflows at 8e9 and PS would format as "2E+14"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  OK   $msg" -ForegroundColor Green }
function Fail($msg) {
    Write-Host "  FAIL $msg" -ForegroundColor Red
    # Never leave orphaned node processes behind on a failure.
    try { Get-Process vhenncoin_enet -ErrorAction SilentlyContinue | Stop-Process -Force } catch {}
    throw "test failed: $msg"
}

function New-WalletKey {
    $out = Invoke-Native $walletExe @("gen")
    $priv = ($out | Where-Object { $_ -match "^priv " }) -replace "^priv ", ""
    $pub  = ($out | Where-Object { $_ -match "^pub " })  -replace "^pub ", ""
    $addr = ($out | Where-Object { $_ -match "^addr " }) -replace "^addr ", ""
    [pscustomobject]@{ priv = $priv; pub = $pub; addr = $addr }
}

function Get-Json($url) { Invoke-RestMethod -Uri $url -TimeoutSec 10 }

# Run a native exe with stderr merged in. PowerShell 5.1 turns native stderr
# into a terminating error when $ErrorActionPreference is "Stop"; run these
# calls with "Continue" and keep only the string lines of output.
function Invoke-Native([string]$exe, [string[]]$argv) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        (& $exe $argv 2>&1) | Where-Object { $_ -is [string] }
    } finally {
        $ErrorActionPreference = $old
    }
}

function Get-Status($api) { Get-Json "$api/status" }

function Submit-Tx($api, $txPath) {
    $body = Get-Content $txPath -Raw
    $resp = Invoke-RestMethod -Uri "$api/transactions" -Method Post -Body $body `
        -ContentType "application/json" -TimeoutSec 10
    if (-not $resp.success) { Fail "transaction rejected: $resp" }
    $resp.txid
}

# Build + sign a transfer with the wallet CLI, keeping only the JSON payload.
function New-TransferTx($priv, $inTxid, $inIndex, $to, $amount, $changeTo, $changeAmount, $file) {
    $wArgs = @("transfer", "--priv", $priv, "--txid", $inTxid, "--index", "$inIndex",
              "--to", $to, "--amount", "$amount")
    if ($changeTo) { $wArgs += @("--change", $changeTo, "--change-amount", "$changeAmount") }
    $out = Invoke-Native $walletExe $wArgs
    $lines = @($out)
    $start = -1
    for ($i = 0; $i -lt $lines.Length; $i++) { if ($lines[$i] -match "^\s*\{") { $start = $i; break } }
    if ($start -lt 0) { Fail "wallet transfer produced no JSON" }
    $end = $lines.Length - 1
    for ($i = $start; $i -lt $lines.Length; $i++) { if ($lines[$i] -match "^\}\s*$") { $end = $i; break } }
    ($lines[$start..$end]) -join "`n" | Set-Content $file -Encoding ASCII
}

# Build + sign a validator-registration tx with the wallet CLI, keeping only
# the JSON payload.
function New-RegisterTx($nodePriv, $stakeAddress, $file) {
    $out = Invoke-Native $walletExe @("register-node", "--node-priv", $nodePriv,
                                      "--stake-address", $stakeAddress)
    $lines = @($out)
    $start = -1
    for ($i = 0; $i -lt $lines.Length; $i++) { if ($lines[$i] -match "^\s*\{") { $start = $i; break } }
    if ($start -lt 0) { Fail "wallet register-node produced no JSON" }
    $end = $lines.Length - 1
    for ($i = $start; $i -lt $lines.Length; $i++) { if ($lines[$i] -match "^\}\s*$") { $end = $i; break } }
    ($lines[$start..$end]) -join "`n" | Set-Content $file -Encoding ASCII
}

function Wait-Height($api, $minHeight, $timeoutSec = 90) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $s = $null
    while ((Get-Date) -lt $deadline) {
        # Retry transient errors: the node may still be binding its listener.
        try { $s = Get-Status $api } catch { Start-Sleep -Milliseconds 500; continue }
        if ($s.height -ge $minHeight) { return $s }
        Start-Sleep -Milliseconds 500
    }
    $h = if ($s) { $s.height } else { "unreachable" }
    Fail "timeout waiting for $api height >= $minHeight (at $h)"
}

function Wait-Peers($api, $minPeers, $timeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $s = $null
    while ((Get-Date) -lt $deadline) {
        # Retry transient errors: the node may still be binding its listener.
        try { $s = Get-Status $api } catch { Start-Sleep -Milliseconds 500; continue }
        if ($s.peers -ge $minPeers) { return $s }
        Start-Sleep -Milliseconds 500
    }
    $p = if ($s) { $s.peers } else { "unreachable" }
    Fail "timeout waiting for $api peers >= $minPeers (at $p)"
}

function Wait-Validators($api, $minCount, $timeoutSec = 120) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $v = $null
    while ((Get-Date) -lt $deadline) {
        try { $v = Get-Json "$api/validators" } catch { $v = $null }
        if ($v -and $v.count -ge $minCount) { return $v }
        Start-Sleep -Seconds 2
    }
    Fail "timeout waiting for $api to register $minCount validator(s)"
}

function Block-Hash($api, $height) { (Get-Json "$api/blocks/$height").hash }

function Stop-Node($name) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "vhenncoin_enet" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1
}

function Start-Node($configName, $logFile) {
    if (Test-Path $logFile) { Remove-Item $logFile -Force }
    $wrapper = Join-Path $root ("start_" + ($configName -replace "\.toml$", "") + ".cmd")
    @(
        "@echo off",
        "set VHENNCOIN_CONFIG=$configName",
        "`"$nodeExe`""
    ) | Set-Content $wrapper -Encoding ASCII
    Start-Process -FilePath $wrapper -WorkingDirectory $root `
        -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" -WindowStyle Hidden
}

# --------------------------------------------------------------------------
Step "Phase 1: create client wallets (genesis wallet from node1 config)"

# The genesis output is owned by the public key configured in node1_config.toml
# ([genesis] public_key); its private key sits in consensus.validator_private_keys.
# Derive the genesis wallet from the config instead of generating a fresh one.
$node1Cfg = Get-Content (Join-Path $root "node1_config.toml") -Raw
if ($node1Cfg -notmatch '(?m)^\s*public_key\s*=\s*"([0-9a-fA-F]+)"') { Fail "genesis.public_key not found in node1_config.toml" }
$genesisPub = $Matches[1]
if ($node1Cfg -notmatch '(?m)validator_private_keys\s*=\s*\[\s*"([0-9a-fA-F]+)"') { Fail "validator_private_keys not found in node1_config.toml" }
$genesisPriv = $Matches[1]
$genesisAddr = $null
foreach ($line in (Invoke-Native $walletExe @("genesis-outpoint", "--pubkey", $genesisPub))) {
    if ($line -match "^address\s+(\S+)$") { $genesisAddr = $Matches[1] }
}
if (-not $genesisAddr) { Fail "could not derive genesis address from configured public key" }
$genesis = [pscustomobject]@{ priv = $genesisPriv; pub = $genesisPub; addr = $genesisAddr }
Ok "genesis wallet  priv=$($genesis.priv)"
Ok "genesis wallet  pub =$($genesis.pub)"
Ok "genesis wallet  addr=$($genesis.addr)"

$w1 = New-WalletKey; Ok "wallet W1 addr=$($w1.addr)"
$w2 = New-WalletKey; Ok "wallet W2 addr=$($w2.addr)"
$w3 = New-WalletKey; Ok "wallet W3 addr=$($w3.addr)"
$w4 = New-WalletKey; Ok "wallet W4 addr=$($w4.addr)"
$stakerA = New-WalletKey; Ok "staker A addr=$($stakerA.addr)"
$stakerB = New-WalletKey; Ok "staker B addr=$($stakerB.addr)"

$systemWallet = (Invoke-Native $walletExe @("system-wallet") | Select-Object -Last 1).Trim()
Ok "system stake wallet = $systemWallet"

$genesisOut = @{}
foreach ($line in (Invoke-Native $walletExe @("genesis-outpoint", "--pubkey", $genesis.pub))) {
    if ($line -match "^txid\s+(\S+)$") { $genesisOut.txid = $Matches[1] }
    if ($line -match "^index\s+(\d+)$") { $genesisOut.index = [int]$Matches[1] }
}
Ok "genesis outpoint = $($genesisOut.txid):$($genesisOut.index)"

# --------------------------------------------------------------------------
Step "Phase 2: start node1 and verify genesis block + genesis wallet"

Stop-Node "vhenncoin_enet"
Remove-Item -Recurse -Force (Join-Path $root "data_node1"), (Join-Path $root "data_node2") `
    -ErrorAction SilentlyContinue
Start-Node "node1_config.toml" $node1Log

$s1 = $null
for ($i = 0; $i -lt 40; $i++) {
    try { $s1 = Get-Status $api1; break } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $s1) { Fail "node1 API never came up (see $node1Log)" }
Ok "node1 up: $($s1.node) height=$($s1.height)"

$genesisInfo = Get-Json "$api1/genesis"
$expectedRecipient = $genesis.addr
$actualRecipient = ($genesisInfo.block.transactions[0].outputs[0].recipient -join '')
Ok "genesis block hash = $($genesisInfo.hash)"
Ok "genesis initial supply = $($genesisInfo.initial_supply)"
$hash1 = $genesisInfo.hash
if ($s1.height -ne 0) { Fail "expected height 0 right after genesis, got $($s1.height)" }
Ok "node1 height=0 with genesis bootstrapped"

# The genesis output must be owned by our genesis wallet address.
$recipHex = ($genesisInfo.block.transactions[0].outputs[0].recipient |
    ForEach-Object { $_.ToString("x2") }) -join ''
if ($recipHex -ne $genesis.addr) { Fail "genesis recipient $recipHex != wallet $expectedRecipient" }
Ok "genesis output recipient == genesis wallet address"

# --------------------------------------------------------------------------
Step "Phase 3: start node2 and verify it syncs genesis from node1"

Start-Node "node2_config.toml" $node2Log
$s2 = Wait-Peers $api2 1 30
Ok "node2 up: $($s2.node) height=$($s2.height) phase=$($s2.phase) peers=$($s2.peers)"
Ok "node2 connected to node1"
$hash2 = Block-Hash $api2 0
if ($hash2 -ne $hash1) { Fail "genesis hash differs: node1=$hash1 node2=$hash2" }
Ok "node1 and node2 agree on genesis hash $hash1"

# --------------------------------------------------------------------------
Step "Phase 4: transfer genesis -> W1 (block produced on node1, node2 syncs)"

# tx1: genesis spends its coinbase -> W1 gets 2,000,000 VHN, change back to genesis
$amount1 = 2000000 * $COIN
$change1 = 78000000 * $COIN
New-TransferTx $genesis.priv $genesisOut.txid $genesisOut.index $w1.addr $amount1 $genesis.addr $change1 (Join-Path $root "tx_t1.json")
$txid1 = Submit-Tx $api1 (Join-Path $root "tx_t1.json")
Ok "T1 submitted to node1: txid=$txid1"

Wait-Height $api1 1 | Out-Null
Ok "node1 produced block 1"
$genesisChangeTxid = $txid1   # index 1 is the genesis change output

$s2 = Wait-Height $api2 1 60
Ok "node2 synced block 1: height=$($s2.height) finalized=$($s2.finalized_height)"
if ((Block-Hash $api2 1) -ne (Block-Hash $api1 1)) { Fail "block 1 hash mismatch between nodes" }
Ok "block 1 hash identical on both nodes"

# --------------------------------------------------------------------------
Step "Phase 5: more wallets and transactions; alternate proposing node"

# T2 via node1: genesis -> W2
$amount2 = 1000000 * $COIN
$change2 = 77000000 * $COIN
New-TransferTx $genesis.priv $genesisChangeTxid 1 $w2.addr $amount2 $genesis.addr $change2 (Join-Path $root "tx_t2.json")
$txid2 = Submit-Tx $api1 (Join-Path $root "tx_t2.json")
Ok "T2 submitted to node1: txid=$txid2"
Wait-Height $api1 2 | Out-Null
$genesisChangeTxid = $txid2
Ok "node1 proposed block 2"
Wait-Height $api2 2 60 | Out-Null
Ok "node2 synced block 2"

# T3 via NODE2: W1 -> W3 (node2 must pick this up and propose)
$amount3 = 500000 * $COIN
$change3 = 1500000 * $COIN
New-TransferTx $w1.priv $txid1 0 $w3.addr $amount3 $w1.addr $change3 (Join-Path $root "tx_t3.json")
$txid3 = Submit-Tx $api2 (Join-Path $root "tx_t3.json")
Ok "T3 submitted to node2: txid=$txid3"
Wait-Height $api2 3 60 | Out-Null
Ok "node2 proposed block 3 (it received the transaction)"
Wait-Height $api1 3 60 | Out-Null
Ok "node1 synced block 3 proposed by node2"
if ((Block-Hash $api1 3) -ne (Block-Hash $api2 3)) { Fail "block 3 hash mismatch" }

# T4 via node1: W1 -> W4 (W1 change from T3 is output index 1)
$amount4 = 600000 * $COIN
$change4 = 900000 * $COIN
New-TransferTx $w1.priv $txid3 1 $w4.addr $amount4 $w1.addr $change4 (Join-Path $root "tx_t4.json")
$txid4 = Submit-Tx $api1 (Join-Path $root "tx_t4.json")
Ok "T4 submitted to node1: txid=$txid4"
Wait-Height $api1 4 60 | Out-Null
Ok "node1 proposed block 4"
Wait-Height $api2 4 60 | Out-Null

# T5 via node2: W2 -> W3 (W2 change from T2 is output index 1)
$amount5 = 100000 * $COIN
$change5 = 900000 * $COIN
New-TransferTx $w2.priv $txid2 0 $w3.addr $amount5 $w2.addr $change5 (Join-Path $root "tx_t5.json")
$txid5 = Submit-Tx $api2 (Join-Path $root "tx_t5.json")
Ok "T5 submitted to node2: txid=$txid5"
Wait-Height $api2 5 60 | Out-Null
Ok "node2 proposed block 5"
Wait-Height $api1 5 60 | Out-Null
Ok "node1 synced block 5"

foreach ($h in 4, 5) {
    if ((Block-Hash $api1 $h) -ne (Block-Hash $api2 $h)) { Fail "block $h hash mismatch" }
}
Ok "blocks 4 and 5 hashes identical on both nodes"

# --------------------------------------------------------------------------
Step "Phase 6: fund staker wallets from genesis, then stake to system wallet"

# T6: genesis -> staker A (150,000 VHN, change back to genesis)
$amount6 = 150000 * $COIN
$change6 = 76850000 * $COIN
New-TransferTx $genesis.priv $genesisChangeTxid 1 $stakerA.addr $amount6 $genesis.addr $change6 (Join-Path $root "tx_t6.json")
$txid6 = Submit-Tx $api1 (Join-Path $root "tx_t6.json")
Ok "T6 submitted: genesis funded staker A, txid=$txid6"
Wait-Height $api1 6 60 | Out-Null
Wait-Height $api2 6 60 | Out-Null
Ok "node2 synced block 6 (staker A funded)"
$genesisChangeTxid = $txid6

# T7: staker A stakes MIN_STAKE (100,000 VHN) into the system wallet, keeps 50,000
$stakeA = 100000 * $COIN
New-TransferTx $stakerA.priv $txid6 0 $systemWallet $stakeA $stakerA.addr (50000 * $COIN) (Join-Path $root "tx_t7.json")
$txid7 = Submit-Tx $api2 (Join-Path $root "tx_t7.json")
Ok "T7 submitted to node2: staker A staked 100,000 VHN, txid=$txid7"
Wait-Height $api2 7 60 | Out-Null
Ok "node2 proposed block 7 (stake deposit)"
Wait-Height $api1 7 60 | Out-Null

# T8: genesis -> staker B (120,000 VHN, change back to genesis)
$amount8 = 120000 * $COIN
$change8 = 76730000 * $COIN
New-TransferTx $genesis.priv $genesisChangeTxid 1 $stakerB.addr $amount8 $genesis.addr $change8 (Join-Path $root "tx_t8.json")
$txid8 = Submit-Tx $api1 (Join-Path $root "tx_t8.json")
Ok "T8 submitted: genesis funded staker B, txid=$txid8"
Wait-Height $api1 8 60 | Out-Null
$genesisChangeTxid = $txid8

# T9: staker B stakes 110,000 VHN, keeps 10,000
$stakeB = 110000 * $COIN
New-TransferTx $stakerB.priv $txid8 0 $systemWallet $stakeB $stakerB.addr (10000 * $COIN) (Join-Path $root "tx_t9.json")
$txid9 = Submit-Tx $api1 (Join-Path $root "tx_t9.json")
Ok "T9 submitted: staker B staked 110,000 VHN, txid=$txid9"
Wait-Height $api1 9 60 | Out-Null
Ok "node1 proposed block 9 (stake deposit)"
Wait-Height $api2 9 60 | Out-Null
Ok "node2 synced block 9"

# --------------------------------------------------------------------------
Step "Phase 7: final verification across both nodes"

$s1 = Get-Status $api1
$s2 = Get-Status $api2
# Let node2 catch up if node1 just produced the last block.
for ($i = 0; $i -lt 180; $i++) {
    $s1 = Get-Status $api1
    $s2 = Get-Status $api2
    if ($s1.height -eq $s2.height -and $s1.finalized_height -eq $s2.finalized_height) { break }
    Start-Sleep -Seconds 1
}
Ok "node1 height=$($s1.height) finalized=$($s1.finalized_height) phase=$($s1.phase) peers=$($s1.peers)"
Ok "node2 height=$($s2.height) finalized=$($s2.finalized_height) phase=$($s2.phase) peers=$($s2.peers)"
if ($s1.height -ne $s2.height) { Fail "heights differ: $($s1.height) vs $($s2.height)" }
Ok "both nodes at identical height $($s1.height)"

$allMatch = $true
for ($h = 0; $h -le $s1.height; $h++) {
    if ((Block-Hash $api1 $h) -ne (Block-Hash $api2 $h)) {
        $allMatch = $false
        Fail "block $h hash differs between nodes"
    }
}
if ($allMatch) { Ok "all $($s1.height + 1) blocks hash-identical on both nodes" }

# Inspect the chain: proposers, transactions, stakes, balances. Retry a few
# times because a node may still be mid-sync (phase) for a few seconds.
$insp1 = @(); $insp2 = @()
for ($try = 0; $try -lt 6; $try++) {
    Invoke-Native $walletExe @("inspect", "--api", $api1) | Set-Content (Join-Path $root "inspect_node1.txt") -Encoding UTF8
    Invoke-Native $walletExe @("inspect", "--api", $api2) | Set-Content (Join-Path $root "inspect_node2.txt") -Encoding UTF8
    $insp1 = @(Get-Content (Join-Path $root "inspect_node1.txt") | Where-Object { $_ -match "^(PROPOSER|TX|STAKE|BAL|HEAD|PHASE)" })
    $insp2 = @(Get-Content (Join-Path $root "inspect_node2.txt") | Where-Object { $_ -match "^(PROPOSER|TX|STAKE|BAL|HEAD|PHASE)" })
    if (-not (Compare-Object $insp1 $insp2)) { break }
    Start-Sleep -Seconds 3
}
$proposers = $insp1 | Where-Object { $_ -match "^PROPOSER" }
Write-Host "`n  Proposers per height (node1 view):"
$proposers | ForEach-Object { Write-Host "    $_" }
$distinctProposers = $proposers | ForEach-Object { ($_ -split " ")[2] } | Sort-Object -Unique
Ok "$($distinctProposers.Count) distinct proposer address(es) observed"

$stakes = $insp1 | Where-Object { $_ -match "^STAKE" }
Write-Host "`n  Stake deposits detected:"
if ($stakes) { $stakes | ForEach-Object { Write-Host "    $_" } } else { Fail "no stake deposits detected" }
if (@($stakes).Count -lt 2) { Fail "expected 2 stake deposits" }
Ok "$(@($stakes).Count) stake deposits >= MIN_STAKE found in chain"

$balances = $insp1 | Where-Object { $_ -match "^BAL" }
Write-Host "`n  Balances (node1):"
$balances | ForEach-Object { Write-Host "    $_" }

$refBal = $insp1 | Where-Object { $_ -match "^BAL|^STAKE|^TX|^PROPOSER|^HEAD|^PHASE" }
$otherBal = $insp2 | Where-Object { $_ -match "^BAL|^STAKE|^TX|^PROPOSER|^HEAD|^PHASE" }
$diff = Compare-Object $refBal $otherBal
if ($diff) { Fail "node1 and node2 chain views differ:`n$($diff | Out-String)" }
Ok "node1 and node2 agree on proposers, transactions, stakes and balances"

# Which node was picked to propose each block (from the nodes' own logs).
function Get-ProducedHeights($log) {
    if (-not (Test-Path $log)) { return @() }
    $copy = "$log.snapshot"
    for ($i = 0; $i -lt 10; $i++) {
        try { Copy-Item $log $copy -Force; break } catch { Start-Sleep -Milliseconds 300 }
    }
    if (-not (Test-Path $copy)) { return @() }
    Select-String -Path $copy -Pattern "Produced block at height (\d+)" -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { [int]$_.Groups[1].Value } |
        Sort-Object
}
$made1 = @(Get-ProducedHeights $node1Log)
$made2 = @(Get-ProducedHeights $node2Log)
Write-Host "`n  Blocks proposed by node1: $(($made1 -join ', '))"
Write-Host "  Blocks proposed by node2: $(($made2 -join ', '))"
if ($made1.Count -eq 0) { Fail "node1 never proposed a block" }
if ($made2.Count -eq 0) { Fail "node2 never proposed a block" }
Ok "both nodes were picked to propose blocks; proposer rotation observed"
if (($made1 + $made2 | Sort-Object | Select-Object -Unique).Count -ne $s1.height) {
    Fail "proposed heights do not cover the whole chain exactly once"
}
Ok "every height was proposed exactly once across both nodes"

Write-Host "`n--- SUMMARY (phases 1-7) ---" -ForegroundColor Cyan
Write-Host "genesis wallet priv: $($genesis.priv)"
Write-Host "genesis wallet pub : $($genesis.pub)"
Write-Host "genesis wallet addr: $($genesis.addr)"
Write-Host "genesis block hash : $hash1"
Write-Host "chain height       : $($s1.height) (both nodes, finalized $($s1.finalized_height))"
Write-Host "stake deposits     : $(@($stakes).Count)"

# --------------------------------------------------------------------------
Step "Phase 8: node profiles - per-node keystores, identities and stake_address"

$profilesDir = Join-Path $root "profiles"
if (Test-Path $profilesDir) { Remove-Item -Recurse -Force $profilesDir }
New-Item -ItemType Directory -Path $profilesDir | Out-Null

# Each node gets its own identity: a seed phrase (17 words) from which the
# private/public key pair is derived, all stored in a local text file.
function New-NodeKeystore($file) {
    $out = Invoke-Native $walletExe @("keystore-init", "--file", $file)
    $ks = [pscustomobject]@{ file = $file; phrase = $null; priv = $null; pub = $null; addr = $null }
    foreach ($line in $out) {
        if ($line -match "^seed-phrase\s+(\S+(?:\s\S+)*)$") { $ks.phrase = $Matches[1].Trim() }
        if ($line -match "^priv\s+(\S+)$") { $ks.priv = $Matches[1] }
        if ($line -match "^pub\s+(\S+)$")  { $ks.pub  = $Matches[1] }
        if ($line -match "^addr\s+(\S+)$") { $ks.addr = $Matches[1] }
    }
    if (-not $ks.pub -or -not $ks.priv -or -not $ks.phrase) { Fail "keystore-init did not produce a full identity for $file" }
    # The stored file must round-trip back to the same identity.
    $shown = Invoke-Native $walletExe @("keystore-show", "--file", $file)
    $showPub = ($shown | Where-Object { $_ -match "^pub\s+" }) -replace "^pub\s+", ""
    if ($showPub.Trim() -ne $ks.pub) { Fail "keystore file $file does not round-trip (pub mismatch)" }
    $ks
}

$node1Identity = New-NodeKeystore (Join-Path $profilesDir "node1.keystore.txt")
Ok "node1 identity from seed phrase ($(($node1Identity.phrase -split ' ').Count) words), stored in $($node1Identity.file)"
Ok "node1  pub=$($node1Identity.pub)"
Ok "node1  addr=$($node1Identity.addr)"

$node2Identity = New-NodeKeystore (Join-Path $profilesDir "node2.keystore.txt")
Ok "node2 identity from seed phrase ($(($node2Identity.phrase -split ' ').Count) words), stored in $($node2Identity.file)"
Ok "node2  pub=$($node2Identity.pub)"
Ok "node2  addr=$($node2Identity.addr)"

if ($node1Identity.pub -eq $node2Identity.pub) { Fail "both nodes got the same identity key" }
Ok "node1 and node2 hold distinct identity keys"

# Profile configs = the node's base config plus its identity. The stake
# wallet is added afterwards, while the nodes are already running. Line-based
# editing so mixed CRLF/LF base configs cannot break the insertion.
function Write-NodeProfile($baseName, $identity) {
    $profileName = ($baseName -replace "\.toml$", "") + "_profile.toml"
    $lines = @(Get-Content (Join-Path $root $baseName))
    $ksPath = "./profiles/" + (Split-Path $identity.file -Leaf)
    $out = @()
    $inserted = $false
    foreach ($line in $lines) {
        $out += $line
        if (-not $inserted -and $line -match '^\s*data_dir\s*=') {
            $out += "keystore_path = `"$ksPath`""
            $out += "public_key = `"$($identity.pub)`""
            $inserted = $true
        }
    }
    if (-not $inserted) { Fail "failed to add identity to $profileName (no data_dir line)" }
    $out -join "`n" | Set-Content (Join-Path $root $profileName) -Encoding ASCII
    $profileName
}
$node1Profile = Write-NodeProfile "node1_config.toml" $node1Identity
$node2Profile = Write-NodeProfile "node2_config.toml" $node2Identity
Ok "wrote $node1Profile and $node2Profile (keystore_path + public_key)"

# Restart both nodes under their profiles; the chain continues from height 9.
Stop-Node "vhenncoin_enet"
Start-Node $node1Profile $node1Log
for ($i = 0; $i -lt 40; $i++) {
    try { $s1 = Get-Status $api1; break } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $s1) { Fail "node1 (profile) API never came up (see $node1Log)" }
Start-Node $node2Profile $node2Log
$s2 = Wait-Peers $api2 1 30
Ok "both nodes restarted under their profiles at height $($s1.height)/$($s2.height)"

# Each node must now expose the identity from its keystore file.
if ($s1.node_public_key -ne $node1Identity.pub) { Fail "node1 /status pub $($s1.node_public_key) != keystore $($node1Identity.pub)" }
Ok "node1 /status reports the keystore identity $($s1.node_public_key)"
if ($s2.node_public_key -ne $node2Identity.pub) { Fail "node2 /status pub $($s2.node_public_key) != keystore $($node2Identity.pub)" }
Ok "node2 /status reports the keystore identity $($s2.node_public_key)"

$v = Get-Json "$api1/validators"
if ($v.count -ne 0) { Fail "expected an empty registry before stake_address is configured, got $($v.count)" }
Ok "registry is still empty before the admin configures stake_address"

# The admin sets the staking wallet's public key in each node's config. The
# stake payments were already confirmed in blocks 7 and 9, so the nodes must
# now register automatically (no restart).
function Set-StakeAddress($profileName, $stakePub) {
    $path = Join-Path $root $profileName
    $lines = @(Get-Content $path)
    $out = @()
    $afterKeystore = $false
    $inserted = $false
    foreach ($line in $lines) {
        $out += $line
        if ($afterKeystore -and $line -match '^\s*public_key\s*=') {
            $out += "stake_address = `"$stakePub`""
            $afterKeystore = $false
            $inserted = $true
        } elseif ($line -match '^\s*keystore_path\s*=') {
            $afterKeystore = $true
        }
    }
    if (-not $inserted) { Fail "failed to set stake_address in $profileName" }
    $out -join "`n" | Set-Content $path -Encoding ASCII
}
Set-StakeAddress $node1Profile $stakerA.pub
Ok "admin set stake_address: node1 -> staker A ($($stakerA.pub))"

# Register the nodes one at a time. This build has no transaction gossip, so
# each node can only put its own registration in its own mempool. If both
# nodes had a pending registration at the same height, each would propose its
# own block and the chain would fork (each node seeing only its own
# registration). Waiting for node1's registration to be confirmed and
# replicated to node2 before configuring node2 keeps the chain linear.
$v1 = Wait-Validators $api1 1 120
$v2 = Wait-Validators $api2 1 120
Ok "node1 registered as a validator (registry size $($v1.count) node1 / $($v2.count) node2)"

Set-StakeAddress $node2Profile $stakerB.pub
Ok "admin set stake_address: node2 -> staker B ($($stakerB.pub))"

$v1 = Wait-Validators $api1 2 120
$v2 = Wait-Validators $api2 2 120
Ok "both nodes registered as validators (registry size $($v1.count)/$($v2.count))"

# --------------------------------------------------------------------------
Step "Phase 9: verify the validator registry on both nodes"

$reg1 = @(Invoke-Native $walletExe @("validators", "--api", $api1) | Where-Object { $_ -match "^REG " })
$reg2 = @(Invoke-Native $walletExe @("validators", "--api", $api2) | Where-Object { $_ -match "^REG " })
Write-Host "`n  Registry (node1 view):"
$reg1 | ForEach-Object { Write-Host "    $_" }
if ($reg1.Count -ne 2) { Fail "expected 2 registry entries on node1, got $($reg1.Count)" }
if (Compare-Object $reg1 $reg2) { Fail "node1 and node2 registries differ:`n$(Compare-Object $reg1 $reg2 | Out-String)" }
Ok "node1 and node2 registries are identical"

# Each entry must bind the node's identity key to its staking wallet and the
# exact stake amount that wallet paid.
$expected = @(
    @{ pub = $node1Identity.pub; addr = $node1Identity.addr; stakeAddr = $stakerA.addr; amount = "10000000000000" },
    @{ pub = $node2Identity.pub; addr = $node2Identity.addr; stakeAddr = $stakerB.addr; amount = "11000000000000" }
)
foreach ($e in $expected) {
    $line = $reg1 | Where-Object { $_ -match [regex]::Escape("REG $($e.pub)") }
    if (-not $line) { Fail "node $($e.pub) is missing from the registry" }
    $parts = $line -split " "
    if ($parts[2] -ne $e.addr)      { Fail "registry node_address for $($e.pub) is $($parts[2]), expected $($e.addr)" }
    if ($parts[3] -ne $e.stakeAddr) { Fail "registry stake_address for $($e.pub) is $($parts[3]), expected $($e.stakeAddr)" }
    if ($parts[4] -ne $e.amount)    { Fail "registry stake_amount for $($e.pub) is $($parts[4]), expected $($e.amount)" }
    $stakeVhn = [decimal]$parts[4] / $COIN
    Ok "node $($e.addr) registered: stake wallet $($e.stakeAddr), stake $stakeVhn VHN, joined at height $($parts[5])"
}

# The chain must still be fully consistent after the registrations.
$s1 = Get-Status $api1
$s2 = Get-Status $api2
for ($i = 0; $i -lt 180; $i++) {
    $s1 = Get-Status $api1
    $s2 = Get-Status $api2
    if ($s1.height -eq $s2.height -and $s1.finalized_height -eq $s2.finalized_height) { break }
    Start-Sleep -Seconds 1
}
if ($s1.height -ne $s2.height) { Fail "heights differ after registration: $($s1.height) vs $($s2.height)" }
Ok "both nodes at height $($s1.height) after the registration blocks"
for ($h = 0; $h -le $s1.height; $h++) {
    if ((Block-Hash $api1 $h) -ne (Block-Hash $api2 $h)) { Fail "block $h hash differs after registration" }
}
Ok "all $($s1.height + 1) blocks still hash-identical on both nodes"

# Registration requests are ordinary transactions: each one is stored in a
# block and queryable by its txid.
$regTxs = 0
for ($h = 10; $h -le $s1.height; $h++) {
    $block = Get-Json "$api1/blocks/$h"
    foreach ($tx in $block.block.transactions) {
        if ($tx.tx_type -eq "validator_registration") {
            $regTxs++
            $txid = $tx.registration.node_public_key -join ''
            Ok "block $h carries a validator_registration tx (node key $($tx.registration.node_public_key.Length) bytes, stake wallet $(($tx.registration.stake_address -join '')))"
        }
    }
}
if ($regTxs -lt 2) { Fail "expected 2 confirmed registration transactions in the chain, found $regTxs" }
Ok "$regTxs registration transactions confirmed in blocks"

# Negative case: a node whose stake wallet never paid must be rejected by the
# network before its key can enter the registry.
Step "Phase 9b: registration without a paid stake is rejected"
$unfunded = New-WalletKey
$badTxPath = Join-Path $root "tx_reg_unfunded.json"
# A fresh, never-registered identity key whose stake wallet never paid: the
# only possible reason to reject it is the missing stake (a duplicate key
# would be rejected earlier, for a different reason).
New-RegisterTx $unfunded.priv $unfunded.addr $badTxPath
$rejected = $false
try {
    Invoke-RestMethod -Uri "$api1/transactions" -Method Post -Body (Get-Content $badTxPath -Raw) `
        -ContentType "application/json" -TimeoutSec 10 | Out-Null
} catch {
    $rejected = $true
    # Invoke-RestMethod (PS 5.1) consumes the response stream before throwing;
    # the body is retained in ErrorDetails.Message.
    $errBody = $_.ErrorDetails.Message
    if (-not $errBody) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errBody = $reader.ReadToEnd()
        } catch { $errBody = "" }
    }
    if ($errBody -notmatch "below the minimum") { Fail "rejection reason was not about the missing stake: $errBody" }
}
if (-not $rejected) { Fail "registration with an unpaid stake wallet was accepted" }
Ok "network rejected the unpaid registration (stake not paid -> below minimum)"
$v = Get-Json "$api1/validators"
if ($v.count -ne 2) { Fail "registry changed after the rejected registration: $($v.count)" }
Ok "registry still holds exactly the 2 legitimately registered nodes"

# inspect must show the same registry lines from both nodes.
$inspReg1 = @(Invoke-Native $walletExe @("inspect", "--api", $api1) | Where-Object { $_ -match "^REG " })
$inspReg2 = @(Invoke-Native $walletExe @("inspect", "--api", $api2) | Where-Object { $_ -match "^REG " })
if (Compare-Object $inspReg1 $inspReg2) { Fail "inspect REG lines differ between nodes" }
Ok "wallet inspect reports identical registry lines on both nodes"

Write-Host "`n--- SUMMARY ---" -ForegroundColor Cyan
Write-Host "genesis wallet priv: $($genesis.priv)"
Write-Host "genesis wallet pub : $($genesis.pub)"
Write-Host "genesis wallet addr: $($genesis.addr)"
Write-Host "genesis block hash : $hash1"
Write-Host "chain height       : $($s1.height) (both nodes, finalized $($s1.finalized_height))"
Write-Host "stake deposits     : $(@($stakes).Count)"
Write-Host "node1 keystore     : $($node1Identity.file)"
Write-Host "node1 seed phrase  : $($node1Identity.phrase)"
Write-Host "node1 identity pub : $($node1Identity.pub)"
Write-Host "node2 keystore     : $($node2Identity.file)"
Write-Host "node2 seed phrase  : $($node2Identity.phrase)"
Write-Host "node2 identity pub : $($node2Identity.pub)"
Write-Host "registered nodes   : $($reg1.Count) (identical registry on both nodes)"
Write-Host "`nALL TEST PHASES PASSED" -ForegroundColor Green

# When VHENN_E2E_CLEANUP is set (automation), stop the nodes so nothing is
# left running; interactively they stay up for inspection.
if ($env:VHENN_E2E_CLEANUP -eq "1") {
    Stop-Node "vhenncoin_enet"
    Write-Host "nodes stopped (VHENN_E2E_CLEANUP=1)" -ForegroundColor DarkGray
}
