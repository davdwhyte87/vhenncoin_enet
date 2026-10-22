# vhenncoin_enet

A permissioned (proof-of-authority) VhennCoin network.

## Permissioning

Only nodes approved by the current validator set may produce blocks. The
genesis validators listed under `[consensus].validators` are seeded as
`Approved` when the chain is first bootstrapped; from then on membership lives
in chain state, not in the config file.

A node joins in three steps:

1. **Stake** – the node's stake wallet pays at least `MIN_STAKE` into the system
   stake wallet with a normal transfer.
2. **Register** – the node broadcasts a `ValidatorRegistration` transaction
   signed by its identity key. It becomes `pending`; it cannot produce blocks
   yet.
3. **Vote** – already-approved validators broadcast `ValidatorVote`
   transactions. Once `approval_threshold_bps` of the eligible voters (default
   90%) approve, the node becomes `approved` and joins the set from the next
   block. If the same supermajority rejects it, it becomes `rejected` and its
   exact stake deposits are paid back to its stake wallet.

Proposals can optionally expire: when `voting_period_blocks > 0`, an undecided
proposal is rejected and refunded after that many blocks (`0` disables expiry).

### Override removal

`[governance].override_keys` lists hex-encoded public keys with emergency
removal power. Any one of them can build a `NodeRemoval` transaction, sign its
transaction id with the override key, and broadcast it. When it is included in
a block the target node is removed, its stake is refunded to its stake wallet,
and the new validator set applies from the next block. Genesis validators are
protected from override removal.

All governance requests travel as ordinary transactions through
`POST /api/transactions`, are gossiped to every connected peer, and take effect
only when a proposer seals them into a block, so every node derives the same
state.

### Consensus

Validator sets are versioned. Blocks commit `validator_set_version` and are
accepted only if signed by the scheduled proposer for their height
(`sorted_addresses[height % count]`). A membership change increments the
version by one and becomes active on the next block, so historical blocks keep
verifying against the set that produced them.

## Configuration

See `config.toml` for the annotated `[consensus]`, `[governance]` and
`[genesis]` sections.
