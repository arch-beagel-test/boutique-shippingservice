# Runbook: boutique-shippingservice

- **Language:** Go
- **Owner:** @arch-beagel-test/checkout
- **Calls:** nothing

## It's down

1. `kubectl logs deploy/shippingservice --tail=200`
2. `kubectl rollout restart deploy/shippingservice`
3. If a dependency is failing, its runbook is in that repository's `docs/runbook.md`.

## Before changing who it calls

Read boutique-deploy `adr/cross/0002` and `0003`. A new call is a change to `protos/demo.proto` first.
