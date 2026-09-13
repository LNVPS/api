# Marketplace #370 review follow-ups

**Status:** complete
**Started:** 2026-09-10
**Last updated:** 2026-09-10

## Goal

Close the five bugs filed from the #370 review, so the marketplace path is
sound before it is finished: the node's packet filter, the API's node
handlers, and the marketplace PKI.

## Findings

All five issues are labelled `bug`:

| # | Where | What |
|---|---|---|
| 373 | `lnvps_node/src/fw.rs:583-607` | tunnel-side accept for 8890/16514 has no source restriction, so any node's guests can reach every other node's libvirtd and control API |
| 374 | `lnvps_node/src/fw.rs:533-560` | `input` chain accepts established/related before the anti-spoof jump |
| 376 | `lnvps_api/src/api/marketplace.rs:733-776` | `POST /api/v1/node/libvirt` has no approval gate; also blocking `fs` IO inside an async handler and prefix/suffix-only PEM validation |
| 375 | `lnvps_api_common/src/host/marketplace_pki.rs:91-104`, `lnvps_node/src/libvirt.rs:612-620` | private key mode is only fixed when contents change, and the file is world-readable while written |
| 377 | `probe.rs`, `probe_ssh.rs`, `host/mod.rs`, `marketplace_pki.rs`, `cloud_init.rs`, `mock.rs` | seven smaller follow-ups, listed in the issue |

Increment plan, one PR each, security first:

1. #374, node input chain ordering
2. #376, node libvirt endpoint approval gate + PEM validation
3. #375, PKI private key permissions
4. #377, grouped follow-ups
5. #373, deferred (see below)

Each increment carries a regression test that fails on the unfixed code, per
`docs/agents-common/bug-fixes.md`.

### #373 deferred: the stated fix breaks the working control path

The issue says to restrict the tunnel-side accept of 8890/16514 to the route
server's inner address (`gateway4`/`gateway6`). That is not the source. Observed
in the `lnvps` netns on a live node, right after an admin status call:

```
ipv4 tcp src=185.18.221.69 dst=10.95.0.2 sport=31518 dport=8890 ...
```

LNVPS's control traffic arrives with the API host's address; the route server
forwards it with the source preserved and no SNAT. Restricting to the gateway
would drop it and take the control API and libvirtd offline. The `gateway4`
premise comes from the e2e harness, which models LNVPS as running inside the
route server's namespace (source `rs_inner`). Production is not that shape.

Closing it needs a decision: SNAT on the route server so the gateway really is
the source, or an explicit allowed-source list in the desired document. Left
open.

## Tasks

- [x] Defer #373 with the live-source finding recorded
- [x] Increment 1: #374, node input chain ordering
- [x] Increment 2: #376, node libvirt approval gate
- [x] Increment 3: #375, PKI private key permissions
- [x] Increment 4: #377, grouped follow-ups

## Remaining

- **#373** is open, blocked on the source-address decision recorded above.
- **#376** closed the approval gate, the blocking file IO and the multi-block
  PEM hole, and capped the body. Still unverified, and deliberately left to a
  follow-up because it needs an X.509 parser dependency and the node's tunnel
  address: the certificate is neither parsed, nor checked for
  `basicConstraints: CA`, expiry, or a SAN matching the node's address. The
  impact is confined to that node's own trust directory, but the doc comment no
  longer claims otherwise.

## Notes

- The `Dockerfile` and `.github/workflows/build.yml` changes that enable the
  `libvirt` feature in the image build ride along in the same PR as a separate
  commit. They are unrelated to these issues, but the images they fix are the
  ones that run this code: without the feature, `get_host_client` has no arm for
  `VmHostKind::MarketplaceNode`.
