# dnsranker

Measures how fast DNS resolvers actually answer, and ranks them live as it goes.
It queries two separate pools of domains against a list of resolvers — plain DNS
(Do53 over UDP or TCP), DNS-over-TLS and DNS-over-HTTPS, over IPv4 and IPv6 —
and reports each pool's latency separately, so you can see the difference
between a resolver that is genuinely fast and one that is merely well-cached.

Every list it needs is downloaded and cached on first run, so bare `dnsranker`
does something useful.

```
$ dnsranker
dnsranker: 30 resolvers × 40 domains × 1 run(s) = 1200 queries
  domains — popular: top 20 (cached)   random: 20 of ~1M (cached)
  resolvers: downloaded   IPv6: included

  #  SERVER                          PROTO      POP-AVG  RND-AVG   TAIL-Δ     OK   ECS     EDGE
 1.  Cloudflare DNS (Standard)       DoT           14.5     15.2    +0.70   100%    no     47.6
 2.  Cloudflare DNS (Standard) [v6]  Do53          12.0     12.5    +0.44   100%    no     48.1
 3.  Quad9 DNS (Unsecured)           Do53          10.9     33.6    +22.7   100%    no     11.8
 4.  Google DNS                      Do53          79.3     92.1    +12.8   100%   yes     13.8
 5.  System (127.0.0.53)             Do53          1.43     43.6    +42.2    98%    no     13.0
 …
```

The table redraws in place while the run is in progress, so you can watch it
fill in and stop early once you've seen enough.

## The two domain pools

Popular domains are cache hits at any large resolver — every resolver looks fast
on `google.com`. So `dnsranker` measures two equal-sized pools separately:

| Pool | Where it comes from | What it tells you |
| --- | --- | --- |
| **popular** | the head of a ranked list of ~10k domains | your everyday latency: almost entirely cache hits |
| **random** | a uniform sample of a **1M-domain** long-tail list, freshly drawn every run | the resolver's real work: mostly cache misses and full recursion |

`TAIL-Δ` is the gap between the two. A resolver with a small delta has a deep
cache or fast recursion; a large delta means it only looks fast on the front
page of the internet. Use `--seed N` to redraw the same random sample (the seed
used is printed after every run), `--pools popular` to skip the tail entirely,
and `-d N` to set the size of *each* pool.

## Install

```sh
cargo build --release      # binary at target/release/dnsranker
```

## Usage

```sh
dnsranker                                    # rank the default catalogue
dnsranker 1.1.1.1 8.8.8.8 tls://dns.google   # just these three
dnsranker -a udp://10.0.0.53                 # the catalogue plus your own
dnsranker -d 200 -r 3 --uncached             # heavier, cold-cache run
dnsranker --no-ecs                           # skip the client-subnet checks
dnsranker --pools popular --sort p95         # popular domains only, by tail latency
dnsranker --filter quad9 --filter cloudflare # one provider family
dnsranker --section anycast -n 0             # global resolvers only, no cap
dnsranker --json > results.json              # machine-readable output
```

### Resolver specs

| Spec | Meaning |
| --- | --- |
| `1.1.1.1` | plain DNS over UDP, port 53 |
| `udp://9.9.9.9:5353` | plain DNS on a non-standard port |
| `tcp://8.8.8.8` | plain DNS over TCP |
| `tls://dns.google` | DNS-over-TLS, port 853 |
| `tls://8.8.8.8#dns.google` | DoT by IP, pinning the certificate name |
| `https://dns.google/dns-query` | DNS-over-HTTPS |
| `2606:4700:4700::1111` | IPv6 works bare; bracket it only to add a port |
| `Name = <spec>` | label the endpoint for the results table |

## Where the lists come from

| List | Source | Cached as |
| --- | --- | --- |
| Popular domains | [OpenDNS top domains](https://github.com/opendns/public-domain-lists) (~10k, ranked) | `~/.cache/dnsranker/domains.txt` |
| In-country resolvers | [public-dns.info](https://public-dns.info) per-country list, with AS org and city | `~/.cache/dnsranker/regional-<cc>.csv` |
| Long-tail domains | [Majestic Million](https://majestic.com/reports/majestic-million) (1M, ~80 MB, fetched only when the random pool is in use) | `~/.cache/dnsranker/long-tail.csv` |
| Resolvers | [AdGuard "Known DNS providers"](https://github.com/AdguardTeam/KnowledgeBaseDNS) (~70 providers, each with its plain/DoT/DoH endpoints) | `~/.cache/dnsranker/dns-providers.md` |

Domains are re-fetched after 30 days, resolvers after 7, the long tail after 90;
`--refresh` forces it.
If a download fails and no cache exists, a small built-in list is used, so the
tool still runs offline-ish. `--domains-file`, `--servers-file`,
`--domains-url`, `--random-url` and `--servers-url` override the sources
entirely. If the long-tail list can't be fetched, the random pool falls back to
sampling the ranked list's own tail and the run header says so.

From the resolver catalogue, a default run selects one endpoint per
provider/protocol/address-family, ordered so the best-known providers survive
the `--max-servers` cut (30 endpoints). Your own resolvers from
`/etc/resolv.conf` are always included as the baseline (`--no-system` to drop
them).

**Only non-filtering resolvers are tested by default.** A resolver that blocks
ads, malware or adult content isn't answering the same question as one that
doesn't — and it can look faster precisely because it answered "no". Whether an
endpoint filters is read from the catalogue's own prose, not just its heading,
so `Quad9 Standard` ("blocklists, DNSSEC validation") is excluded in favour of
`Quad9 Unsecured`, and OpenDNS resolves to its `Sandbox` variant rather than the
malware-filtering default. Providers that offer nothing unfiltered at all
(CleanBrowsing, CERT-EE, 114DNS, …) drop out entirely. `--include-filtered`
puts them back.

**Regional means *your* region.** A resolver on another continent is just a slow
global one, so 8 of the 30 slots are reserved for resolvers in your own country
(`--regional N`). Your country is detected automatically — Cloudflare's
`/cdn-cgi/trace` edge, falling back to the system locale — and can be set with
`--country AU` or switched off with `--country any`.

The provider catalogue has no country field, so in-country resolvers come from
[public-dns.info](https://public-dns.info)'s per-country list instead, which
does: `https://public-dns.info/nameserver/{cc}.csv`, cached for 30 days. Only
fully reliable entries are used, one per network operator, so the slice reads as
a spread of local networks (`Telstra Corporation Ltd`, `Aussie Broadband
(Brisbane)`, …) rather than eight boxes on one ISP. These are plain-DNS only.
Catalogue entries that *do* state a country — CIRA Canadian Shield, CZ.NIC,
Quad101, DNS4EU — are matched against your region too, from their name,
description or country-code TLD.

That list is a scan of the open internet and some of it has gone stale, so the
candidates are probed once in parallel before selection: dead ones are dropped
and the survivors are ordered by round-trip time, which puts the nearest first.
Unused reserved slots go back to the global pool.

IPv6 endpoints are included when the host has a route to the IPv6 internet
(checked at startup); force with `--ipv6 yes|no`.

## Adding your own resolvers

To rank your own resolvers *alongside* the catalogue, pass them with `-a`:

```sh
dnsranker -a udp://10.0.0.53 "Pi-hole = udp://192.168.1.2" https://dns.nextdns.io/abc123
```

Added resolvers are exempt from `--proto`, `--section`, `--filter` and
`--max-servers`, and they win against an identical catalogue entry, so a
resolver you named never silently drops out of the results.

Without `-a`, positional specs replace the catalogue entirely, and nothing else
(not even your system resolvers) is added:

```sh
dnsranker udp://10.0.0.53 tls://dns.mullvad.net https://dns.nextdns.io/abc123
```

For a list you'll reuse, save the current selection and edit it.
`--list-servers` prints the `Name = spec` format that `--servers-file` reads
back, so it round-trips:

```sh
dnsranker --list-servers -n 0 --section anycast,regional > servers.txt
cat >> servers.txt <<'EOF'
Work resolver = udp://10.0.0.53
Pi-hole       = udp://192.168.1.2
NextDNS mine  = https://dns.nextdns.io/abc123
EOF
dnsranker -S servers.txt -n 0
```

Notes on list files:

- One entry per line, `Name = spec` or a bare spec; `#` starts a comment (a `#`
  inside a spec, as in `tls://1.1.1.1#dns.example`, is left alone).
- Give each endpoint a distinct name. Entries are de-duplicated per
  name/protocol/address-family, and identical endpoints collapse to one — which
  is what lets you append to a saved list without worrying about overlap.
- `--proto` still filters what runs; add `tcp` to it if your file has `tcp://`
  entries, since the default is `udp,dot,doh`.
- `-n 0` lifts the 30-resolver cap, which otherwise truncates a long file.
- `--servers-url` accepts the same plain format as well as the AdGuard provider
  tables, so a shared team list can just be a file on a web server.

To widen the *built-in* catalogue rather than add to it, reach for
`--section anycast,regional,personal`, `--include-filtered` and `-n 0`.

## EDNS Client Subnet

ECS doesn't make DNS faster — it usually makes it slower, since the resolver can
cache less. What it's supposed to buy you is a *better answer*: a CDN edge near
your network rather than near the resolver. Both halves of that trade are
measured separately, on by default (`--no-ecs` to skip).

```
  #  SERVER          PROTO      POP-AVG  RND-AVG     OK   ECS     EDGE
 1.  8.8.8.8         Do53           138      143   100%   yes     10.0
 2.  208.67.222.222  Do53          56.6      180   100%    no     16.1
 3.  9.9.9.9         Do53          27.6      285    83%  yes*     16.9
 4.  1.1.1.1         Do53          12.3     66.2   100%    no     51.2
```

**ECS** — does the resolver honour client subnet? It's asked for the same name
from two routed prefixes on different continents:

- `yes` — it echoed an ECS option with a non-zero scope. Definitive.
- `yes*` — no scope echoed, but the addresses changed with the subnet claimed,
  so it is using ECS somewhere upstream.
- `no` — same answers from both, no scope. It ignores ECS.
- `?` — the probe queries failed, so nothing can be said.

**EDGE** — the payoff, and the number worth acting on. For each CDN test domain
the resolver is asked normally (no subnet claimed, exactly as your machine would
ask), and a TCP handshake is opened to the address it returns. The column is the
median of those handshakes: how far away the edge it steered you to actually is.
That first round trip is paid by every connection your machine makes to those
services, so a resolver with slower DNS but a much closer edge can still be the
better choice. In the run above, `1.1.1.1` has the fastest DNS by a wide margin
and the worst edge by a wide margin.

`--ecs-domains a.com,b.com` replaces the default CDN test set. The checks run
once per resolver on the already-warm probe connection, adding a handful of
queries plus a few TCP connections per resolver; `--no-ecs` skips them if you
want the run shorter or would rather not open connections to CDN edges.

## How it measures

- **Connection setup is not timed.** Each resolver gets one probe query first,
  which brings the UDP socket, TCP/TLS connection or HTTP/2 connection up and is
  then discarded. Every protocol is therefore measured warm, on equal terms —
  a DoH figure is a query round trip, not a TLS handshake.
- **Resolvers are benchmarked one at a time** by default, so they aren't
  competing for the same link. `--parallel-servers N` overlaps them if you'd
  rather have the run finish sooner.
- **Queries within a resolver run concurrently** (`-c`, default 8), each worker
  on its own connection, matching how a busy client actually behaves.
- **Filtering resolvers are excluded by default**, because a blocked answer is
  not a fast answer. See "Where the lists come from".
- **A resolver that fails its probe is skipped**, rather than spending
  `domains × timeout` proving it's down.
- **The two pools are interleaved**, not run back to back, so a network hiccup
  lands on both rather than skewing one against the other.
- **`--uncached` goes further than the random pool**: it prefixes a random label
  to *every* name, so even popular domains cost a full recursion. The random
  pool shows what the long tail costs in practice; `--uncached` shows what a
  resolver can do with no cache at all.
- `OK` is the share of queries that got a response at all. `resolved` in the
  JSON/CSV output additionally requires `NOERROR` with an answer record — a gap
  between the two usually means the resolver is filtering something.

Caveats worth remembering: anycast means your result is about *your* network
path, not the provider globally; and a filtering resolver may be fast precisely
because it answered "no".

## Options

Run `dnsranker --help` for the full list. The ones that change results most:

| Flag | Default | Effect |
| --- | --- | --- |
| `-a, --add` | off | add the given specs to the catalogue instead of replacing it |
| `-d, --domains N` | 20 | domains in *each* pool |
| `--pools LIST` | `popular,random` | which pools to query |
| `-n, --max-servers N` | 30 | resolvers tested (0 = no limit) |
| `--regional N` | 8 | slots reserved for resolvers in your own country |
| `--country CODE` | `auto` | your region: an ISO code, `auto`, or `any` |
| `--include-filtered` | off | also test ad/malware/family-filtering resolvers |
| `--seed N` | 0 (fresh) | fix the random pool's sample |
| `--no-ecs` | — | skip the client-subnet and edge-latency checks (on by default) |
| `-r, --runs N` | 1 | queries per domain |
| `-c, --concurrency N` | 8 | concurrent queries per resolver |
| `-t, --timeout MS` | 2000 | per-query deadline |
| `--proto LIST` | `udp,dot,doh` | protocols to include (`tcp` also available) |
| `--uncached` | off | force full recursion instead of cache hits |
| `--type RR` | `A` | record type to query |
| `--sort KEY` | `avg` | `avg`, `median`, `p95`, `min`, `max`, `success`, `popular`, `random`, `delta` |

## Watching and interrupting a run

The ranking is drawn in place while the run happens: rows fill in as results
arrive, the resolver currently being measured is marked `»`, and a progress bar
sits underneath. On a narrow terminal the detail columns are dropped rather than
wrapped, and a table taller than the window is truncated with a `… N more` line.
Piped or redirected output gets none of this — just the final table.

Ctrl-C stops cleanly: in-flight queries are abandoned immediately (no waiting
out timeouts), resolvers that were never reached are dropped, and the results
measured so far are printed with a note about how much of the run completed. A
second Ctrl-C exits at once.

## Output formats

`--json` prints a document with run metadata and full per-resolver statistics —
each pool separately, plus rcode, error and ECS breakdowns. `--csv FILE` writes
the same ranking as a spreadsheet-friendly table, one column group per pool.
`-v` adds endpoints, error breakdowns and the returned CDN addresses to the
terminal table.
