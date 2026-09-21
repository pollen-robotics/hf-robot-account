# The client side

This crate owns one half of a sentence: *this robot belongs to that Hugging Face account*. On its
own that is inert. The half that makes it mean something lives in a browser — a page that signs a
**person** in to the same account, finds the robot that answers to it, and opens a session.

This document describes how that half works today, in the one implementation that exists: the
Reachy Mini JS SDK (`@pollen-robotics/reachy-mini-sdk`) and the three Hugging Face Spaces built on
it. It is deliberately **not** a guide to using that SDK — the package ships a 1,900-line
`APP_CREATION_GUIDE.md` for that. It is a description of the *mechanisms*, and of which of them are
about a robot with a head and two antennas and which are about any device reached through a
rendezvous server.

It is here because the generic SDK should be here, next to the crate that issues the credential the
whole chain hangs on.

**Where this overlaps something with an owner.** §2 and §3 describe a rendezvous protocol and a
session handshake that `pollen-robotics/microduck` documents from the device end, and that
repository assigns each mechanism exactly one owning page: `docs/design/remote-access-design.md`
for the account, the device flow and the rendezvous bridge, and `docs/design/remote-webrtc.md` for
sessions, signalling and the control channel. Those are the pages to correct when the wire changes.
What is written here is the *client's* view of the same wire — what a browser has to do about it,
and which parts of that are not about ducks — and when the two disagree, this one is the bug.

---

## Scope: two client shapes

Everything below is about a client that is **somewhere else** — a phone on cellular, a laptop in
another country — reaching a robot it cannot address. There are two, and the difference is who owns
the WebRTC session:

| Shape | Session owner | Example |
|---|---|---|
| **Browser-owned** | The page itself holds the peer connection and drives the device directly. | `pollen-robotics/emotions` |
| **Backend-owned** | The page forwards credentials to a server, which holds the peer connection. | `pollen-robotics/rf-detr-realtime-webcam` |

A third thing exists and is **out of scope**: an app installed on the robot, served over
`localhost`, talking to the local daemon (`pollen-robotics/reachy_mini_testbench`). It has no
account, no rendezvous, no WebRTC and no client in this sense. Its Space is a distribution listing,
not a client. The crate's own docs draw this line first, and so does this one: an account is what
makes a robot reachable from *outside* the LAN, and a program already inside the LAN needs none of
it.

---

## 1. The identity chain

```
  robot                        rendezvous ("central")            browser
  ─────                        ────────────────────              ───────
  hf-robot-account                                               OAuth authorization code
  RFC 8628 device grant        resolves a bearer token           in the page
        │                      to an HF identity, and                   │
        ▼                      scopes every view by it                  ▼
  /etc/robot/hf-token ──────►  ┌──────────────────┐  ◄──────────  sessionStorage
  30-day token,                │ producers        │               15 min … 30 day token,
  refresh rotates              │ listeners        │               tab-scoped
                               │ sessions         │
                               └──────────────────┘
                                        │
                      SDP + ICE relayed between the two peers,
                      then the relay is out of the data path
```

Both ends present a Hugging Face bearer token to the same server. The server turns each token into
an account, and **shows each side only what that account owns**. The SDK's fleet-watching helper
names this outright: its callbacks are documented as firing when a robot comes online or goes busy
*"(same-owner)"*.

So the invariant that makes the whole system work, and that is written down in neither half:

> **The account the robot signed in to with the device grant and the account the person signs in to
> in the browser must be the same account.** There is no pairing step, no claim code, no
> registration. Ownership *is* the account match.

A robot that does not appear in a client's list has one of four causes, and **the first one is on
the client**:

1. **The browser's token has expired** and the page is still presenting it. Central cannot resolve
   it to an account, so it answers with an empty directory — which is indistinguishable, on screen,
   from the robot being switched off. This is the one that actually happens: it cost a day across
   two Spaces (§8), because a page that caches a sign-in and never re-reads its expiry goes on
   displaying a username long after the credential behind it died.
2. The robot signed in to a different account.
3. The robot lost its token.
4. The robot is offline.

Only the last three are readable from `Status` on the robot side (§9). The first is invisible there
by construction — the robot is fine — which is why a client must rule it out first, and why §6's
expiry check is not optional.

The two ends acquire that identity by different grants, for reasons this crate's `lib.rs` sets out:
the robot has no browser, so it uses the device grant; the page *is* a browser, so it uses the
authorization code flow. The token lifetimes that fall out of that are worth putting side by side,
because they are the reason the robot has a maintenance loop and the browser does not:

| | Robot | Browser |
|---|---|---|
| Grant | RFC 8628 device code | Authorization code, in-page |
| Lifetime | 30 days | 8 h default; Spaces can ask for 30 days |
| Renewal | `maintain` refreshes under a week left; **refresh token rotates** | Silent re-auth (`prompt=none`) on demand |
| Storage | File, `0640`, root-owned, group-readable | The SDK: `sessionStorage`, tab-scoped, plus a 24 h sliding idle window. Other clients differ — see §6 |
| Scopes | Everything the first-party client grants, unless you register your own | `openid profile` — nothing else, deliberately |

The scope row runs the wrong way and is worth fixing on this side. The browser gets identity and
nothing more; the robot, using Hugging Face's first-party device client, gets `write-repos`,
`manage-repos`, `jobs` and `read-billing` for a credential whose only job is to say who it is.
`Config::client_id` and a public device-code client registered to your own org is the fix, and the
crate's README already says so.

---

## 2. The rendezvous

Central is an HTTP service. Today it is itself a Hugging Face Space
(`pollen-robotics-reachy-mini-central.hf.space`), hardcoded as the SDK's default. It does two jobs:
it is a **directory** of the devices an account owns, and it is a **signaling relay** that carries
SDP and ICE between two peers that cannot address each other. Once the peer connection is up it is
out of the data path entirely.

### The wire

Two endpoints, both authenticated with `Authorization: Bearer <hf-token>`:

- **`GET /events`** — Server-Sent Events, held open. Inbound: `welcome`, `list`,
  `peerStatusChanged`, `sessionStarted`, `sessionRejected`, `endSession`, `peer`.
- **`POST /send`** — one JSON envelope per call, answered with JSON. Outbound: `setPeerStatus`,
  `list`, `startSession`, `endSession`, `peer`.

`peer` carries the WebRTC payload in both directions — `{ sessionId, sdp }` or
`{ sessionId, ice }` — and is the only message type that means anything to WebRTC.

Note what is *not* used: the browser's native `EventSource`. It cannot set headers, which would put
the token in the URL and therefore in DevTools, proxy logs and browser history. The SDK uses
`fetch` with a manual `ReadableStream` reader and splits on `data:` lines itself. Any replacement
has the same constraint.

### Peer identity, leases, and why the peer id is not an identifier

On connecting, `welcome` assigns a **peer id** and advertises a lease —
`lease_seconds`, and optionally `recommended_heartbeat_interval_seconds`. A peer that goes quiet is
evicted at the end of its lease *even though its SSE stream is still open*, so every peer re-POSTs
its `setPeerStatus` on a timer (falling back to `lease_seconds / 3` when no cadence is
recommended). Repeated `setPeerStatus` from the same peer is defined as a refresh, so the heartbeat
and the initial registration are byte-identical.

The consequence that catches people: **the peer id rotates on every relay reconnect.** It is a
handle on a connection, not a name for a device. The protocol grew a second field for this — a
stable `meta.hardware_id` — and the host now passes both to the app, which re-resolves the *current*
peer id from the hardware id immediately before dialing. Without that, an iframe with a slow cold
start dials a producer that no longer exists.

A generic SDK should not repeat this as an afterthought. **Two identifiers, named as what they
are**: a durable device id that survives reconnects, and an ephemeral routing id that does not.

### The one-peer-per-token rule

Central maps **one token to one peer**. That single sentence explains an entire class of design in
the SDK:

- A picker screen that wants a live view of the fleet cannot just open an SDK instance, because that
  registers a peer and clobbers the slot the next session's handshake needs. Hence a separate
  listener (`roles: ["listener"]`) that watches without claiming.
- When the shell hands off to the app iframe, the shell must `disconnect()` its own SDK *before*
  the app connects, or central still believes the shell owns the device. This is the "Robot is busy"
  false positive, and it is a protocol consequence, not a bug in any one screen.
- The shell registers as `"<appName> (shell)"` so that the narrow window where both exist is legible
  in central's logs.

Roles are the mechanism that makes this survivable: `listener` observes, a producer serves, a
consumer claims. A generic relay should keep them, and should probably relax the 1:1 rule to
*one session-claiming peer per token*, which is the property actually being protected.

---

## 3. The session

### The device dials, the client answers

This is inverted from the usual browser assumption and it is the single most surprising thing in
the protocol:

> **The robot creates the offer. The client creates the answer.**

`startSession` is a request to central naming a producer. What comes back over SSE is the device's
`peer` message carrying an **offer**; the client calls `setRemoteDescription`, `createAnswer`,
`setLocalDescription` and posts the answer back. The Python backend consumer does exactly the same
thing with aiortc, which is the useful proof that none of this is browser-specific.

ICE is trickled both ways and buffered in one direction: remote candidates that arrive before the
remote description is set are queued and replayed afterwards. The empty-string candidate is the
end-of-candidates marker — legal and optional in the spec — and must be dropped rather than
forwarded, because Safari and the iOS WKWebView reject it with `OperationError`. aiortc, by
contrast, gathers everything before `setLocalDescription` returns, so the backend sends one answer
and never trickles out. A relay must tolerate both.

### The channels the device opens

The client never calls `createDataChannel`. It waits on `ondatachannel`, and the device opens
**two**, distinguished by label:

- **the control channel** (reliable, ordered) — commands and replies. This one is `_dc`, and its
  `open` event is half of the session-ready condition.
- **`pose`** (unreliable, unordered) — pushed device state at roughly 30 Hz, opened lazily when the
  client subscribes, so it can appear mid-session. Frames carry a `seq`; anything at or below the
  high-water mark is dropped, because an unordered channel will happily hand you a stale frame and
  rewind the state mirror the stream exists to smooth. The mark resets to `null` on every new
  channel, since the device's counter restarts too.

Two channels with opposite reliability guarantees for two genuinely different jobs — *do this thing
and tell me it worked* versus *here is the world, most recent wins* — is a good pattern and
transfers directly.

Alongside it sits a subtlety worth stealing: while pose frames are arriving, the periodic state
poll **stands itself down**, and resumes on its own if the stream stalls for more than 750 ms. Poll
replies carry no `seq`, so a reply crossing a fresher pushed frame would rewind the mirror. Keying
the suppression on *frame arrival* rather than on a subscription flag means it also does the right
thing against a device too old to know about the pose channel at all.

The session is ready when **ICE is connected and the control channel is open** — not when either one
is. Both halves have to land.

### Audio, and the track nobody plays

To receive audio *from* the device, WebRTC needs the audio section negotiated `sendrecv`, which
means the client must offer a sending track. The SDK will not call `getUserMedia` — asking for a
microphone permission the app never requested would be indefensible — so it attaches a **silent
placeholder**: a zero-gain oscillator into a `MediaStreamDestination`, track disabled. An app that
actually wants to send audio calls `replaceTrack()` on that sender afterwards.

It also inspects the offer SDP for `a=sendrecv` on the audio section to decide whether the device
supports bidirectional audio at all, and reports that as an event rather than assuming.

Two device-independent lessons: **negotiate the shape of the media up front, populate it later**,
and **never acquire a capture device on the user's behalf**.

---

## 4. The command channel

One data channel multiplexes four request/response disciplines, each with its own correlation rule:

1. **Reply slots** — commands whose replies carry no request id, correlated by *message type*.
   Single-flight per type; a newer call resolves the older waiter with `null`.
2. **JSON-RPC** — correlated by an id the client mints. The general case.
3. **Motion completions** — acks correlated by command name, FIFO.
4. **Broadcast waiters** — device-initiated lifecycle events matched by a caller-supplied predicate.

All four live in **one ledger**, settled in a single call on every teardown path. That is the part
to keep: the reason it is one object is that there is then no way to add a fifth mechanism and
forget it in one of the five places a session can die. Every pending promise is settled by a
transport that is going away, always, by construction.

Slot calls **fail open**: a 4-second timeout resolves `null` rather than rejecting, because the
failure mode being handled is a newer client calling a command an older device silently drops.
`null` maps onto the "unsupported or failed" branch every caller already has, and a gated UI never
hangs. Version-skew tolerance as a timeout policy, not a capability handshake — cheap and
surprisingly effective.

The slot discipline is also the clearest piece of debt in the SDK, and its own source comments say
so: correlating by type means a genuinely late reply can be delivered to a *newer* caller of the
same command. A replacement should have **one** discipline — an id on every request — and keep the
ledger.

---

## 5. Resilience is most of the SDK

A phone on cellular, in a pocket, roaming between access points is the normal case, not the edge
case. The transport layer is the largest part of the SDK that has nothing whatsoever to do with
robots, and it is the part most worth lifting wholesale.

**ICE blips are debounced.** `disconnected` is transient per spec and browsers usually heal it in a
second or two, so it gets a 3 s grace window. `failed` is terminal per spec, but real
`failed → connected` flips have been observed on fast AP roams and iOS Bluetooth route changes, so
it gets 1 s anyway. Both are cancelled the moment ICE heals.

**A hidden tab defers judgement, but not forever.** Timers throttle when a tab is backgrounded, so
grace evaluation waits for the tab to come back — capped at 60 s. The cap is not arbitrary: the
device's own STUN consent-freshness check (RFC 7675, ~30 s) tears its side down and releases the
producer slot past that window, so a longer grace would be a lie. **A client's patience must be
bounded by the peer's, and you have to go and find out what the peer's is.**

**Recovery is the whole session, because there is no ICE restart.** The device's GStreamer
`webrtcbin` cannot do a standards ICE restart, so the recovery unit is the session: tear the dead
peer connection down and dial the same device again through central. Backoff is
`0, 2, 4, 8, 8` seconds — a ~22 s window — with each attempt capped at 15 s, because past that the
device probably still holds the previous dead session and the attempt is better spent against a
freed slot. Crucially this lives *in the SDK*, so every consumer inherits it instead of five apps
each half-implementing it.

**Silence is a failure even when ICE says otherwise.** A live session always has inbound traffic —
poll replies at worst every 500 ms, pose frames at ~30 Hz — so total silence means a dead transport
that ICE has not noticed. A half-open link dodges STUN consent checks for tens of seconds. The
watchdog ticks at 1 s, nudges with one extra request at 2.5 s, and escalates at 8 s: roughly four
times faster than consent freshness would get there. A hidden or throttled tab re-baselines instead
of judging stale timestamps.

And one ownership rule that keeps all of this honest: the supervisor **never touches** the peer
connection, the data channel or any promise. It receives forwarded events and calls injected
dependencies. The transport owns the transport; the supervisor owns the *recovery policy*. That
split is why the policy is testable, and why it can be lifted out of a Reachy-specific SDK at all.

There is also a case where resilience must be switched **off**: a deliberate device reboot (a
firmware update) needs the teardown to surface immediately as "install done, rebooting", not get
absorbed by 22 s of doomed reconnects. Any generic implementation needs the same escape hatch, and
should note the sharp edge the SDK documents — cancelling an in-flight re-dial leaves the session
down without emitting a terminal event, so the caller owns it.

---

## 6. Credentials in a browser

`authenticate()` returns a boolean and does three things in order, which is two too many but is at
least the right three:

1. **Consume fragment credentials.** A `#hf_token=…&hf_username=…&hf_token_expires=…` fragment is
   moved into `sessionStorage` and the fragment is wiped. This is the escape hatch for a host page
   that already holds a token and embeds the app in an iframe — `huggingface.co/login` sends
   `X-Frame-Options: SAMEORIGIN`, so a full OAuth round trip inside an iframe cannot complete.
   Fragments are never sent over HTTP, so nothing leaks to the Space backend or an intermediate
   proxy.
2. **Complete an OAuth redirect** if the URL carries one, and cache the result.
3. **Read the cache**, subject to both the OAuth expiry *and* a 24 h sliding idle window.

That idle window replaced a wipe-on-`pagehide` policy that could not distinguish a refresh from a
tab close and logged people out on every F5. It keeps the one real threat — a tab resurrected days
later by session restore — and stops punishing reloads.

**Step 3 is the rule. The storage medium is a surface choice.** Those are worth separating, because
the SDK makes one choice and it is not the only correct one:

- The SDK uses `sessionStorage` — tab-scoped, dies with the tab.
- The `microduck-console` and `microduck-policy-playground` Spaces use `localStorage`, deliberately:
  their OAuth redirect can come back in a **new tab**, where a session store is empty and reads as
  a sign-in that silently did nothing.

Both are defensible and the difference is about how the redirect lands, not about security. What is
*not* optional is reading the expiry back. Both of those Spaces stored the whole OAuth result —
expiry included — and then presented the token forever without ever looking at it, which is the
§1 failure this document now leads with. A generic SDK should therefore expose the expiry check and
let the surface pick the medium, rather than hard-coding `sessionStorage` and calling the pair one
decision.

Sign-in has a silent mode. `prompt=none` sends an already-authorized user straight back with a code
and no visible screen; anyone else comes back with `?error=login_required` instead of landing on a
login page. Those error params are stripped from the URL before an app router or a copy-pasted link
can carry them around. Silent re-auth is what makes a short token lifetime bearable, and it is what
lets a page recover from an expired token without a visible interruption.

---

## 7. The shell / app split

### Why an iframe

Every app needs the same four screens — sign in, pick a device, show connection progress, leave
cleanly — and none of them are the app. Putting them in a **host shell** that renders *around* the
app in an iframe buys two things: a fix to sign-in reaches every deployed app without any app being
rebuilt, and an app author can use any framework at all, because the shell is on the other side of
an origin boundary.

The price is honest and worth stating: every app loads the shell's React + MUI bundle for its
sign-in and picker screens, whatever the app itself is written in.

One page serves both roles. A dispatcher reads the URL and either mounts the shell (top-level visit)
or boots the app (`?embedded=1`), and the shell iframes **its own origin** to produce the second.

### The handoff

```
user clicks a device
  host  → mounts iframe at <same-origin>?embedded=1#creds=<base64>
  embed → decodes the hash, wipes it with replaceState (first synchronous tick, before any await)
  embed → postMessage  embed:ready
  host  → disconnect() its own SDK          ← frees the peer slot
  host  → postMessage  host:init
  embed → connect() → startSession() → wake
  embed → postMessage  embed:app-state { phase: 'live' }
  host  → fades its overlay out
```

Every envelope carries `source: 'reachy-mini'` and `version: 1`. The version integer is the only
sanctioned way to break the protocol; new optional fields ship without touching it. Both sides check
`event.origin`, but against *different* references — the web shell demands strict same-origin,
while an app embedded by a native shell accepts its parent's origin resolved from
`document.referrer`, because a Tauri webview is a different origin by construction.

The credentials bundle travels **in the hash, never the query**: hashes are not sent to servers, do
not appear in `Referer`, and do not land in Spaces access logs. It carries a deliberately short-lived
token (documented as 15 minutes), the device's ephemeral and stable ids, the signaling URL, and the
theme and opaque config.

### Two invariants that are not obvious

**The boot must be idempotent.** React Strict Mode mounts every component twice in development. Two
`embed:ready` posts means two SDK instances, two competing peer connections and a ghost session at
central. The fix is a module-level promise: calling the connect helper twice returns the same
in-flight promise, full stop. Any generic version needs this, and needs it at the module level
rather than in a hook.

**Media has a real race, and the API exists to solve it.** The connect helper completes the entire
WebRTC handshake *before* the app's UI mounts. `pc.ontrack` and the SDK's one-shot track event have
therefore already fired by the time a freshly-mounted component subscribes — any listener registered
afterwards sits silent until the next `startSession()`, which an embedded app never triggers. So the
handle exposes a media accessor that **replays streams from a synchronous snapshot of the peer
connection's receivers**. There is no equivalent race on the data channel, because the handshake
only resolves once ICE *and* the channel are up and state then streams continuously.

The general rule: **a boot sequence that finishes before the UI exists must hand back state, not
events.** Anything one-shot that fired during boot has to be replayable from the handle.

### Credentials-only mode

For the backend-owned shape, the same handshake runs through `host:init` and then **stops**: no SDK
instance, no `connect`, no `startSession`. The handle exposes only `{ hfToken, robotPeerId,
signalingUrl }` plus the lifecycle callbacks, and the app forwards those three to its own server,
which dials central itself. The reason it is a separate entry point rather than a flag is the
one-peer-per-token rule again: a browser session and a backend session on the same token race, and
central rejects one of them as busy.

This is the mode that proves the protocol is not a JS protocol. The Python consumer speaks the same
SSE and the same envelopes, with aiortc, in a single file.

---

## 8. Deployment, as of today

Worth recording because the SDK's own guide has drifted from all three live Spaces, and an agent
following it lands in a broken state:

- The guide's canonical path is a **static** Space with `app_build_command: npm ci && npm run
  build`. Hugging Face now restricts `app_build_command` to paid Team/Enterprise plans; the Emotions
  Space hit `CONFIG_ERROR` and moved to a **Docker** Space. Docker Spaces do *not* get HF's native
  `window.huggingface.variables` injection — that is a static-Space feature — so its `server.mjs`
  splices the same bootstrap into `index.html` at request time from environment variables, exposing
  only the public ones and never the OAuth client secret.
- A Gradio Space runs no `npm` at all, so `rf-detr` **commits its built bundle** and rebuilds by hand
  before every push.
- The Space must be **public**. A private Space cannot load inside HF's iframe wrapper, because the
  `hf_jwt` cookie is SameSite-blocked cross-origin.
- The SDK pin has drifted too: the guide says `1.8.0` throughout, Emotions ships `1.10.0-rc.5`.
- So has the dispatch rule: the guide requires `?embedded=1` **and** a creds hash; Emotions accepts
  `?embedded=1` *or* `?embed=1` and no hash.

The lesson for the generic SDK is not about Spaces. It is that **the host page's runtime
configuration has to have one documented injection point**, with the platform's native mechanism as
one implementation of it rather than as the assumption.

### Three more Spaces, and the same two faults twice

`microduck-console`, `microduck-policy-playground` and `telepresence` are the in-house data points,
and they are worth recording because two of them failed in exactly the way the lesson above
predicts. Neither console nor playground is built on the SDK, so neither inherited §6 — and both
were Docker Spaces waiting for an injection that is a static-Space feature.

- Both **hard-coded or placeholder-substituted the client id** and guessed the scopes, instead of
  reproducing `window.huggingface.variables`. They now write the whole object from the
  environment, as `telepresence`'s `server.mjs` does. Scopes come from `OAUTH_SCOPES` rather than a
  literal, because that variable is Hugging Face reporting back what it provisioned the app with.
- Both **stored the OAuth expiry and never read it**, which is §1's first cause and §6's rule.

Two platform facts worth having written down, from `huggingface/hub-docs`: `hf_oauth_expiration_minutes`
defaults to **480** (8 h) and caps at **43200** (30 days), and `openid profile` is *always* included
in a Space's OAuth app whether or not `hf_oauth_scopes` lists anything. So a page that reads
`OAUTH_SCOPES` can never come away with less than identity.

And one trap that is specific to injecting the object yourself: **anchor the match to the `<head>`
tag, not the first `<head>` in the file.** A page whose own comments discuss that tag — the console's
do, because its `<html>`/`<head>` skeleton is load-bearing for exactly this reason — will take a
naive first-match replace *inside an HTML comment*, where the bootstrap never runs. The page then
looks precisely like a Space with no OAuth app, which is the failure the comments were recording.

---

## 9. Extracting the generic SDK

### What transfers unchanged

Everything in §2 (the rendezvous wire, roles, leases, heartbeats, the two identifiers), §3's
negotiation shape (device offers, client answers, buffered trickle, two channels of opposite
reliability, media negotiated up front and populated later), §4's single settle-everything ledger,
**all of §5**, §6's token handling — the expiry check especially, and as a seam rather than a
hard-coded medium — and §7's protocol, idempotency rule and media replay.

That is the great majority of the code and essentially all of the hard-won parts. A device-agnostic
SDK is the existing one minus its verbs.

### What must be parameterised

- **The command vocabulary.** `setHeadRpyDeg`, `setAntennasDeg`, `setBodyYawDeg`, `playSound`,
  `playRecordedMove`, `wakeUp`, `gotoSleep`, head tracking, IMU, motor mode and torque, volume,
  daemon update — every one of these is a Reachy Mini verb sitting on the generic `request()` and
  `sendRaw()` underneath. Ship the transport; let a device profile supply the verbs.
- **The state schema.** A 4×4 head matrix, `[right, left]` antennas and a body yaw is one device's
  telemetry. The pose channel's *mechanism* — unordered, sequenced, deduplicated, suppressing the
  poll — is general; its payload is not.
- **The readiness definition.** The connect helper currently waits for a wake trajectory to finish,
  with a 5 s budget, and the shell's progress indicator has a literal `wake` step. "Connected" and
  "ready to be commanded" are genuinely different states for a device with motors, but *what* makes
  a device ready belongs to the profile.
- **ICE servers.** The SDK hardcodes a Google STUN server, and `rf-detr` separately fetches
  Cloudflare TURN credentials per visitor. There should be one injected ICE configuration; a device
  behind symmetric NAT needs TURN and no hardcoded default will do.
- **The rendezvous URL and the OAuth provider.** Both are Hugging Face today and both are
  hardcoded defaults. This crate already does the right thing on the robot side by honouring
  `HF_ENDPOINT`; the client needs the same seam.
- **The shell's screens.** Sign-in, picker and progress copy are specific to devices, accounts and
  the number of steps a boot takes.

### What should not be carried forward

Stated as observations, several of which the SDK's own comments already make:

- **Reply slots correlated by message type.** Single-flight and admits documented cross-talk between
  a late reply and a newer caller. One correlation discipline — an id per request.
- **`window.ReachyMini` plus a `reachymini:ready` event and an 8-second wait loop.** This is a
  bundling workaround from the era of a CDN script tag, now that the package is imported from npm.
  A module import is the handoff.
- **Underscore-private fields read from outside.** The host's media wrapper exists partly because
  `_pc` and `_micStream` are the only way to reach what apps need. Make them API.
- **`authenticate()` doing three unrelated things** and reporting all of them as one boolean.
  Separate consuming injected credentials, completing a redirect, and reading the cache.
- **Refetching the entire directory on every `peerStatusChanged`.** The event already carries the
  peer, its roles and its metadata; apply it.
- **Tolerating both `?embedded=1` and `?embed=1`.** Protocol drift accreted during a refactor,
  already inconsistent with the written contract. Pick one and version it.

### The seam with this crate

The two halves meet at exactly one place, and both sides already have the right shape for it.

`Status` here carries `account`, `login` and `last_error` — who the robot belongs to, a login in
flight with the time left on its code, and why the last thing that failed, failed. That is precisely
what a client's "this robot" screen and its failure copy need, and the mapping is direct:

| Client symptom | Cause |
|---|---|
| Device absent from the picker, **and no `Status` can be read** | Check the browser's own token first: an expired one yields an empty directory, not an error. §1. |
| Device absent from the picker | `account: None` — never signed in. Show the device code. |
| Device absent, but owner is set | Different account, or `last_error` names a refresh failure. |
| Device present, dials fail | Not an account problem. Session slot, or the device is offline. |
| Owner shown as `unknown` | Login worked, `/oauth/userinfo` did not. Cosmetic; `maintain` fixes it. |

The one window this crate documents as unclosable — a power cut between the server issuing a
rotated refresh token and that pair reaching the disk — surfaces as a device that silently stops
appearing about a month later. A client that surfaces `last_error` turns that from a mystery into a
sentence, and the remedy is a fresh login.

A generic SDK should therefore define one small **account status** shape as part of its contract,
and treat "which device am I allowed to see" as the same question as "who does this device belong
to", asked from the other end.
