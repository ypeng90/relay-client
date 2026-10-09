#!/usr/bin/env zsh
# relay work client.
#
# Pure-zsh terminal client for the work side of the relay. It unlocks the
# mailbox GitHub token (sealed under the day's key), lists waiting sessions and
# their threads on the alternate screen, and posts sealed replies back to
# GitHub. Only /usr/bin/curl, /usr/bin/openssl and /usr/bin/python3 are used.
#
# Crypto method (matches src/relay/crypto.ts byte-for-byte):
#   day key = PBKDF2-HMAC-SHA256("<pass> <w1 w2 w3>", salt, 600000, 32)
#   enc/mac = sha256(day_key_hex + ":enc" / ":mac")
#   wire    = AES-256-CBC + HMAC-SHA256 EtM, "v1:<id>:<ts>:<sender>:<iv>:<ct>"

# The daily job replaces this placeholder with the day's sealed mailbox token,
# base64-encoded so it embeds safely as a single shell token.
SEALED_MAILBOX_TOKEN="PCEtLXJlbGF5OnYxLS0+CnsidiI6MSwiaWQiOiIyNjU3ZjllNDI0M2UxYTA3YzQyZWU3NTgxODlkZWI1ZCIsInRzIjoxNzkxNTYxNjA0LCJzZW5kZXIiOiJob21lIiwicmVwbHlfdG8iOm51bGwsInNlcSI6MCwiaXYiOiJhMjFhYTk0YzI4ODc5ZDMyMjkzOTUwNDJiNmRjMzVmMSIsInRhZyI6ImRiNGEzZTY1YTdlOWJmY2IzZDhiNzE2NzhmMWI3NTdmZWJkMDBhMzAyMDk1MmM2YWZlYzBhNGQyMzI4N2MxYzgiLCJjdCI6IjYydHJXOG9tMkJ6UE5Femx0ZEZVczF1anZZdFlraldOU0hvT3NCL1I0R0VxVTFIdk4rb3EraDBSYTA4M1NyZjZvUmFRQU5vcGU1R0liUkZUZUk4aVlPMEJvRTZUYkVJb2RYdU1yeWVxVmFTcjJ4TmRTeTBDMjF6U1ovWFdxMUhmIn0="

# Public, non-secret configuration (mirrors config.toml). Overridable so the
# script can be exercised without the home repo.
: ${RELAY_SALT_HEX:=ff7a202975a814664d765a52801cc3d4}
: ${RELAY_MAILBOX_REPO:=ypeng90/relay-mailbox}
: ${RELAY_API:=https://api.github.com}
: ${RELAY_REFRESH_MINUTES:=5}

WIRE_PREFIX='<!--relay:v1-->'
PLACEHOLDER_MARKER='<!--relay:placeholder-->'

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

# derive_day_key_zsh <pass> "<w1 w2 w3>" <salt_hex> -> lowercase hex
# Inputs travel through the environment, never argv.
derive_day_key_zsh() {
  local pass="$1"
  pass="${pass#"${pass%%[![:space:]]*}"}"   # trim leading whitespace
  pass="${pass%"${pass##*[![:space:]]}"}"   # trim trailing whitespace
  local combined="${pass} ${2:l}"
  DK_IN="$combined" DK_SALT="$3" /usr/bin/python3 -c '
import os, hashlib, binascii
print(hashlib.pbkdf2_hmac("sha256", os.environ["DK_IN"].encode(),
      binascii.unhexlify(os.environ["DK_SALT"]), 600000, 32).hex())'
}

# sha256(day_key_hex + suffix), matching crypto.ts createHash usage.
derive_enc_key() {
  printf '%s:enc' "$1" | /usr/bin/openssl dgst -sha256 | awk '{print $NF}'
}
derive_mac_key() {
  printf '%s:mac' "$1" | /usr/bin/openssl dgst -sha256 | awk '{print $NF}'
}

# _hmac_sha256 <mac_key_hex> <message> -> hex digest
# Key and message travel through the environment, never argv.
_hmac_sha256() {
  MACHEX="$1" MSG="$2" /usr/bin/python3 -c '
import os, hmac, hashlib, binascii
print(hmac.new(binascii.unhexlify(os.environ["MACHEX"]),
      os.environ["MSG"].encode(), hashlib.sha256).hexdigest())'
}

# _b64d <base64> -> decoded bytes on stdout
_b64d() {
  B64="$1" /usr/bin/python3 -c '
import os, base64, sys
sys.stdout.write(base64.b64decode(os.environ["B64"]).decode())'
}

# seal_message_zsh <plaintext> <enc_key_hex> <mac_key_hex> <sender> [id] [reply_to] [seq]
# Prints the wire payload (prefix + JSON). The plaintext reaches openssl on
# stdin, never argv.
seal_message_zsh() {
  local plaintext="$1" enc_key="$2" mac_key="$3" sender="$4"
  local id="$5" reply_to="$6" seq="$7"
  [[ -n "$id" ]] || id=$(/usr/bin/openssl rand -hex 16)
  [[ -n "$seq" ]] || seq=0
  local ts=$(date +%s)
  local iv=$(/usr/bin/openssl rand -hex 16)

  local ct
  ct=$(printf '%s' "$plaintext" | /usr/bin/openssl enc -aes-256-cbc \
        -K "$enc_key" -iv "$iv" -base64 -A) || return 1

  local tag
  tag=$(_hmac_sha256 "$mac_key" "v1:${id}:${ts}:${sender}:${iv}:${ct}") || return 1

  local json
  json=$(ID="$id" TS="$ts" SENDER="$sender" REPLY_TO="$reply_to" SEQ="$seq" \
         IV="$iv" TAG="$tag" CT="$ct" /usr/bin/python3 -c '
import os, json
r = os.environ["REPLY_TO"]
reply_to = None if r in ("", "null") else int(r)
obj = {
  "v": 1,
  "id": os.environ["ID"],
  "ts": int(os.environ["TS"]),
  "sender": os.environ["SENDER"],
  "reply_to": reply_to,
  "seq": int(os.environ["SEQ"]),
  "iv": os.environ["IV"],
  "tag": os.environ["TAG"],
  "ct": os.environ["CT"],
}
print(json.dumps(obj, separators=(",", ":")))') || return 1

  printf '%s\n%s\n' "$WIRE_PREFIX" "$json"
}

# _open_wire_fields_zsh <wire> <enc_key_hex> <mac_key_hex>
# Parses and MAC-verifies the wire payload. On success WIRE_FIELDS holds the
# newline-separated fields: id, ts, sender, reply_to, seq, iv, tag, ct.
_open_wire_fields_zsh() {
  local wire="$1" mac_key="$3"
  if [[ "$wire" == "$WIRE_PREFIX"$'\n'* ]]; then
    wire="${wire#*$'\n'}"
  fi
  local fields
  fields=$(WIRE="$wire" /usr/bin/python3 -c '
import os, json, sys
o = json.loads(os.environ["WIRE"])
def s(v):
    # A non-empty token for every field: zsh drops empty elements when
    # splitting on newlines, which would shift the field indices.
    return "null" if v is None else str(v)
sys.stdout.write("\n".join([s(o["id"]), s(o["ts"]), s(o["sender"]),
    s(o["reply_to"]), s(o["seq"]), s(o["iv"]), s(o["tag"]), s(o["ct"])]))') || return 1
  local -a f=("${(f)fields}")
  (( ${#f} == 8 )) || return 1
  local expected
  expected=$(_hmac_sha256 "$mac_key" "v1:${f[1]}:${f[2]}:${f[3]}:${f[6]}:${f[8]}") || return 1
  [[ "$expected" == "${f[7]}" ]] || {
    print -u2 "relay: HMAC verification failed"
    return 1
  }
  WIRE_FIELDS="$fields"
  return 0
}

# open_message_zsh <wire> <enc_key_hex> <mac_key_hex> -> plaintext on stdout
open_message_zsh() {
  _open_wire_fields_zsh "$1" "$2" "$3" || return 1
  local -a f=("${(f)WIRE_FIELDS}")
  printf '%s' "${f[8]}" | /usr/bin/openssl enc -d -aes-256-cbc \
    -K "$2" -iv "${f[6]}" -base64 -A
}

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

# format_idle_line <waiting> <total> <checked HH:MM>
format_idle_line() {
  printf 'relay · %s/%s waiting · checked %s' "$1" "$2" "$3"
}

# format_thread_comment <seq> <HH:MM> <text>
format_thread_comment() {
  printf ' #%s  %s  %s' "$1" "$2" "$3"
}

# check_key_mapped <key> -> "yes"/"no". Tab is explicitly NOT mapped.
check_key_mapped() {
  case "$1" in
    h|[1-9]|r|b|q|$'\e') print -r -- yes ;;
    *) print -r -- no ;;
  esac
}

# ---------------------------------------------------------------------------
# GitHub API (curl). The token is supplied through a curl config file passed
# via process substitution, so it never appears in argv.
# ---------------------------------------------------------------------------

_gh_curl() {
  /usr/bin/curl -sS -K <(printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n' "$RELAY_TOKEN") "$@"
}
_gh_get() { _gh_curl "$RELAY_API$1"; }
_gh_post() { _gh_curl -X POST -H 'Content-Type: application/json' -d "$2" "$RELAY_API$1"; }

# ---------------------------------------------------------------------------
# Client state and data
# ---------------------------------------------------------------------------

typeset -a ISSUES COMMENTS
typeset WAITING_COUNT=0 TOTAL_COUNT=0
typeset CURRENT_ISSUE="" LATEST_SEQ=0
typeset NEW_IN_THREAD=0 UNREACHABLE=0
typeset VIEW="idle"

_now_hm() { date +%H:%M; }

fetch_issues() {
  ISSUES=()
  local json
  json=$(_gh_get "/repos/${RELAY_MAILBOX_REPO}/issues?labels=waiting&state=open&per_page=50") || {
    UNREACHABLE=1
    return 1
  }
  UNREACHABLE=0
  local num title body
  while IFS=$'\t' read -r num title body; do
    [[ -n "$num" ]] && ISSUES+=("$num|$title|$body")
  done < <(JSON="$json" /usr/bin/python3 -c '
import os, json
data = json.loads(os.environ["JSON"])
for it in data:
    body = (it.get("body") or "").replace("\t", " ").replace("\n", " ")
    print("%s\t%s\t%s" % (it.get("number"), it.get("title", ""), body))
')
  WAITING_COUNT=${#ISSUES[@]}
  TOTAL_COUNT=$WAITING_COUNT
  return 0
}

# fetch_comments <issue> -> COMMENTS entries "id|created_at|<body base64>"
fetch_comments() {
  COMMENTS=()
  local json
  json=$(_gh_get "/repos/${RELAY_MAILBOX_REPO}/issues/$1/comments?per_page=100") || {
    UNREACHABLE=1
    return 1
  }
  UNREACHABLE=0
  local cid created body_b64
  while IFS=$'\t' read -r cid created body_b64; do
    [[ -n "$cid" ]] && COMMENTS+=("$cid|$created|$body_b64")
  done < <(JSON="$json" /usr/bin/python3 -c '
import os, json, base64
data = json.loads(os.environ["JSON"])
for c in data:
    body = c.get("body") or ""
    b64 = base64.b64encode(body.encode()).decode()
    print("%s\t%s\t%s" % (c.get("id"), c.get("created_at", ""), b64))
')
  return 0
}

# _comment_wire <base64 body> -> raw wire on stdout
_comment_wire() {
  _b64d "$1"
}

# _comment_seq <raw wire> -> sequence number, or empty for a placeholder
_comment_seq() {
  local wire="$1"
  if [[ "$wire" == *"$PLACEHOLDER_MARKER"* ]]; then
    local tail="${wire##*#}"
    print -r -- "${tail%% *}"
    return 0
  fi
  _open_wire_fields_zsh "$wire" "$ENC_KEY" "$MAC_KEY" 2>/dev/null || return 1
  local -a f=("${(f)WIRE_FIELDS}")
  print -r -- "${f[5]}"
}

# _thread_latest_seq -> highest seq among decoded messages
_thread_latest_seq() {
  local latest=0 entry wire seq
  for entry in "${COMMENTS[@]}"; do
    wire=$(_comment_wire "${entry##*|}")
    seq=$(_comment_seq "$wire") || continue
    [[ "$seq" == <-> ]] || continue
    (( seq > latest )) && latest=$seq
  done
  print -r -- "$latest"
}

# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

render_idle_screen() {
  print -r -- "$(format_idle_line "$WAITING_COUNT" "$TOTAL_COUNT" "$(_now_hm)")"
}

render_list_screen() {
  render_idle_screen
  local i=1 entry num title body
  for entry in "${ISSUES[@]}"; do
    num="${entry%%|*}"
    title="${entry#*|}"
    body="${title#*|}"
    title="${title%%|*}"
    printf ' [%s] %-12s waiting  "%s"\n' "$i" "$title" "$body"
    (( i++ ))
  done
  print -r -- " h hide · 1-9 open · r refresh · q quit"
}

render_thread_screen() {
  if (( NEW_IN_THREAD )); then
    print -r -- "relay · ● new in this thread, r to reload"
  else
    render_idle_screen
  fi
  local entry created body_b64 wire when seq sender name marker text
  for entry in "${COMMENTS[@]}"; do
    created="${entry#*|}"
    body_b64="${created#*|}"
    created="${created%%|*}"
    when="${created:11:5}"
    wire=$(_comment_wire "$body_b64")
    if [[ "$wire" == *"$PLACEHOLDER_MARKER"* ]]; then
      seq=$(_comment_seq "$wire")
      print -r -- "$(format_thread_comment "$seq" "$when" "answered elsewhere")"
      continue
    fi
    if _open_wire_fields_zsh "$wire" "$ENC_KEY" "$MAC_KEY" 2>/dev/null; then
      local -a f=("${(f)WIRE_FIELDS}")
      seq="${f[5]}"
      sender="${f[3]}"
      text=$(open_message_zsh "$wire" "$ENC_KEY" "$MAC_KEY")
      name="Claude"
      [[ "$sender" == "work" ]] && name="You"
      marker=""
      (( seq == LATEST_SEQ )) && marker="   ← waiting"
      print -r -- "$(format_thread_comment "$seq" "$when" "$name   $text")$marker"
    fi
  done
  print -r -- " Enter reply · b back · h hide · q quit"
}

# ---------------------------------------------------------------------------
# Interaction
# ---------------------------------------------------------------------------

select_issue() {
  local idx="$1"
  (( idx >= 1 && idx <= ${#ISSUES[@]} )) || return 1
  local entry="${ISSUES[$idx]}"
  CURRENT_ISSUE="${entry%%|*}"
  fetch_comments "$CURRENT_ISSUE" || return 1
  LATEST_SEQ=$(_thread_latest_seq)
  NEW_IN_THREAD=0
  return 0
}

# Reload-before-send: re-fetch the thread, and if the comment count changed ask
# `send anyway as a reply to #n? [y/N/e]` before posting.
start_reply() {
  tput cnorm 2>/dev/null
  stty echo 2>/dev/null
  print -n "reply> "
  local text
  read -r text
  stty -echo 2>/dev/null
  [[ -n "$text" ]] || { tput civis 2>/dev/null; return 0 }

  local before=${#COMMENTS[@]}
  fetch_comments "$CURRENT_ISSUE"
  local after=${#COMMENTS[@]}
  local reply_to=$LATEST_SEQ
  if (( after != before )); then
    render_thread_screen
    print -n "send anyway as a reply to #${reply_to}? [y/N/e] "
    local verdict
    read -k 1 verdict
    print
    case "$verdict" in
      y|Y) : ;;
      e|E) start_reply; return ;;
      *) tput civis 2>/dev/null; return 0 ;;
    esac
  fi

  local wire payload
  wire=$(seal_message_zsh "$text" "$ENC_KEY" "$MAC_KEY" "work" "" "$reply_to" 0)
  payload=$(BODY="$wire" /usr/bin/python3 -c 'import os, json; print(json.dumps({"body": os.environ["BODY"]}))')
  _gh_post "/repos/${RELAY_MAILBOX_REPO}/issues/${CURRENT_ISSUE}/comments" "$payload"
  fetch_comments "$CURRENT_ISSUE"
  LATEST_SEQ=$(_thread_latest_seq)
  NEW_IN_THREAD=0
  print -r -- "sent"
  tput civis 2>/dev/null
}

refresh_view() {
  case "$VIEW" in
    thread)
      local before=${#COMMENTS[@]}
      fetch_comments "$CURRENT_ISSUE"
      local after=${#COMMENTS[@]}
      if (( after != before )); then
        NEW_IN_THREAD=1
      else
        LATEST_SEQ=$(_thread_latest_seq)
        NEW_IN_THREAD=0
      fi
      ;;
    *)
      fetch_issues
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Unlock and main loop
# ---------------------------------------------------------------------------

unlock_client() {
  local pass words
  read -s "pass?Passphrase: "
  print
  read -s "words?Three words: "
  print
  DAY_KEY=$(derive_day_key_zsh "$pass" "$words" "$RELAY_SALT_HEX") || return 1
  ENC_KEY=$(derive_enc_key "$DAY_KEY") || return 1
  MAC_KEY=$(derive_mac_key "$DAY_KEY") || return 1
  local sealed_wire
  sealed_wire=$(_b64d "$SEALED_MAILBOX_TOKEN") || return 1
  RELAY_TOKEN=$(open_message_zsh "$sealed_wire" "$ENC_KEY" "$MAC_KEY") || return 1
  [[ -n "$RELAY_TOKEN" ]] || return 1
  return 0
}

cleanup_terminal() {
  tput rmcup 2>/dev/null
  stty echo 2>/dev/null
}

main() {
  trap cleanup_terminal EXIT INT
  if ! unlock_client; then
    print -u2 "Can't unlock: check your passphrase and today's words."
    return 1
  fi

  tput smcup 2>/dev/null
  tput civis 2>/dev/null
  stty -echo 2>/dev/null
  clear
  fetch_issues

  # Declare `key` ONCE, before the loop. A bare `local key` inside the loop
  # re-declares an already-set variable each iteration, and zsh prints
  # `key=<value>` when you do that — which leaked the last keypress onto the
  # screen. (This is a declaration echo, not terminal echo; `stty -echo` above
  # separately suppresses the raw keystroke from `read -k`.)
  local key
  while true; do
    clear
    case "$VIEW" in
      idle) render_idle_screen ;;
      list) render_list_screen ;;
      thread) render_thread_screen ;;
    esac

    if ! read -t $(( RELAY_REFRESH_MINUTES * 60 )) -k 1 key; then
      # Auto-refresh: idle/list rewrite; a thread only flips its top banner.
      refresh_view
      continue
    fi
    case "$key" in
      h)
        if [[ "$VIEW" == "idle" ]]; then VIEW="list"; else VIEW="idle"; fi
        ;;
      [1-9])
        if select_issue "$key"; then VIEW="thread"; fi
        ;;
      r)
        refresh_view
        ;;
      b)
        VIEW="list"
        ;;
      q)
        break
        ;;
      $'\e')
        # Esc cancels a reply in progress; outside a reply it is a no-op.
        ;;
      $'\t'|'^I')
        # Tab is explicitly ignored: a stray post-quit Tab must not trigger
        # terminal completion.
        ;;
      $'\n'|$'\r')
        [[ "$VIEW" == "thread" ]] && start_reply
        ;;
    esac
  done
  return 0
}

# In test mode only the helpers are defined; the interactive client is not run.
if [[ -z "$RELAY_TEST_MODE" ]]; then
  main "$@"
fi
