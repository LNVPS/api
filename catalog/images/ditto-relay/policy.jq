def csv: if . == "" then [] else split(",") end;
def has_elem($x): any(.[]; . == $x);
def nibble_bits: if . == 0 then 4 elif . < 2 then 3 elif . < 4 then 2 elif . < 8 then 1 else 0 end;
def pow_bits:
  explode
  | map(if . < 58 then . - 48 else . - 87 end)
  | reduce .[] as $n ({bits: 0, stop: false};
      if .stop then .
      else ($n | nibble_bits) as $b | .bits += $b | .stop = ($b < 4)
      end)
  | .bits;
def reject($msg): {action: "reject", msg: $msg};
def accept: {action: "accept", msg: ""};

$policy[0] as $p
| (($p.kinds // "") | csv | map(tonumber? // -1)) as $kinds
| (($p.allow // "") | csv) as $allow
| (($p.deny // "") | csv) as $deny
| ($p.min_pow | tonumber? // 0) as $min_pow
| ($p.max_size | tonumber? // 0) as $max_size
| ($p.per_minute | tonumber? // 0) as $limit
| ($p.require_auth == "true") as $need_auth
| def judge($in):
    $in.event as $e
    | if $need_auth and ($in.authed == null) then reject("auth-required: this relay requires authentication to write")
      elif ($allow | length) > 0 and (($allow | has_elem($e.pubkey)) | not) then reject("blocked: this pubkey may not write here")
      elif $deny | has_elem($e.pubkey) then reject("blocked: this pubkey is blocked")
      elif ($kinds | length) > 0 and (($kinds | has_elem($e.kind)) | not) then reject("blocked: kind \($e.kind) is not accepted")
      elif $max_size > 0 and ($e | tojson | utf8bytelength) > $max_size then reject("blocked: event is larger than \($max_size) bytes")
      elif $min_pow > 0 and (($e.id | pow_bits) < $min_pow) then reject("pow: difficulty is below \($min_pow) bits")
      else accept
      end;
  foreach inputs as $in ({hits: {}, out: null};
    $in.receivedAt as $now
    | "\($in.sourceType):\($in.sourceInfo)" as $who
    | judge($in) as $v
    | if $v.action == "accept" and $limit > 0 then
        (.hits[$who] // [] | map(select(. > $now - 60))) as $recent
        | if ($recent | length) >= $limit then
            .out = reject("rate-limited: too many events from this address") | .hits[$who] = $recent
          else
            .out = $v | .hits[$who] = $recent + [$now]
          end
      else
        .out = $v
      end
    | .out += {id: $in.event.id}
    | if (.hits | length) > 4096 then .hits |= with_entries(select(.value | any(. > $now - 60))) else . end;
    .out)
