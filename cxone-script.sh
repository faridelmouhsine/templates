#!/usr/bin/env bash
set -euo pipefail

CXONE_BASE_URL="${CXONE_BASE_URL:-}"
CXONE_TOKEN="${CXONE_TOKEN:-}"
OUTPUT_DIR="${OUTPUT_DIR:-.}"
PAGE_SIZE="${PAGE_SIZE:-500}"

TAG_KEY=""
TAG_VALUE=""

log(){ printf '[INFO] %s\n' "$*" >&2; }
err(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }

slugify(){
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g'
}

require_cmd(){ command -v "$1" >/dev/null || err "Missing $1"; }

parse_args(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        TAG_KEY="${2%%:*}"
        TAG_VALUE="${2#*:}"
        shift 2;;
      *) shift;;
    esac
  done
}

api_get(){
  curl -sS --fail \
    --connect-timeout 10 --max-time 60 --retry 2 \
    -H "Authorization: Bearer $CXONE_TOKEN" \
    "$CXONE_BASE_URL$1"
}

build_dashboard(){

  apps=$(mktemp)
  filtered=$(mktemp)
  result=$(mktemp)

  api_get "/api/applications?limit=$PAGE_SIZE" > "$apps"

  jq --arg k "$TAG_KEY" --arg v "$TAG_VALUE" '
    .applications
    | map(select(.tags[$k]==$v))
  ' "$apps" > "$filtered"

  echo "[]" > "$result"

  count=$(jq length "$filtered")

  for ((i=0;i<count;i++)); do

    app=$(jq -c ".[$i]" "$filtered")
    name=$(jq -r '.name' <<<"$app")
    ids=$(jq -r '.projectIds[]?' <<<"$app")

    app_tmp=$(mktemp)
    echo '{"name":"'"$name"'","projects":[]}' > "$app_tmp"

    for pid in $ids; do

      log "Processing $pid"

      scans=$(mktemp)
      api_get "/api/scans?projectId=$pid" > "$scans" || true

      scan_id=$(jq -r '
        (.scans // .items // [])
        | map(select(.type=="sast" and .status!="Failed"))
        | sort_by(.createdAt)
        | reverse
        | .[0].id // empty
      ' "$scans")

      [[ -z "$scan_id" ]] && continue

      res=$(mktemp)
      api_get "/api/scans/$scan_id/results" > "$res" || continue

      metrics=$(jq '
        .results // [] |
        map({
          sev:(.severity|ascii_upcase),
          st:(.state|ascii_upcase)
        }) |
        reduce .[] as $r (
          {c:0,h:0,todo:0,done:0};
          if $r.sev=="CRITICAL" then .c+=1
          elif $r.sev=="HIGH" then .h+=1
          else . end
          | if ($r.st|test("VERIFY|NEW|TODO|RECURRENT")) then .todo+=1
            elif ($r.st|test("CONFIRMED|NOT_EXPLOITABLE")) then .done+=1
            else . end
        )
      ' "$res")

      tmp2=$(mktemp)

      jq --arg pid "$pid" --argjson m "$metrics" '
        .projects += [{
          id:$pid,
          critical:$m.c,
          high:$m.h,
          todo:$m.todo,
          done:$m.done
        }]
      ' "$app_tmp" > "$tmp2"

      mv "$tmp2" "$app_tmp"

    done

    tmp3=$(mktemp)
    jq -s '.[0]+[.[1]]' "$result" "$app_tmp" > "$tmp3"
    mv "$tmp3" "$result"

  done

  echo "$result"
}

render_html(){

  json_file="$1"
  html_file="$2"
  js_file="${json_file%.json}.js"

  cp "$json_file" "$OUTPUT_DIR/$(basename "$json_file")"

  echo "window.DATA = $(cat "$json_file");" > "$js_file"

  cat > "$html_file" <<EOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body{font-family:Arial;background:#f4f7fb}
.app{border:1px solid #ddd;margin:10px;padding:10px;border-radius:10px}
.todo{color:orange}
.done{color:green}
.bar{height:10px;background:orange}
.full{background:green}
</style>
</head>
<body>

<h1>Dashboard</h1>
<div id="apps"></div>

<script src="$(basename "$js_file")"></script>
<script>

const root=document.getElementById("apps")

DATA.forEach(app=>{
  const div=document.createElement("div")
  div.className="app"

  let html="<h2>"+app.name+"</h2>"

  app.projects.forEach(p=>{
    const total=p.critical+p.high
    const pct= total? Math.round(p.done*100/total):0

    html+=\`
      <div>
        <b>\${p.id}</b> -
        <span class="todo">Todo:\${p.todo}</span>
        <span class="done">Done:\${p.done}</span>
        <div class="bar \${pct==100?'full':''}" style="width:\${pct}%"></div>
      </div>
    \`
  })

  div.innerHTML=html
  root.appendChild(div)
})

</script>

</body>
</html>
EOF
}

main(){
  require_cmd jq
  require_cmd curl

  parse_args "$@"

  slug=$(slugify "$TAG_VALUE")
  date=$(date +%F)

  json="$OUTPUT_DIR/dashboard_${slug}_${date}.json"
  html="$OUTPUT_DIR/dashboard_${slug}_${date}.html"

  tmp=$(build_dashboard)

  cp "$tmp" "$json"

  render_html "$json" "$html"

  echo "Generated:"
  echo "$json"
  echo "$html"
}

main "$@"
