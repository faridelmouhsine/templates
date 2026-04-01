#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# CXOne AppSec Dashboard by Application Tag
# - Filters applications locally on tags.KEY == VALUE
# - Resolves project names
# - Finds latest SAST scan per project
# - Pulls findings and computes qualification effort
#
# Qualification scope:
#   IN SCOPE  : Critical + High
#   INFO ONLY : Medium
#
# Progress logic:
#   TODO = To Verify / Verify / Todo / New / Recurrent / Proposed
#   DONE = Confirmed / Not Exploitable
#
# Output files:
#   dashboard_<analyst>_<date>.json
#   dashboard_<analyst>_<date>.html
# ============================================================

CXONE_BASE_URL="${CXONE_BASE_URL:-}"
CXONE_TOKEN="${CXONE_TOKEN:-}"
OUTPUT_DIR="${OUTPUT_DIR:-.}"
PAGE_SIZE="${PAGE_SIZE:-500}"

TAG_KEY=""
TAG_VALUE=""

usage() {
  cat <<EOF
Usage:
  $0 --tag KEY:VALUE [--base-url URL] [--token TOKEN] [--out DIR]

Example:
  $0 --tag Analyst:Farid
EOF
}

log()  { printf '[INFO] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err()  { printf '[ERROR] %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing required command: $1"
    exit 1
  }
}

slugify() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9._-]/_/g' \
    | sed 's/__*/_/g' \
    | sed 's/^_//; s/_$//'
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        [[ $# -ge 2 ]] || { err "--tag requires KEY:VALUE"; exit 1; }
        TAG_KEY="${2%%:*}"
        TAG_VALUE="${2#*:}"
        [[ "$TAG_KEY" != "$TAG_VALUE" ]] || { err "Invalid tag format"; exit 1; }
        shift 2
        ;;
      --base-url)
        CXONE_BASE_URL="$2"; shift 2 ;;
      --token)
        CXONE_TOKEN="$2"; shift 2 ;;
      --out)
        OUTPUT_DIR="$2"; shift 2 ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        err "Unknown arg: $1"
        usage
        exit 1
        ;;
    esac
  done

  [[ -n "$TAG_KEY" ]] || { err "Missing --tag KEY:VALUE"; exit 1; }
  [[ -n "$CXONE_BASE_URL" ]] || { err "Missing CXONE_BASE_URL"; exit 1; }
  [[ -n "$CXONE_TOKEN" ]] || { err "Missing CXONE_TOKEN"; exit 1; }
}

api_get() {
  local path="$1"
  curl -sS --fail \
    -H "Authorization: Bearer $CXONE_TOKEN" \
    -H "Accept: application/json" \
    "${CXONE_BASE_URL%/}${path}"
}

fetch_all_applications() {
  api_get "/api/applications?limit=${PAGE_SIZE}"
}

fetch_project_details() {
  local project_id="$1"
  local endpoints=(
    "/api/projects/${project_id}"
    "/api/projects/${project_id}/details"
    "/api/projects?ids=${project_id}"
  )
  local tmp
  tmp="$(mktemp)"
  for ep in "${endpoints[@]}"; do
    if api_get "$ep" >"$tmp" 2>/dev/null; then
      cat "$tmp"
      rm -f "$tmp"
      return 0
    fi
  done
  rm -f "$tmp"
  return 1
}

fetch_project_scans() {
  local project_id="$1"
  local endpoints=(
    "/api/scans?project-id=${project_id}&limit=100"
    "/api/scans?projectId=${project_id}&limit=100"
    "/api/projects/${project_id}/scans?limit=100"
  )
  local tmp
  tmp="$(mktemp)"
  for ep in "${endpoints[@]}"; do
    if api_get "$ep" >"$tmp" 2>/dev/null; then
      cat "$tmp"
      rm -f "$tmp"
      return 0
    fi
  done
  rm -f "$tmp"
  return 1
}

fetch_scan_results() {
  local scan_id="$1"
  local endpoints=(
    "/api/sast-results?scan-id=${scan_id}&limit=10000"
    "/api/sast-results?scanId=${scan_id}&limit=10000"
    "/api/scans/${scan_id}/results?limit=10000"
    "/api/scans/${scan_id}/findings?limit=10000"
    "/api/results?scan-id=${scan_id}&limit=10000"
    "/api/results?scanId=${scan_id}&limit=10000"
  )
  local tmp
  tmp="$(mktemp)"
  for ep in "${endpoints[@]}"; do
    if api_get "$ep" >"$tmp" 2>/dev/null; then
      cat "$tmp"
      rm -f "$tmp"
      return 0
    fi
  done
  rm -f "$tmp"
  return 1
}

normalize_scans_array() {
  jq '
    if .scans then .scans
    elif .items then .items
    elif .data then .data
    elif type=="array" then .
    else []
    end
  '
}

normalize_results_array() {
  jq '
    if .results then .results
    elif .findings then .findings
    elif .items then .items
    elif .data then .data
    elif type=="array" then .
    else []
    end
  '
}

pick_project_name() {
  jq -r '
    .name
    // .projectName
    // .project.name
    // (if .projects and (.projects|length)>0 then (.projects[0].name // .projects[0].projectName // empty) else empty end)
    // empty
  ' 2>/dev/null
}

latest_sast_scan_from_payload() {
  normalize_scans_array | jq '
    map({
      id: (.id // .scanId // .scan_id // ""),
      createdAt: (.createdAt // .dateAndTime.startedOn // .startTime // .startedAt // ""),
      status: (.status // .state // .stage // "UNKNOWN"),
      engine: (.type // .scanType // .scanner // .origin // .engine // ""),
      raw: .
    })
    | map(
        select(
          (
            .engine
            | tostring
            | ascii_upcase
            | test("SAST")
          )
          or (
            (.raw | tostring | ascii_upcase) | test("\"NAME\":\"SAST\"|\"ENGINES\":\\[\"SAST\"")
          )
        )
      )
    | sort_by(.createdAt)
    | reverse
    | .[0] // null
  '
}

summarize_findings() {
  normalize_results_array | jq '
    def sev:
      (
        .severity
        // .severityName
        // .resultSeverity
        // .issueSeverity
        // .riskSeverity
        // ""
      ) | tostring | ascii_upcase;

    def st:
      (
        .state
        // .status
        // .resultState
        // .workflowStatus
        // .triageStatus
        // ""
      ) | tostring | ascii_upcase;

    def is_critical: sev == "CRITICAL";
    def is_high: sev == "HIGH";
    def is_medium: sev == "MEDIUM";

    def is_todo_state:
      (
        st == "TO_VERIFY"
        or st == "TO VERIFY"
        or st == "VERIFY"
        or st == "TODO"
        or st == "TO DO"
        or st == "NEW"
        or st == "RECURRENT"
        or st == "PROPOSED_NOT_EXPLOITABLE"
        or st == "PROPOSED_NOT EXPLOITABLE"
        or st == "PROPOSED CONFIRMED"
        or st == "URGENT"
        or st == ""
      );

    def is_done_state:
      (
        st == "CONFIRMED"
        or st == "NOT_EXPLOITABLE"
        or st == "NOT EXPLOITABLE"
      );

    {
      totalCritical: (map(select(is_critical)) | length),
      totalHigh:     (map(select(is_high)) | length),
      totalMedium:   (map(select(is_medium)) | length),

      todoCritical:  (map(select(is_critical and is_todo_state)) | length),
      todoHigh:      (map(select(is_high and is_todo_state)) | length),
      todoMedium:    (map(select(is_medium and is_todo_state)) | length),

      doneCritical:  (map(select(is_critical and is_done_state)) | length),
      doneHigh:      (map(select(is_high and is_done_state)) | length),
      doneMedium:    (map(select(is_medium and is_done_state)) | length)
    }
    | .totalTodo = (.todoCritical + .todoHigh)
    | .totalDone = (.doneCritical + .doneHigh)
    | .totalTarget = (.totalCritical + .totalHigh)
    | .progressPct = (
        if .totalTarget > 0
        then ((.totalDone * 100 / .totalTarget) * 100 | round / 100)
        else 0
        end
      )
  '
}

build_dashboard() {
  local apps_raw apps_filtered result
  apps_raw="$(mktemp)"
  apps_filtered="$(mktemp)"
  result="$(mktemp)"

  log "Fetching all applications"
  fetch_all_applications > "$apps_raw"

  log "Filtering locally on tags.${TAG_KEY} == ${TAG_VALUE}"
  jq \
    --arg k "$TAG_KEY" \
    --arg v "$TAG_VALUE" '
    .applications
    | map(select((.tags[$k] // "") == $v))
    | map({
        applicationId: .id,
        applicationName: .name,
        tags: (.tags // {}),
        projectIds: (.projectIds // [])
      })
  ' "$apps_raw" > "$apps_filtered"

  local app_count
  app_count="$(jq 'length' "$apps_filtered")"
  log "Applications matched: $app_count"

  printf '[]' > "$result"

  for ((i=0; i<app_count; i++)); do
    local app app_id app_name project_count app_json
    app="$(jq -c ".[$i]" "$apps_filtered")"
    app_id="$(jq -r '.applicationId' <<<"$app")"
    app_name="$(jq -r '.applicationName' <<<"$app")"
    project_count="$(jq '.projectIds | length' <<<"$app")"

    log "Processing application: $app_name ($project_count projects)"

    app_json="$(jq -n \
      --arg id "$app_id" \
      --arg name "$app_name" \
      '{
        applicationId: $id,
        applicationName: $name,
        totalProjects: 0,
        totalCritical: 0,
        totalHigh: 0,
        totalMedium: 0,
        todoCritical: 0,
        todoHigh: 0,
        todoMedium: 0,
        doneCritical: 0,
        doneHigh: 0,
        doneMedium: 0,
        totalTodo: 0,
        totalDone: 0,
        totalTarget: 0,
        progressPct: 0,
        projects: []
      }'
    )"

    for ((j=0; j<project_count; j++)); do
      local project_id project_name project_details_raw scans_raw latest_sast scan_id results_raw metrics
      project_id="$(jq -r ".projectIds[$j]" <<<"$app")"
      project_name="$project_id"

      project_details_raw="$(mktemp)"
      if fetch_project_details "$project_id" > "$project_details_raw" 2>/dev/null; then
        local maybe_name
        maybe_name="$(pick_project_name < "$project_details_raw" || true)"
        [[ -n "${maybe_name:-}" ]] && project_name="$maybe_name"
      fi
      rm -f "$project_details_raw"

      scans_raw="$(mktemp)"
      latest_sast='null'
      if fetch_project_scans "$project_id" > "$scans_raw" 2>/dev/null; then
        latest_sast="$(latest_sast_scan_from_payload < "$scans_raw")"
      fi
      rm -f "$scans_raw"

      scan_id="$(jq -r '.id // empty' <<<"$latest_sast")"

      if [[ -n "${scan_id:-}" ]]; then
        results_raw="$(mktemp)"
        if fetch_scan_results "$scan_id" > "$results_raw" 2>/dev/null; then
          metrics="$(summarize_findings < "$results_raw")"
        else
          metrics='{"totalCritical":0,"totalHigh":0,"totalMedium":0,"todoCritical":0,"todoHigh":0,"todoMedium":0,"doneCritical":0,"doneHigh":0,"doneMedium":0,"totalTodo":0,"totalDone":0,"totalTarget":0,"progressPct":0}'
        fi
        rm -f "$results_raw"
      else
        metrics='{"totalCritical":0,"totalHigh":0,"totalMedium":0,"todoCritical":0,"todoHigh":0,"todoMedium":0,"doneCritical":0,"doneHigh":0,"doneMedium":0,"totalTodo":0,"totalDone":0,"totalTarget":0,"progressPct":0}'
      fi

      app_json="$(
        jq \
          --arg pid "$project_id" \
          --arg pname "$project_name" \
          --argjson latest "$latest_sast" \
          --argjson m "$metrics" '
          .projects += [{
            projectId: $pid,
            projectName: $pname,
            latestSastScan: $latest,
            totalCritical: $m.totalCritical,
            totalHigh: $m.totalHigh,
            totalMedium: $m.totalMedium,
            todoCritical: $m.todoCritical,
            todoHigh: $m.todoHigh,
            todoMedium: $m.todoMedium,
            doneCritical: $m.doneCritical,
            doneHigh: $m.doneHigh,
            doneMedium: $m.doneMedium,
            totalTodo: $m.totalTodo,
            totalDone: $m.totalDone,
            totalTarget: $m.totalTarget,
            progressPct: $m.progressPct
          }]
          | .totalProjects += 1
          | .totalCritical += $m.totalCritical
          | .totalHigh += $m.totalHigh
          | .totalMedium += $m.totalMedium
          | .todoCritical += $m.todoCritical
          | .todoHigh += $m.todoHigh
          | .todoMedium += $m.todoMedium
          | .doneCritical += $m.doneCritical
          | .doneHigh += $m.doneHigh
          | .doneMedium += $m.doneMedium
          | .totalTodo += $m.totalTodo
          | .totalDone += $m.totalDone
          | .totalTarget += $m.totalTarget
          | .progressPct = (
              if .totalTarget > 0
              then ((.totalDone * 100 / .totalTarget) * 100 | round / 100)
              else 0
              end
            )
        ' <<<"$app_json"
      )"
    done

    jq --argjson app "$app_json" '. + [$app]' "$result" > "${result}.new"
    mv "${result}.new" "$result"
  done

  jq \
    --arg generatedAt "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg tag "${TAG_KEY}:${TAG_VALUE}" '
    {
      generatedAt: $generatedAt,
      filters: {
        tag: $tag,
        scanner: "SAST",
        qualificationScope: ["CRITICAL","HIGH"],
        informationalOnly: ["MEDIUM"],
        todoStates: ["TO VERIFY","VERIFY","TODO","NEW","RECURRENT"],
        doneStates: ["CONFIRMED","NOT EXPLOITABLE"]
      },
      summary: {
        totalApplications: length,
        totalProjects: (map(.totalProjects) | add // 0),
        totalCritical: (map(.totalCritical) | add // 0),
        totalHigh: (map(.totalHigh) | add // 0),
        totalMedium: (map(.totalMedium) | add // 0),
        totalTodo: (map(.totalTodo) | add // 0),
        totalDone: (map(.totalDone) | add // 0),
        totalTarget: (map(.totalTarget) | add // 0),
        progressPct: (
          ((map(.totalTarget) | add // 0)) as $target
          | ((map(.totalDone) | add // 0)) as $done
          | if $target > 0
            then (($done * 100 / $target) * 100 | round / 100)
            else 0
            end
        )
      },
      applications: (sort_by(.progressPct, .totalDone, .totalTodo, .totalHigh, .totalCritical) | reverse)
    }
  ' "$result"

  rm -f "$apps_raw" "$apps_filtered" "$result"
}

render_terminal() {
  local json_file="$1"

  echo
  echo "======================================================================"
  echo "                 CXONE SAST QUALIFICATION DASHBOARD"
  echo "======================================================================"
  echo "Generated at : $(jq -r '.generatedAt' "$json_file")"
  echo "Tag filter   : $(jq -r '.filters.tag' "$json_file")"
  echo "Scope        : Critical + High"
  echo "Applications : $(jq -r '.summary.totalApplications' "$json_file")"
  echo "Projects     : $(jq -r '.summary.totalProjects' "$json_file")"
  echo "Critical     : $(jq -r '.summary.totalCritical' "$json_file")"
  echo "High         : $(jq -r '.summary.totalHigh' "$json_file")"
  echo "Medium(info) : $(jq -r '.summary.totalMedium' "$json_file")"
  echo "Todo         : $(jq -r '.summary.totalTodo' "$json_file")"
  echo "Done         : $(jq -r '.summary.totalDone' "$json_file")"
  echo "Progress     : $(jq -r '.summary.progressPct' "$json_file")%"
  echo "======================================================================"
  echo
}

render_html() {
  local json_file="$1"
  local html_file="$2"
  local payload
  payload="$(cat "$json_file")"

  cat > "$html_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CXOne AppSec Qualification Dashboard</title>
  <style>
    :root{
      --axa-blue:#103184;
      --axa-blue-2:#0d2a70;
      --axa-red:#ee0000;
      --bg:#f4f7fb;
      --card:#ffffff;
      --ink:#172033;
      --muted:#667085;
      --line:#d9e2f1;
      --todo:#f59e0b;
      --done:#16a34a;
      --critical:#b91c1c;
      --high:#ea580c;
      --medium:#2563eb;
      --shadow:0 10px 30px rgba(16,49,132,.10);
      --radius:18px;
    }

    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:Arial, sans-serif;
      background:linear-gradient(180deg,#edf3ff 0%, #f8fbff 220px, var(--bg) 220px);
      color:var(--ink);
    }

    .shell{
      max-width:1500px;
      margin:0 auto;
      padding:24px;
    }

    .hero{
      background:linear-gradient(135deg,var(--axa-blue) 0%, var(--axa-blue-2) 70%, #0b1f52 100%);
      color:#fff;
      border-radius:24px;
      padding:28px;
      box-shadow:var(--shadow);
      margin-bottom:24px;
      position:relative;
      overflow:hidden;
    }

    .hero:after{
      content:"";
      position:absolute;
      right:-80px;
      top:-80px;
      width:240px;
      height:240px;
      border-radius:50%;
      background:rgba(255,255,255,.06);
    }

    .hero h1{
      margin:0 0 10px 0;
      font-size:32px;
      line-height:1.1;
    }

    .hero-sub{
      opacity:.92;
      font-size:14px;
      line-height:1.6;
      max-width:980px;
    }

    .hero-tags{
      margin-top:16px;
      display:flex;
      flex-wrap:wrap;
      gap:10px;
    }

    .hero-tag{
      background:rgba(255,255,255,.12);
      border:1px solid rgba(255,255,255,.15);
      color:#fff;
      border-radius:999px;
      padding:8px 12px;
      font-size:12px;
    }

    .top{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
      gap:16px;
      margin-bottom:26px;
    }

    .card{
      background:var(--card);
      border:1px solid var(--line);
      border-radius:var(--radius);
      padding:18px;
      box-shadow:var(--shadow);
    }

    .metric-title{
      font-size:13px;
      color:var(--muted);
      margin-bottom:8px;
      font-weight:700;
      text-transform:uppercase;
      letter-spacing:.04em;
    }

    .metric{
      font-size:34px;
      font-weight:800;
      line-height:1;
      color:var(--axa-blue);
    }

    .metric-sub{
      color:var(--muted);
      font-size:12px;
      margin-top:8px;
      line-height:1.45;
    }

    .done-number{ color:var(--done); }
    .todo-number{ color:var(--todo); }
    .critical-number{ color:var(--critical); }
    .high-number{ color:var(--high); }
    .medium-number{ color:var(--medium); }

    .section-title{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin:26px 0 14px;
    }

    .section-title h2{
      margin:0;
      font-size:22px;
      color:var(--axa-blue);
    }

    .hint{
      color:var(--muted);
      font-size:13px;
    }

    .app{
      background:var(--card);
      border:1px solid var(--line);
      border-radius:20px;
      box-shadow:var(--shadow);
      margin-bottom:18px;
      overflow:hidden;
    }

    .app-header{
      padding:18px 20px;
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:16px;
      cursor:pointer;
      background:linear-gradient(180deg,#ffffff 0%, #f8fbff 100%);
    }

    .app-left{
      flex:1;
      min-width:320px;
    }

    .app-title-row{
      display:flex;
      align-items:center;
      gap:12px;
      flex-wrap:wrap;
    }

    .app-title{
      font-size:20px;
      font-weight:800;
      color:var(--axa-blue);
    }

    .collapse-icon{
      width:30px;
      height:30px;
      border-radius:50%;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      background:#eef4ff;
      color:var(--axa-blue);
      font-weight:800;
      flex-shrink:0;
      transition:transform .2s ease;
    }

    .app.collapsed .collapse-icon{
      transform:rotate(-90deg);
    }

    .summary-row{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      margin-top:10px;
    }

    .pill{
      border-radius:999px;
      padding:7px 11px;
      font-size:12px;
      font-weight:700;
      border:1px solid var(--line);
      background:#fff;
      color:var(--ink);
    }

    .pill.todo{
      background:rgba(245,158,11,.10);
      border-color:rgba(245,158,11,.30);
      color:#9a6700;
    }

    .pill.done{
      background:rgba(22,163,74,.10);
      border-color:rgba(22,163,74,.28);
      color:#0f7a34;
    }

    .pill.critical{
      background:rgba(185,28,28,.08);
      border-color:rgba(185,28,28,.22);
      color:#9b1c1c;
    }

    .pill.high{
      background:rgba(234,88,12,.08);
      border-color:rgba(234,88,12,.22);
      color:#b45309;
    }

    .pill.medium{
      background:rgba(37,99,235,.08);
      border-color:rgba(37,99,235,.22);
      color:#1d4ed8;
    }

    .app-right{
      min-width:240px;
      text-align:right;
    }

    .progress-line{
      display:flex;
      justify-content:flex-end;
      align-items:center;
      gap:10px;
      margin-bottom:8px;
    }

    .progress-value{
      font-size:28px;
      font-weight:800;
      color:var(--axa-blue);
    }

    .progress-value.full{
      color:var(--done);
    }

    .bar-wrap{
      width:240px;
      height:12px;
      background:#edf2fa;
      border-radius:999px;
      overflow:hidden;
      border:1px solid #dce6f7;
      margin-left:auto;
    }

    .bar{
      height:100%;
      background:linear-gradient(90deg,var(--todo) 0%, #fbbf24 100%);
      transition:width .3s ease;
    }

    .bar.full{
      background:linear-gradient(90deg,var(--done) 0%, #22c55e 100%);
    }

    .projects{
      padding:0 20px 18px 20px;
      display:block;
    }

    .app.collapsed .projects{
      display:none;
    }

    .project{
      background:#fbfdff;
      border:1px solid #e6edf8;
      border-radius:16px;
      padding:16px;
      margin-top:12px;
      display:flex;
      justify-content:space-between;
      gap:18px;
      flex-wrap:wrap;
    }

    .project-main{
      flex:1;
      min-width:320px;
    }

    .project-name{
      font-size:16px;
      font-weight:800;
      color:#17356d;
      margin-bottom:6px;
    }

    .muted{
      color:var(--muted);
      font-size:13px;
      line-height:1.5;
    }

    .project-side{
      min-width:320px;
    }

    .mini-bar-wrap{
      width:180px;
      height:10px;
      background:#edf2fa;
      border-radius:999px;
      overflow:hidden;
      border:1px solid #dce6f7;
    }

    .mini-bar{
      height:100%;
      background:linear-gradient(90deg,var(--todo) 0%, #fbbf24 100%);
    }

    .mini-bar.full{
      background:linear-gradient(90deg,var(--done) 0%, #22c55e 100%);
    }

    .project-progress{
      display:flex;
      align-items:center;
      gap:10px;
      margin-top:12px;
    }

    .project-progress-value{
      font-size:13px;
      font-weight:800;
      color:var(--axa-blue);
    }

    .project-progress-value.full{
      color:var(--done);
    }

    .toolbar{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
    }

    .toolbar button{
      border:none;
      background:var(--axa-blue);
      color:#fff;
      border-radius:999px;
      padding:10px 14px;
      font-weight:700;
      cursor:pointer;
      box-shadow:var(--shadow);
    }

    .toolbar button.secondary{
      background:#fff;
      color:var(--axa-blue);
      border:1px solid var(--line);
    }

    @media (max-width:900px){
      .app-right{
        text-align:left;
        min-width:100%;
      }
      .bar-wrap{
        margin-left:0;
      }
      .progress-line{
        justify-content:flex-start;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <h1>CXOne SAST Qualification Dashboard</h1>
      <div class="hero-sub" id="sub"></div>
      <div class="hero-tags">
        <div class="hero-tag" id="heroTagFilter"></div>
        <div class="hero-tag">Qualification scope: Critical + High</div>
        <div class="hero-tag">Medium shown as informational only</div>
      </div>
    </div>

    <div class="top">
      <div class="card">
        <div class="metric-title">Applications</div>
        <div class="metric" id="appsCount"></div>
        <div class="metric-sub">Applications assigned to the selected analyst.</div>
      </div>

      <div class="card">
        <div class="metric-title">Projects</div>
        <div class="metric" id="projectsCount"></div>
        <div class="metric-sub">Projects attached to the selected applications.</div>
      </div>

      <div class="card">
        <div class="metric-title">Critical / High</div>
        <div class="metric"><span class="critical-number" id="criticalCount"></span> / <span class="high-number" id="highCount"></span></div>
        <div class="metric-sub">In-scope vulnerabilities used for qualification progress.</div>
      </div>

      <div class="card">
        <div class="metric-title">Medium</div>
        <div class="metric medium-number" id="mediumCount"></div>
        <div class="metric-sub">Visible for awareness, excluded from effort and progress.</div>
      </div>

      <div class="card">
        <div class="metric-title">Todo</div>
        <div class="metric todo-number" id="todoCount"></div>
        <div class="metric-sub">Critical + High still pending qualification.</div>
      </div>

      <div class="card">
        <div class="metric-title">Done</div>
        <div class="metric done-number" id="doneCount"></div>
        <div class="metric-sub">Confirmed + Not Exploitable on Critical + High.</div>
      </div>

      <div class="card">
        <div class="metric-title">Overall Progress</div>
        <div class="metric" id="progressPct"></div>
        <div class="bar-wrap" style="margin-top:12px;"><div class="bar" id="globalBar"></div></div>
        <div class="metric-sub">Progress is based only on Critical + High.</div>
      </div>
    </div>

    <div class="section-title">
      <h2>Applications</h2>
      <div class="toolbar">
        <button onclick="expandAll()">Expand all</button>
        <button class="secondary" onclick="collapseAll()">Collapse all</button>
      </div>
    </div>

    <div class="hint">Applications can be expanded or collapsed to show or hide projects.</div>
    <div id="apps" style="margin-top:12px;"></div>
  </div>

  <script>
    const data = $payload;

    function pctClass(v){
      return Number(v) >= 100 ? "full" : "";
    }

    function esc(s){
      return String(s ?? "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;");
    }

    document.getElementById("sub").textContent =
      "Generated on " + data.generatedAt +
      " for " + data.filters.tag +
      ". This view tracks qualification effort on SAST Critical and High findings only.";

    document.getElementById("heroTagFilter").textContent = "Filter: " + data.filters.tag;

    document.getElementById("appsCount").textContent = data.summary.totalApplications;
    document.getElementById("projectsCount").textContent = data.summary.totalProjects;
    document.getElementById("criticalCount").textContent = data.summary.totalCritical;
    document.getElementById("highCount").textContent = data.summary.totalHigh;
    document.getElementById("mediumCount").textContent = data.summary.totalMedium;
    document.getElementById("todoCount").textContent = data.summary.totalTodo;
    document.getElementById("doneCount").textContent = data.summary.totalDone;
    document.getElementById("progressPct").textContent = data.summary.progressPct + "%";

    const globalBar = document.getElementById("globalBar");
    globalBar.style.width = data.summary.progressPct + "%";
    if (Number(data.summary.progressPct) >= 100) globalBar.classList.add("full");

    const appsDiv = document.getElementById("apps");

    function toggleApp(id){
      const el = document.getElementById(id);
      if (el) el.classList.toggle("collapsed");
    }

    function expandAll(){
      document.querySelectorAll(".app").forEach(el => el.classList.remove("collapsed"));
    }

    function collapseAll(){
      document.querySelectorAll(".app").forEach(el => el.classList.add("collapsed"));
    }

    window.expandAll = expandAll;
    window.collapseAll = collapseAll;

    data.applications.forEach((app, idx) => {
      const appId = "app_" + idx;
      const appEl = document.createElement("div");
      appEl.className = "app";
      appEl.id = appId;

      const progressClass = pctClass(app.progressPct);
      const sortedProjects = [...app.projects].sort((a,b) =>
        (b.totalTodo - a.totalTodo) ||
        (b.totalHigh - a.totalHigh) ||
        (b.totalCritical - a.totalCritical)
      );

      const header = document.createElement("div");
      header.className = "app-header";
      header.onclick = () => toggleApp(appId);
      header.innerHTML = \`
        <div class="app-left">
          <div class="app-title-row">
            <div class="collapse-icon">⌄</div>
            <div class="app-title">\${esc(app.applicationName)}</div>
          </div>
          <div class="summary-row">
            <span class="pill">\${app.totalProjects} projects</span>
            <span class="pill critical">Critical: \${app.totalCritical}</span>
            <span class="pill high">High: \${app.totalHigh}</span>
            <span class="pill medium">Medium(info): \${app.totalMedium}</span>
            <span class="pill todo">Todo: \${app.totalTodo}</span>
            <span class="pill done">Done: \${app.totalDone}</span>
          </div>
        </div>
        <div class="app-right">
          <div class="progress-line">
            <div class="progress-value \${progressClass}">\${app.progressPct}%</div>
          </div>
          <div class="bar-wrap"><div class="bar \${progressClass}" style="width:\${app.progressPct}%"></div></div>
        </div>
      \`;

      const projects = document.createElement("div");
      projects.className = "projects";

      sortedProjects.forEach(p => {
        const latestDate =
          p.latestSastScan && (p.latestSastScan.createdAt || p.latestSastScan.startTime || p.latestSastScan.startedAt)
            ? (p.latestSastScan.createdAt || p.latestSastScan.startTime || p.latestSastScan.startedAt)
            : "-";

        const scanStatus =
          p.latestSastScan && p.latestSastScan.status
            ? p.latestSastScan.status
            : "Unknown";

        const projectProgressClass = pctClass(p.progressPct);

        const row = document.createElement("div");
        row.className = "project";
        row.innerHTML = \`
          <div class="project-main">
            <div class="project-name">\${esc(p.projectName)}</div>
            <div class="muted">Project ID: \${esc(p.projectId)}</div>
            <div class="muted">Latest SAST scan: \${esc(latestDate)} | Status: \${esc(scanStatus)}</div>
          </div>
          <div class="project-side">
            <div class="summary-row">
              <span class="badge" style="color:var(--critical); background:rgba(185,28,28,.08); border:1px solid rgba(185,28,28,.18);">Critical: \${p.totalCritical}</span>
              <span class="badge" style="color:var(--high); background:rgba(234,88,12,.08); border:1px solid rgba(234,88,12,.18);">High: \${p.totalHigh}</span>
              <span class="badge" style="color:var(--medium); background:rgba(37,99,235,.08); border:1px solid rgba(37,99,235,.18);">Medium(info): \${p.totalMedium}</span>
              <span class="badge" style="color:#9a6700; background:rgba(245,158,11,.10); border:1px solid rgba(245,158,11,.22);">Todo: \${p.totalTodo}</span>
              <span class="badge" style="color:#0f7a34; background:rgba(22,163,74,.10); border:1px solid rgba(22,163,74,.22);">Done: \${p.totalDone}</span>
            </div>
            <div class="project-progress">
              <div class="mini-bar-wrap"><div class="mini-bar \${projectProgressClass}" style="width:\${p.progressPct}%"></div></div>
              <div class="project-progress-value \${projectProgressClass}">\${p.progressPct}%</div>
            </div>
          </div>
        \`;
        projects.appendChild(row);
      });

      appEl.appendChild(header);
      appEl.appendChild(projects);
      appsDiv.appendChild(appEl);
    });
  </script>
</body>
</html>
EOF
}

main() {
  require_cmd curl
  require_cmd jq
  parse_args "$@"
  mkdir -p "$OUTPUT_DIR"

  local analyst_slug report_date base_name json_out html_out
  analyst_slug="$(slugify "$TAG_VALUE")"
  report_date="$(date +%F)"
  base_name="dashboard_${analyst_slug}_${report_date}"

  json_out="$OUTPUT_DIR/${base_name}.json"
  html_out="$OUTPUT_DIR/${base_name}.html"

  build_dashboard > "$json_out"
  render_terminal "$json_out"
  render_html "$json_out" "$html_out"

  echo
  echo "Files generated:"
  echo "  - $json_out"
  echo "  - $html_out"
}

main "$@"
