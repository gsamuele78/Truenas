#!/usr/bin/env bash
#
# SCRIPT: create_ad_homedirs.sh
# AUTHOR: GitHub Copilot & User Collaboration
# DATE: 2025-09-06
# REV: 3.3.1 (Definitive & Syntax Corrected)
# PLATFORM: TrueNAS SCALE 25.04 and later
#
# PURPOSE:
# This script automates the creation of home directories for Active Directory (AD)
# users on a TrueNAS SCALE system.
#
# FEATURES:
# - Corrected critical syntax error that caused script to crash.
# - EXTENSIBLE EXCLUSION FILTERING: A new '--exclude-pattern' flag allows adding
#   custom regex patterns to skip specific non-user accounts.
# - AUTO-DETECT UID RANGE: Intelligently queries the TrueNAS idmap configuration
#   to automatically determine the correct UID range for AD users.
# - ADVANCED PER-USER CACHING: Each user's group memberships are cached individually.
# - All detailed functions and debug logging are present and correct.
#

set -euo pipefail
IFS=$'\n\t'

# --- Script metadata ---
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_VERSION="3.3.1"
readonly LOG_FILE="${LOG_FILE:-/var/log/${SCRIPT_NAME%.sh}.log}"
readonly SYSLOG_TAG="${SCRIPT_NAME%.sh}"

# --- Exit codes ---
readonly EXIT_SUCCESS=0; readonly EXIT_ERROR=1; readonly EXIT_INVALID_ARGS=2; readonly EXIT_MISSING_DEPS=3; readonly EXIT_AUTH_ERROR=4; readonly EXIT_STORAGE_ERROR=5

# --- Defaults ---
DOMAIN=""; AD_GROUP=""; DATASET_PATH=""; APPLY=0; DEBUG=0; FORCE_POSIX=0; QUIET=0; SKIP_BACKUP=0; MAX_RETRIES=3; TIMEOUT=30; FORCE_RESCAN=0
MIN_UID=1000
MAX_UID=2000000000

# --- Cache Settings ---
readonly CACHE_DIR="/var/tmp/create_ad_homedirs_cache"
readonly USER_CACHE_DIR="${CACHE_DIR}/users"
readonly CACHE_TTL_SECONDS=$((24 * 3600))

# --- Global state tracking ---
declare -a CREATED_DIRS=(); declare -a FAILED_USERS=(); declare -i TOTAL_PROCESSED=0; declare -i SUCCESS_COUNT=0
declare -A OPERATIONS=(); declare -a ROLLBACK_QUEUE=()
declare -a EXCLUDE_PATTERNS=()

# --- Operation status tracking ---
readonly OP_SUCCESS=0; readonly OP_FAILED=1; readonly OP_SKIPPED=2

# --- TrueNAS SCALE tool detection ---
HAS_NFS4XDR_SETFACL=0; HAS_NFS4_SETFACL=0; HAS_SETFACL=0; USE_NFSV4=0; ZFS_DATASET=""

# --- Logging functions ---
log() {
    local level="$1"; shift; local message="$*";
    local timestamp; timestamp=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
    if [[ ${QUIET} -eq 0 ]]; then echo "[${timestamp}] [${level}] ${message}" >&2; fi
    local log_dir; log_dir="$(dirname "${LOG_FILE}" 2>/dev/null)"
    if [[ -w "${log_dir}" ]]; then echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true; fi
    if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then logger -t "${SYSLOG_TAG}" -p user.err "${message}" 2>/dev/null || true; fi
}
log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { [[ $DEBUG -eq 1 ]] && log "DEBUG" "$@"; }

# --- Operation tracking and rollback ---
track_operation() {
    local op_type="$1"; local target="$2"; local status="$3"
    local status_str="UNKNOWN"; case "$status" in "$OP_SUCCESS") status_str="SUCCESS";; "$OP_FAILED") status_str="FAILED";; "$OP_SKIPPED") status_str="SKIPPED";; esac
    log_debug "Track op: ${op_type} on ${target} -> ${status_str}"
    OPERATIONS["${op_type}:${target}"]=$status
    if [[ $status -eq $OP_SUCCESS && "$op_type" != "verify" ]]; then ROLLBACK_QUEUE+=("${op_type}:${target}"); fi
}

print_operation_summary() {
    if [[ $DEBUG -eq 0 ]]; then return; fi
    log_info "--- Operation Summary ---"
    if [[ ${#OPERATIONS[@]} -eq 0 ]]; then log_info "No operations were tracked."; return; fi
    local op_success=0 op_failed=0 op_skipped=0
    for op_key in "${!OPERATIONS[@]}"; do
        case "${OPERATIONS[$op_key]}" in "$OP_SUCCESS") op_success=$((op_success + 1));; "$OP_FAILED") op_failed=$((op_failed + 1));; "$OP_SKIPPED") op_skipped=$((op_skipped + 1));; esac
    done
    log_info "Summary: ${op_success} successful, ${op_failed} failed, ${op_skipped} skipped."
}

rollback_operations() {
    log_warn "Rolling back operations for failed user..."
    for ((i=${#ROLLBACK_QUEUE[@]}-1; i>=0; i--)); do
        local op="${ROLLBACK_QUEUE[i]}"; local op_type="${op%%:*}"; local target="${op#*:}"
        if [[ "$op_type" == "mkdir" && -d "$target" ]]; then log_info "Rolling back directory creation: $target"; rmdir "$target" 2>/dev/null || true; fi
    done
    ROLLBACK_QUEUE=()
}

# --- Cleanup & Signal Handling ---
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_warn "Script exiting with error code $exit_code."
        if [[ ${#ROLLBACK_QUEUE[@]} -gt 0 ]]; then log_error "An operation failed. Rolling back changes for the last user."; rollback_operations; fi
        if [[ ${#FAILED_USERS[@]} -gt 0 ]]; then log_warn "Failed to process users: ${FAILED_USERS[*]}"; fi
    fi
    print_operation_summary
    log_info "Script completed. Processed: $TOTAL_PROCESSED, Success: $SUCCESS_COUNT"
    exit "$exit_code"
}
trap cleanup EXIT
trap 'log_warn "Received interrupt signal. Cleaning up..."; exit 130' INT TERM

# --- Validation Functions ---
validate_domain() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]] || { log_error "Invalid domain format: $1"; return 1; }; }
validate_group_name() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9\ \._\-]{0,254}$ ]] || { log_error "Invalid group name format: $1"; return 1; }; }
validate_dataset_path() { [[ "$1" =~ ^/mnt/.* && ! "$1" =~ \.\. ]] || { log_error "Invalid or insecure dataset path: $1"; return 1; }; }
error_exit() { log_error "$2"; exit "$1"; }

# --- Usage and Help ---
usage() {
    cat <<EOF >&2
Usage: $SCRIPT_NAME [OPTIONS]
REQUIRED:
  --domain DOMAIN       AD domain name
  --group "AD_GROUP"    AD group name
  --dataset PATH        ZFS dataset path (must start with /mnt/)
OPTIONAL:
  --apply               Apply changes (default: dry-run)
  --debug               Enable debug output
  --force-posix         Force POSIX ACLs
  --force-rescan        Force a new scan, ignoring all cached user results
  --skip-backup         Do not back up existing ACLs
  --min-uid UID         The minimum UID for an account to be considered a user (overrides auto-detection)
  --max-uid UID         The maximum UID for an account to be considered a user (overrides auto-detection)
  --exclude-pattern REGEX
                        Exclude accounts matching a regex pattern. Can be used multiple times.
                        Example: --exclude-pattern '\\.[0-9]{3}$'
  --help                Show this help message
  --version             Show version information
EOF
}
version() { echo "$SCRIPT_NAME version $SCRIPT_VERSION"; exit $EXIT_SUCCESS; }

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) [[ -n "${2:-}" ]] || error_exit $EXIT_INVALID_ARGS "Missing value for --domain"; DOMAIN="$2"; shift 2 ;;
            --group) [[ -n "${2:-}" ]] || error_exit $EXIT_INVALID_ARGS "Missing value for --group"; AD_GROUP="$2"; shift 2 ;;
            --dataset) [[ -n "${2:-}" ]] || error_exit $EXIT_INVALID_ARGS "Missing value for --dataset"; DATASET_PATH="$2"; shift 2 ;;
            --min-uid) [[ "${2:-}" =~ ^[0-9]+$ ]] || error_exit $EXIT_INVALID_ARGS "Invalid UID for --min-uid"; MIN_UID="$2"; shift 2 ;;
            --max-uid) [[ "${2:-}" =~ ^[0-9]+$ ]] || error_exit $EXIT_INVALID_ARGS "Invalid UID for --max-uid"; MAX_UID="$2"; shift 2 ;;
            --exclude-pattern) [[ -n "${2:-}" ]] || error_exit $EXIT_INVALID_ARGS "Missing value for --exclude-pattern"; EXCLUDE_PATTERNS+=("$2"); shift 2 ;;
            --apply) APPLY=1; shift ;;
            --debug) DEBUG=1; shift ;;
            --force-posix) FORCE_POSIX=1; shift ;;
            --force-rescan) FORCE_RESCAN=1; shift ;;
            --skip-backup) SKIP_BACKUP=1; shift ;;
            --help) usage; exit $EXIT_SUCCESS ;;
            --version) version ;;
            -*) error_exit $EXIT_INVALID_ARGS "Unknown option: $1" ;;
            *) error_exit $EXIT_INVALID_ARGS "Unexpected argument: $1" ;;
        esac
    done
    if [[ -z "$DOMAIN" || -z "$AD_GROUP" || -z "$DATASET_PATH" ]]; then usage; error_exit $EXIT_INVALID_ARGS "Missing required arguments."; fi
    validate_domain "$DOMAIN" && validate_group_name "$AD_GROUP" && validate_dataset_path "$DATASET_PATH" || exit $EXIT_INVALID_ARGS
}

# --- System & Prerequisite Checks ---
check_dependencies() {
    log_info "Checking system dependencies..."; local missing_deps=0
    for cmd in wbinfo getent id zfs timeout midclt systemctl host jq; do
        if ! command -v "$cmd" &>/dev/null; then log_error "Required command not found: $cmd"; missing_deps=1; fi
    done
    if command -v nfs4xdr_setfacl &>/dev/null; then HAS_NFS4XDR_SETFACL=1; fi; if command -v nfs4_setfacl &>/dev/null; then HAS_NFS4_SETFACL=1; fi
    if command -v setfacl &>/dev/null; then HAS_SETFACL=1; fi
    if [[ $HAS_NFS4XDR_SETFACL -eq 0 && $HAS_NFS4_SETFACL -eq 0 && $HAS_SETFACL -eq 0 ]]; then log_error "No ACL tools found"; missing_deps=1; fi
    if [[ $APPLY -eq 1 && $EUID -ne 0 ]]; then log_error "Must run as root with --apply"; missing_deps=1; fi
    if [[ $missing_deps -eq 1 ]]; then error_exit $EXIT_MISSING_DEPS "Missing required dependencies"; fi
    log_info "All dependencies satisfied."
}

verify_dataset() {
    log_info "Verifying ZFS dataset: $DATASET_PATH"; DATASET_PATH="${DATASET_PATH%/}"; ZFS_DATASET="${DATASET_PATH#/mnt/}"
    timeout "$TIMEOUT" zfs list -H "$ZFS_DATASET" &>/dev/null || error_exit $EXIT_STORAGE_ERROR "ZFS dataset not found: $ZFS_DATASET"
    if [[ $APPLY -eq 1 && ! -w "$DATASET_PATH" ]]; then error_exit $EXIT_STORAGE_ERROR "Dataset path is not writable: $DATASET_PATH"; fi
    local acltype; acltype=$(zfs get -H -o value acltype "$ZFS_DATASET" 2>/dev/null || echo "off")
    log_info "Dataset ACL type: $acltype"
    if [[ $FORCE_POSIX -eq 0 && "$acltype" == "nfsv4" ]]; then
        if [[ $HAS_NFS4XDR_SETFACL -eq 1 ]]; then USE_NFSV4=1; log_info "Will use TrueNAS SCALE NFSv4 XDR ACLs";
        elif [[ $HAS_NFS4_SETFACL -eq 1 ]]; then USE_NFSV4=2; log_info "Will use standard NFSv4 ACLs";
        else USE_NFSV4=0; log_warn "NFSv4 dataset but only POSIX tools found. Falling back."; fi
    else USE_NFSV4=0; log_info "Will use POSIX ACLs"; fi
}

check_system_state() {
    log_info "Verifying system state..."
    if [[ -f /etc/version ]] && grep -qi "TrueNAS-SCALE" /etc/version 2>/dev/null; then
        log_debug "TrueNAS SCALE detected. Running specific checks."
        if ! systemctl is-active --quiet middlewared; then log_error "TrueNAS middleware service is not running"; return 1; fi
        if ! midclt call activedirectory.get_state | grep -q "HEALTHY"; then log_error "AD service is not healthy according to midclt"; return 1; fi
    fi
    if ! wbinfo --ping-dc &>/dev/null; then error_exit $EXIT_AUTH_ERROR "Cannot contact domain controller via winbind"; fi
    log_info "System state OK."
}

detect_uid_range() {
    log_info "Attempting to auto-detect UID range from idmap settings..."
    local idmap_json; if ! idmap_json=$(midclt call idmap.query 2>/dev/null); then log_warn "Could not query idmap settings. Will use default UID range."; return; fi
    local ad_backend; ad_backend=$(echo "$idmap_json" | jq -r '.[] | select(.name == "DS_TYPE_ACTIVEDIRECTORY")')
    if [[ -z "$ad_backend" ]]; then log_warn "Could not find Active Directory idmap backend. Will use default UID range."; return; fi
    local detected_low; detected_low=$(echo "$ad_backend" | jq -r '.range_low'); local detected_high; detected_high=$(echo "$ad_backend" | jq -r '.range_high')
    if [[ "$detected_low" =~ ^[0-9]+$ && "$detected_high" =~ ^[0-9]+$ ]]; then
        MIN_UID=$detected_low; MAX_UID=$detected_high
        log_info "Successfully detected UID range for AD: $MIN_UID - $MAX_UID"
    else
        log_warn "Detected idmap ranges are invalid. Will use default UID range."
    fi
}

# --- Per-User Caching Group Member Lookup with UID Filtering ---
_get_live_group_members() {
    local groupname="$1"; local members=()
    log_info "Strategy A: Attempting fast lookup for group '$groupname'..."
    local group_line; group_line=$(getent group "$groupname" || echo ""); local member_list; member_list=$(echo "$group_line" | cut -d: -f4)
    if [[ -n "$member_list" ]]; then
        log_info "Strategy A successful.";
        while IFS= read -r user; do [[ -n "$user" ]] && members+=("${DOMAIN}\\${user}"); done <<< "$(echo "$member_list" | tr ',' '\n')"
        printf '%s\n' "${members[@]}"; return 0
    fi

    log_warn "Strategy A found no members. Falling back to Strategy B: Full User Scan with UID Filtering."
    local group_gid; group_gid=$(echo "$group_line" | cut -d: -f3); if [[ -z "$group_gid" ]]; then log_error "Could not resolve GID for group '$groupname'."; return 1; fi

    local all_users_full; all_users_full=$(getent passwd)
    local all_users; readarray -t all_users <<< "$all_users_full"; local total_user_count=${#all_users[@]}
    log_info "Will scan $total_user_count total system accounts using UID range: $MIN_UID - $MAX_UID. This may be slow on first run."

    local user_count=0; local skipped_uid_count=0; local skipped_pattern_count=0
    for user_line in "${all_users[@]}"; do
        user_count=$((user_count + 1))
        local raw_user; raw_user=$(echo "$user_line" | cut -d: -f1); local user_uid; user_uid=$(echo "$user_line" | cut -d: -f3)

        if (( user_uid < MIN_UID || user_uid > MAX_UID )); then
            log_debug "Skipping account outside UID range ($MIN_UID-$MAX_UID): $raw_user (UID: $user_uid)"; skipped_uid_count=$((skipped_uid_count + 1)); continue
        fi
        
        local excluded=0
        if [[ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]]; then
            for pattern in "${EXCLUDE_PATTERNS[@]}"; do
                if [[ "$raw_user" =~ $pattern ]]; then
                    log_debug "Skipping account matching exclude pattern '$pattern': $raw_user"; skipped_pattern_count=$((skipped_pattern_count + 1)); excluded=1; break
                fi
            done
        fi
        if [[ $excluded -eq 1 ]]; then continue; fi
        
        if (( user_count % 500 == 0 )); then log_info "  ...scan progress: $user_count / $total_user_count accounts processed..."; fi
        
        local user_cache_file="${USER_CACHE_DIR}/${raw_user}.groups"; local user_groups=""
        if [[ -f "$user_cache_file" ]]; then
            local now; now=$(date +%s); local file_mod_time; file_mod_time=$(stat -c %Y "$user_cache_file")
            if (( (now - file_mod_time) < CACHE_TTL_SECONDS )); then
                log_debug "Cache HIT for user '$raw_user'"; user_groups=$(cat "$user_cache_file")
            else
                log_debug "Cache STALE for user '$raw_user'."; user_groups=$(wbinfo -r "$raw_user" 2>/dev/null || echo "failed"); echo "$user_groups" > "$user_cache_file"
            fi
        else
            log_debug "Cache MISS for user '$raw_user'."; user_groups=$(wbinfo -r "$raw_user" 2>/dev/null || echo "failed"); echo "$user_groups" > "$user_cache_file"
        fi
        
        if [[ -n "$user_groups" && "$user_groups" != "failed" ]] && echo "$user_groups" | grep -qw "$group_gid"; then
            log_info "Found group member: $raw_user"; members+=("${DOMAIN}\\${raw_user}")
        fi
    done
    
    log_info "Strategy B scan complete. Processed $user_count accounts, skipped $skipped_uid_count (UID range) and $skipped_pattern_count (pattern)."
    printf '%s\n' "${members[@]}"
}

# --- ACL and Home Directory Functions ---
backup_acls() {
    local homedir="$1"; if [[ $SKIP_BACKUP -eq 1 ]]; then return 0; fi
    log_debug "Backing up existing ACLs for: $homedir"; local backup_file="${homedir}/.acl_backup_$(date +%Y%m%d_%H%M%S)"
    if [[ $USE_NFSV4 -eq 1 ]]; then nfs4xdr_getfacl "$homedir" > "$backup_file.nfs4xdr" 2>/dev/null || true;
    elif [[ $USE_NFSV4 -eq 2 ]]; then nfs4_getfacl "$homedir" > "$backup_file.nfs4" 2>/dev/null || true;
    else getfacl "$homedir" > "$backup_file.posix" 2>/dev/null || true; fi
}

apply_acls_with_retry() {
    local homedir="$1" domain_user="$2" success=0
    for (( i=1; i<=$MAX_RETRIES; i++ )); do
        case $USE_NFSV4 in
            1) nfs4xdr_setfacl -b "$homedir" &>/dev/null && nfs4xdr_setfacl -a "A::${domain_user}:rwxpDdaARWcCos" -a "A:fd:${domain_user}:rwxpDdaARWcCos" "$homedir" &>/dev/null && success=1 && break ;;
            2) nfs4_setfacl -b "$homedir" &>/dev/null && nfs4_setfacl -a "A::${domain_user}:rwxpDdaARWcCos" -a "A:fd:${domain_user}:rwxpDdaARWcCos" "$homedir" &>/dev/null && success=1 && break ;;
            0) setfacl -b "$homedir" &>/dev/null && setfacl -m "u:${domain_user}:rwx" -m "d:u:${domain_user}:rwx" "$homedir" &>/dev/null && success=1 && break ;;
        esac
        log_warn "ACL application failed (attempt $i/$MAX_RETRIES), retrying..."; sleep 2
    done
    return $((1 - success))
}

verify_acls() {
    local homedir="$1" domain_user="$2"; log_debug "Verifying ACLs for: $homedir"
    if [[ $USE_NFSV4 -gt 0 ]]; then
        if nfs4_getfacl "$homedir" 2>/dev/null | grep -q "${domain_user}"; then return 0; fi
    else
        if getfacl "$homedir" 2>/dev/null | grep -q "user:${domain_user}:rwx"; then return 0; fi
    fi
    log_warn "ACL verification failed for: $domain_user on $homedir"; return 1
}

create_home_dir() {
    local domain_user="$1"; local username="${domain_user##*\\}"; local homedir="${DATASET_PATH}/${username}"
    ROLLBACK_QUEUE=()
    if [[ ! "$username" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$ ]]; then log_error "Invalid username format: $username"; return 1; fi
    log_info "Processing user: $domain_user -> $homedir"; TOTAL_PROCESSED=$((TOTAL_PROCESSED + 1))
    local uid; uid=$(id -u "$domain_user" 2>/dev/null) || { log_error "Could not resolve UID for: $domain_user"; return 1; }
    local primary_gid; primary_gid=$(id -g "$domain_user" 2>/dev/null || echo "$uid")
    log_debug "User: $domain_user, UID: $uid, GID: $primary_gid"
    
    if [[ $APPLY -eq 0 ]]; then log_info "  (DRY-RUN) Would create $homedir"; return 0; fi
    if [[ -d "$homedir" ]]; then log_info "Directory already exists: $homedir"; track_operation "mkdir" "$homedir" "$OP_SKIPPED";
    else
        if ! mkdir -p "$homedir"; then log_error "Failed to create directory: $homedir"; return 1; fi
        track_operation "mkdir" "$homedir" "$OP_SUCCESS"
    fi
    
    backup_acls "$homedir"; if ! chown "$uid:$primary_gid" "$homedir" || ! chmod 0750 "$homedir"; then log_error "Failed to set ownership for: $homedir"; return 1; fi
    track_operation "chown" "$homedir" "$OP_SUCCESS"
    if ! apply_acls_with_retry "$homedir" "$domain_user"; then log_error "Failed to apply ACLs for: $homedir"; return 1; fi
    track_operation "acl" "$homedir" "$OP_SUCCESS"
    if ! verify_acls "$homedir" "$domain_user"; then log_error "Final verification of ACLs failed."; return 1; fi
    track_operation "verify" "$homedir" "$OP_SUCCESS"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    log_info "Successfully configured home directory for: $domain_user"
}

# --- Pre-flight and Main Logic ---
preflight_checks() {
    mkdir -p "$USER_CACHE_DIR" &>/dev/null || true
    check_dependencies
    verify_dataset
}

run_script_logic() {
    check_system_state || error_exit "$EXIT_ERROR" "System state check failed"
    if ! [[ "$MIN_UID" -ne 1000 || "$MAX_UID" -ne 2000000000 ]]; then
        detect_uid_range
    else
        log_info "Using manually specified UID range: $MIN_UID - $MAX_UID"
    fi
    if [[ $FORCE_RESCAN -eq 1 ]]; then
        log_info "Clearing per-user cache directory due to --force-rescan flag."; rm -rf "${USER_CACHE_DIR:?}/"*
    fi
    
    local members; members=$(_get_live_group_members "$AD_GROUP")
    local total_users=0; if [[ -n "$members" ]]; then total_users=$(echo "$members" | wc -l); fi
    log_info "Found $total_users users to process"
    if [[ $total_users -eq 0 ]]; then log_info "No users to process. Exiting."; return 0; fi

    local current_user_num=1
    while IFS= read -r domain_user; do
        [[ -z "$domain_user" ]] && continue
        log_info "--- Processing user $current_user_num of $total_users ---"
        if ! create_home_dir "$domain_user"; then
            FAILED_USERS+=("$domain_user"); log_error "Failed to process user: $domain_user. Continuing...";
        fi
        current_user_num=$((current_user_num + 1)); sleep 0.1
    done <<< "$members"
}

# --- Script entry point ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    preflight_checks
    run_script_logic
fi