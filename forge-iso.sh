#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Forged ISO Builder — Linux-native Windows 11 Gaming ISO creation
# ==============================================================================
# Replaces NTLITE. Extracts the Windows ISO, injects payload, writes
# autounattend.xml, and repacks to a bootable UEFI+BIOS hybrid ISO.
# All optimization logic lives in Forge-PostInstall.ps1 (runs at first logon).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="${SCRIPT_DIR}/payload"

# --- logging ---
log_info()  { echo -e "\033[0;32m[INFO]\033[0m  $1"; }
log_warn()  { echo -e "\033[0;33m[WARN]\033[0m  $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }

# --- dependency checks ---
check_deps() {
    local missing=()
    for dep in 7z wimlib-imagex xorrisofs; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if ((${#missing[@]} > 0)); then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Install them: sudo pacman -S p7zip wimlib libisoburn"
        exit 1
    fi
    log_info "All dependencies found."
}

# --- find Pro edition index ---
find_pro_index() {
    local wim="$1"
    local output
    output=$(wimlib-imagex info "$wim" 2>&1)
    local index
    index=$(echo "$output" | awk '/^Index:/{idx=$2} /^Name:[[:space:]]*Windows 11 Pro$/{print idx; exit}')
    if [[ -z "$index" ]]; then
        log_error "Could not find Windows Pro edition in WIM. Available editions:"
        wimlib-imagex info "$wim"
        exit 1
    fi
    log_info "Found Pro edition at index $index" >&2
    echo "$index"
}

# --- isolate Pro edition in a single export pass ---
isolate_pro_edition() {
    local wim="$1"
    local keep="$2"
    local wim_new="${wim}.new"

    log_info "Exporting only Pro edition (index $keep) to new WIM (single-pass)..."
    wimlib-imagex export "$wim" "$keep" "$wim_new" --compress=LZX 2>&1 || {
        log_error "Export failed"
        rm -f "$wim_new"
        exit 1
    }
    rm -f "$wim"
    mv "$wim_new" "$wim"
    log_info "WIM now contains only Pro edition at index 1."
}

# --- copy payload files into mounted WIM ---
inject_payload() {
    local mount="$1"
    local dest="${mount}/Windows/Setup/Scripts"

    mkdir -p "$dest"

    if [[ -f "${PAYLOAD_DIR}/Forge-PostInstall.ps1" ]]; then
        cp "${PAYLOAD_DIR}/Forge-PostInstall.ps1" "${dest}/"
        log_info "Injected Forge-PostInstall.ps1"
    else
        log_error "Forge-PostInstall.ps1 not found in ${PAYLOAD_DIR}"
        exit 1
    fi

    if [[ -f "${PAYLOAD_DIR}/MinSudo.exe" ]]; then
        cp "${PAYLOAD_DIR}/MinSudo.exe" "${dest}/"
        log_info "Injected MinSudo.exe"
    else
        log_error "MinSudo.exe not found in ${PAYLOAD_DIR}"
        exit 1
    fi

    if [[ -f "${PAYLOAD_DIR}/RemoveEdge.ps1" ]]; then
        cp "${PAYLOAD_DIR}/RemoveEdge.ps1" "${dest}/"
        log_info "Injected RemoveEdge.ps1"
    else
        log_warn "RemoveEdge.ps1 not found -- Edge removal will be skipped"
    fi

    if [[ -f "${PAYLOAD_DIR}/Forged.png" ]]; then
        mkdir -p "${mount}/Windows/Web/Wallpaper/Forged"
        cp "${PAYLOAD_DIR}/Forged.png" "${mount}/Windows/Web/Wallpaper/Forged/"
        log_info "Injected Forged.png wallpaper"
    else
        log_warn "Forged.png not found — skipping wallpaper injection"
    fi

    if [[ -f "${PAYLOAD_DIR}/driver-exclude.reg" ]]; then
        cp "${PAYLOAD_DIR}/driver-exclude.reg" "${dest}/"
        log_info "Injected driver-exclude.reg"
    fi

    if [[ -f "${PAYLOAD_DIR}/onedrive.bat" ]]; then
        cp "${PAYLOAD_DIR}/onedrive.bat" "${dest}/"
        log_info "Injected onedrive.bat"
    fi

    if [[ -f "${PAYLOAD_DIR}/taskbar.bat" ]]; then
        cp "${PAYLOAD_DIR}/taskbar.bat" "${dest}/"
        log_info "Injected taskbar.bat"
    fi

    if [[ -f "${PAYLOAD_DIR}/W11STARTMENU.ps1" ]]; then
        cp "${PAYLOAD_DIR}/W11STARTMENU.ps1" "${dest}/"
        log_info "Injected W11STARTMENU.ps1"
    fi

    # Inject clean LayoutModification.xml into Default User (prevents default pins)
    local_layout_dir="${mount}/Users/Default/AppData/Local/Microsoft/Windows/Shell"
    mkdir -p "$local_layout_dir"
    if [[ -f "${PAYLOAD_DIR}/LayoutModification.xml" ]]; then
        cp "${PAYLOAD_DIR}/LayoutModification.xml" "$local_layout_dir/LayoutModification.xml"
        log_info "Injected LayoutModification.xml -- clean taskbar and start menu"
    fi
}

# --- offline AppX debloat: remove bloatware from WIM before it ever boots ---
debloat_wim() {
    local mount="$1"

    log_info "Offline AppX debloat -- removing packages from WIM..."

    local appx_fragments=(
        "Microsoft.BingNews" "Microsoft.BingWeather" "Microsoft.BingSearch"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.People" "Microsoft.Todos"
        "Microsoft.WindowsFeedbackHub" "Microsoft.WindowsMaps"
        "Microsoft.ZuneMusic" "Microsoft.ZuneVideo"
        "Microsoft.WindowsSoundRecorder" "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera" "Microsoft.MicrosoftOfficeHub"
        "Microsoft.549981C3F5F10" "MicrosoftCorporationII.QuickAssist"
        "MicrosoftCorporationII.MicrosoftFamily"
        "Microsoft.PowerAutomateDesktop"
        "Microsoft.Advertising.Xaml" "Microsoft.Microsoft3DViewer"
        "Microsoft.MixedReality.Portal" "Microsoft.Windows.DevHome"
        "Microsoft.OutlookForWindows" "Microsoft.SkypeApp"
        "Microsoft.YourPhone" "Microsoft.Windows.ContentDeliveryManager"
        "Microsoft.Windows.Photos" "Microsoft.StorePurchaseApp"
        "Microsoft.WindowsCommunicationsApps"
        "Microsoft.GamingApp" "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxApp" "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.XboxIdentityProvider"
        "Clipchamp.Clipchamp" "Microsoft.StartExperiencesApp"
        "Microsoft.Whiteboard" "Microsoft.WidgetsPlatformRuntime"
        "MicrosoftWindows.Client.WebExperience"
        "Microsoft.OneDriveSync" "microsoft.microsoftskydrive"
        "MSTeams" "MicrosoftTeams" "Microsoft.WindowsStore"
    )

    local apps_dir
    apps_dir="${mount}/Program Files/WindowsApps"
    if [[ -d "$apps_dir" ]]; then
        for frag in "${appx_fragments[@]}"; do
            find "$apps_dir" -maxdepth 1 -iname "*${frag}*" -type d -exec rm -rf {} + 2>/dev/null
        done
    fi

    local sysapps_dir
    sysapps_dir="${mount}/Windows/SystemApps"
    local sysapps_bloat=(
        "Microsoft.MicrosoftEdgeDevToolsClient"
        "Microsoft.Windows.AI.Copilot.Provider"
    )
    if [[ -d "$sysapps_dir" ]]; then
        for frag in "${sysapps_bloat[@]}"; do
            find "$sysapps_dir" -maxdepth 1 -iname "*${frag}*" -type d -exec rm -rf {} + 2>/dev/null
        done
    fi

    local od_exe
    od_exe="${mount}/Windows/SysWOW64/OneDriveSetup.exe"
    [[ -f "$od_exe" ]] && rm -f "$od_exe"

    log_info "WIM debloat complete."
}

# --- build ISO with xorrisofs ---
build_iso() {
    local extracted="$1"
    local output="$2"
    local label="${3:-FORGED}"

    log_info "Building ISO: ${output}"

    xorrisofs \
        -iso-level 4 \
        -joliet \
        -joliet-long \
        -disable-deep-relocation \
        -rational-rock \
        -no-emul-boot \
        -b boot/etfsboot.com \
        -boot-load-size 8 \
        -eltorito-alt-boot \
        -no-emul-boot \
        -e efi/microsoft/boot/efisys.bin \
        -boot-load-size 1 \
        -volid "${label}" \
        -output "${output}" \
        "${extracted}" 2>&1

    log_info "ISO created: ${output}"
}

# --- main ---
main() {
    check_deps

    local ISO_INPUT="${1:-}"
    local ISO_OUTPUT="${2:-${SCRIPT_DIR}/Forged-Win11.iso}"

    if [[ -z "$ISO_INPUT" ]]; then
        echo "Usage: $0 <path-to-windows-iso> [output-iso-path]"
        echo "Example: $0 ../en-us_windows_11_*.iso ./Forged-Win11-25H2.iso"
        exit 1
    fi

    if [[ ! -f "$ISO_INPUT" ]]; then
        log_error "ISO not found: $ISO_INPUT"
        exit 1
    fi

    local WORK_DIR="${SCRIPT_DIR}/work"
    local EXTRACT_DIR="${WORK_DIR}/extracted"
    local MOUNT_DIR="${WORK_DIR}/mount"
    local WIM_FILE

    # cleanup any previous runs
    log_info "Cleaning up previous work directory..."
    rm -rf "$WORK_DIR"

    # trap for cleanup on error
    trap_on_error() {
        log_error "Build failed at step: ${1:-unknown}"
        # try to unmount if still mounted
        if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
            log_warn "Unmounting WIM (discarding changes)..."
            wimlib-imagex unmount "$MOUNT_DIR" --lazy 2>/dev/null || true
        fi
        log_warn "Work directory preserved at: $WORK_DIR"
        exit 1
    }

    # step 1: extract ISO
    log_info "Extracting ISO..."
    mkdir -p "$EXTRACT_DIR"
    7z x -y -o"$EXTRACT_DIR" "$ISO_INPUT" > /dev/null
    log_info "ISO extracted to ${EXTRACT_DIR}"

    # locate install.wim or install.esd
    if [[ -f "${EXTRACT_DIR}/sources/install.wim" ]]; then
        WIM_FILE="${EXTRACT_DIR}/sources/install.wim"
    elif [[ -f "${EXTRACT_DIR}/sources/install.esd" ]]; then
        WIM_FILE="${EXTRACT_DIR}/sources/install.esd"
    else
        log_error "No install.wim or install.esd found in extracted ISO"
        exit 1
    fi

    # step 2: find & isolate Pro edition
    local PRO_INDEX
    PRO_INDEX=$(find_pro_index "$WIM_FILE")
    isolate_pro_edition "$WIM_FILE" "$PRO_INDEX"

    # step 3: mount WIM RW
    log_info "Mounting WIM for modification..."
    mkdir -p "$MOUNT_DIR"
    wimlib-imagex mountrw "$WIM_FILE" 1 "$MOUNT_DIR" 2>&1
    log_info "WIM mounted at ${MOUNT_DIR}"

    # step 4: inject payload
    inject_payload "$MOUNT_DIR"

    # step 4b: offline AppX debloat -- delete bloatware files from WIM
    debloat_wim "$MOUNT_DIR"

    # step 5: unmount and commit
    log_info "Unmounting and committing changes..."
    wimlib-imagex unmount "$MOUNT_DIR" --commit --check 2>&1
    log_info "WIM changes committed."

    # step 5b: place autounattend.xml at ISO root (Windows Setup reads it from boot media root, not inside WIM)
    if [[ -f "${SCRIPT_DIR}/autounattend.xml" ]]; then
        cp "${SCRIPT_DIR}/autounattend.xml" "${EXTRACT_DIR}/"
        log_info "Placed autounattend.xml at ISO root"
    else
        log_error "autounattend.xml not found in ${SCRIPT_DIR}"
        exit 1
    fi

    # step 6: build ISO
    build_iso "$EXTRACT_DIR" "$ISO_OUTPUT" "FORGED"

    # step 7: cleanup work dir
    log_info "Cleaning up work directory..."
    rm -rf "$WORK_DIR"

    log_info "Done! ISO ready at: ${ISO_OUTPUT}"
    log_info "Burn to USB with: sudo dd bs=4M if=${ISO_OUTPUT} of=/dev/sdX status=progress oflag=sync"
}

main "$@"
