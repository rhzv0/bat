#!/bin/bash
# kcc-build.sh <kernel_version> <arch> <output_path>
# Compila bat-stealth.ko para o kernel especificado.
# Chamado pelo kcc-server.py; não executar manualmente em produção.

set -euo pipefail

KERNEL_VERSION="$1"
ARCH="$2"
OUTPUT="$3"
SRC_DIR="/root/kcc/kperf-qos-src"
BUILD_TMP="/tmp/kcc-build-$$"

log() { echo "[KCC-BUILD] $*" >&2; }

# Instala headers se necessário
HEADERS_DIR="/lib/modules/${KERNEL_VERSION}/build"

_is_ubuntu_kernel() {
    # Ubuntu kernels: 6.14.0-1018-aws, 6.8.0-1050-generic, etc.
    # Flavor is a known Ubuntu suffix; build number is 3+ digits (vs Debian 2-digit)
    local kver="$1"
    local flavor
    flavor=$(echo "$kver" | grep -oP '(?<=-)\w[\w-]*$' || true)
    case "$flavor" in
        aws|aws-arm64|azure|gcp|gke|oracle|generic|lowlatency|kvm|raspi|intel-iotg|oem)
            return 0 ;;
        *-aws|*-azure|*-gcp|*-generic|*-lowlatency)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

_install_ubuntu_headers() {
    # Instala headers de kernels Ubuntu (Noble/Jammy/Focal) em relay Ubuntu 22.04.
    # Necessário quando o kernel alvo é de release Ubuntu diferente do relay.
    # Estratégia: adicionar temp apt source para cada codename; tentar apt-get install.
    local kver="$1"
    local pkg="linux-headers-${kver}"
    local tmp_list="/etc/apt/sources.list.d/kcc-ubuntu-headers-tmp.list"
    local codenames=("noble" "jammy" "focal" "mantic" "oracular")

    log "Ubuntu kernel detected — trying Ubuntu archives for $pkg..."

    local codename
    for codename in "${codenames[@]}"; do
        log "Trying Ubuntu ${codename} repos..."
        cat > "$tmp_list" <<EOF
deb [trusted=yes] http://archive.ubuntu.com/ubuntu ${codename} main restricted
deb [trusted=yes] http://archive.ubuntu.com/ubuntu ${codename}-updates main restricted
deb [trusted=yes] http://security.ubuntu.com/ubuntu ${codename}-security main restricted
EOF
        DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>&1 | tail -5 &&
           [[ -d "/lib/modules/${kver}/build" ]]; then
            log "Installed $pkg from Ubuntu ${codename}"
            rm -f "$tmp_list"
            DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
            return 0
        fi
        rm -f "$tmp_list"
    done

    log "ERROR: could not install $pkg from any Ubuntu archive codename"
    return 1
}

_install_debian_headers() {
    # Instala headers Debian em relay Ubuntu via download direto de .deb
    # Necessário quando relay Ubuntu não tem pacotes Debian no apt.
    # Estratégia: baixar linux-headers-common + linux-headers-<flavor> + linux-kbuild
    # de security.debian.org e extrair para /usr/src/ + /usr/lib/linux-kbuild-<major>/
    local kver="$1"   # ex: 6.1.0-44-cloud-amd64
    local base_ver    # ex: 6.1
    base_ver=$(echo "$kver" | grep -oP '^\d+\.\d+')
    local kbuild_pkg="linux-kbuild-${base_ver}"
    local common_pkg="linux-headers-${kver%-*}-common"   # ex: linux-headers-6.1.0-44-common
    local flavor_pkg="linux-headers-${kver}"

    # Tenta encontrar versão do pacote via um Debian temporário (fallback: snapshot)
    local pkg_ver
    pkg_ver=$(apt-cache show "$flavor_pkg" 2>/dev/null | grep "^Version:" | head -1 | awk '{print $2}' || true)

    if [[ -z "$pkg_ver" ]]; then
        log "ERROR: cannot determine package version for $flavor_pkg from local apt cache"
        log "       Add Debian bookworm to apt sources or pre-install headers manually"
        exit 1
    fi

    log "Downloading Debian headers $flavor_pkg=$pkg_ver from security.debian.org..."

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" RETURN

    # Determina URL base: pacotes em pool/updates = security, pool/main = stable
    local common_fn="${common_pkg}_${pkg_ver}_all.deb"
    local flavor_fn="${flavor_pkg}_${pkg_ver}_amd64.deb"
    local kbuild_fn="${kbuild_pkg}_${pkg_ver}_amd64.deb"

    for base_url in \
        "http://security.debian.org/debian-security/pool/updates/main/l/linux" \
        "http://deb.debian.org/debian/pool/main/l/linux" \
        "http://deb.debian.org/debian-security/pool/updates/main/l/linux"
    do
        if wget -q --timeout=30 "${base_url}/${common_fn}" -O "${tmpdir}/${common_fn}" 2>/dev/null && \
           wget -q --timeout=30 "${base_url}/${flavor_fn}" -O "${tmpdir}/${flavor_fn}" 2>/dev/null && \
           wget -q --timeout=30 "${base_url}/${kbuild_fn}" -O "${tmpdir}/${kbuild_fn}" 2>/dev/null; then
            log "Downloaded from ${base_url}"
            break
        fi
        rm -f "${tmpdir}/"*.deb
    done

    [[ -f "${tmpdir}/${common_fn}" ]] || { log "ERROR: failed to download $common_fn"; exit 1; }

    # Extrai os .deb (dpkg -x funciona cross-arch)
    dpkg -x "${tmpdir}/${common_fn}" "$tmpdir/common"
    dpkg -x "${tmpdir}/${flavor_fn}" "$tmpdir/flavor"
    dpkg -x "${tmpdir}/${kbuild_fn}" "$tmpdir/kbuild"

    # Instala headers em /usr/src/
    local src_common="/usr/src/${common_pkg}"
    local src_flavor="/usr/src/${flavor_pkg}"
    [[ -d "$src_common" ]] || cp -r "$tmpdir/common/usr/src/${common_pkg}" /usr/src/
    [[ -d "$src_flavor" ]] || cp -r "$tmpdir/flavor/usr/src/${flavor_pkg}" /usr/src/

    # Instala kbuild scripts (scripts/ nos headers e symlink para /usr/lib/linux-kbuild-<major>/)
    local kbuild_lib="/usr/lib/${kbuild_pkg}"
    mkdir -p "$kbuild_lib"
    [[ -d "${kbuild_lib}/scripts" ]] || cp -r "$tmpdir/kbuild/usr/lib/${kbuild_pkg}/scripts" "$kbuild_lib/"
    [[ -d "${kbuild_lib}/tools"   ]] || cp -r "$tmpdir/kbuild/usr/lib/${kbuild_pkg}/tools"   "$kbuild_lib/" 2>/dev/null || true
    [[ -d "${kbuild_lib}/certs"   ]] || cp -r "$tmpdir/kbuild/usr/lib/${kbuild_pkg}/certs"   "$kbuild_lib/" 2>/dev/null || true

    # Cria symlink /lib/modules/<ver>/build
    mkdir -p "/lib/modules/${kver}"
    ln -sfn "$src_flavor" "/lib/modules/${kver}/build"
    log "Debian headers installed: $src_flavor"
}

if [[ ! -d "$HEADERS_DIR" ]]; then
    log "Installing kernel headers for ${KERNEL_VERSION}..."
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "linux-headers-${KERNEL_VERSION}" 2>&1 | tail -5 || true
        if [[ ! -d "$HEADERS_DIR" ]]; then
            if _is_ubuntu_kernel "$KERNEL_VERSION"; then
                log "apt-get did not provide headers — trying Ubuntu archive repos..."
                _install_ubuntu_headers "$KERNEL_VERSION"
            else
                log "apt-get did not provide headers — trying Debian repo download..."
                _install_debian_headers "$KERNEL_VERSION"
            fi
        fi
    elif command -v dnf &>/dev/null; then
        dnf install -y "kernel-devel-${KERNEL_VERSION}" 2>&1 | tail -5
    else
        log "ERROR: unknown package manager"
        exit 1
    fi
fi

[[ -d "$HEADERS_DIR" ]] || { log "ERROR: headers not found at $HEADERS_DIR"; exit 1; }

# Determina CC correto: Ubuntu 22.04 usa gcc-12; Debian pode usar gcc padrão
# Verifica se o compilador que construiu o kernel está disponível
if [[ -f "${HEADERS_DIR}/include/generated/compile.h" ]]; then
    # Extrai GCC version do kernel build
    GCC_VER=$(grep -oP 'gcc-\K[0-9]+' "${HEADERS_DIR}/include/generated/compile.h" 2>/dev/null | head -1 || true)
    if [[ -n "$GCC_VER" ]] && command -v "gcc-${GCC_VER}" &>/dev/null; then
        CC_FLAG="CC=gcc-${GCC_VER}"
        log "Using gcc-${GCC_VER} (from kernel compile.h)"
    elif [[ -n "$GCC_VER" ]]; then
        # Versão específica não instalada — tenta instalar via apt antes de usar fallback
        log "gcc-${GCC_VER} not found — trying apt-get install gcc-${GCC_VER}..."
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "gcc-${GCC_VER}" 2>&1 | tail -3 && \
           command -v "gcc-${GCC_VER}" &>/dev/null; then
            CC_FLAG="CC=gcc-${GCC_VER}"
            log "gcc-${GCC_VER} installed and selected"
        else
            # Fallback: usa gcc do sistema com override explícito para evitar default cross-compile
            CC_FLAG="CC=$(command -v gcc)"
            log "Fallback: CC=$(command -v gcc) (gcc-${GCC_VER} unavailable)"
        fi
    else
        CC_FLAG="CC=$(command -v gcc)"
        log "No compile.h version found — using CC=$(command -v gcc)"
    fi
else
    CC_FLAG=""
    log "compile.h not found — using default gcc"
fi

# Cria build dir isolado
cp -r "$SRC_DIR" "$BUILD_TMP"
trap "rm -rf $BUILD_TMP" EXIT

# Limpa artefatos de builds anteriores presentes no SRC_DIR
# Make incremental reutilizaria .o de kernel diferente → .ko silenciosamente corrompido
find "$BUILD_TMP" \( -name "*.o" -o -name "*.ko" -o -name "*.mod" \
    -o -name "*.mod.c" -o -name "modules.order" \) -delete 2>/dev/null || true

log "Building for kernel=${KERNEL_VERSION} arch=${ARCH}..."
make -C "$HEADERS_DIR" M="$BUILD_TMP" \
    ARCH="$ARCH" \
    ${CC_FLAG} \
    modules 2>&1 | tail -20

KO_FILE=$(find "$BUILD_TMP" -name "kperf_qos.ko" | head -1)
[[ -f "$KO_FILE" ]] || { log "ERROR: kperf_qos.ko not found after build"; exit 1; }

# NÃO fazer strip em kernel modules: seções de relocação e symbol table
# são necessárias para loading. strip pode invalidar o .ko.
cp "$KO_FILE" "$OUTPUT"
chmod 600 "$OUTPUT"
log "Success: $(wc -c < "$OUTPUT") bytes → $OUTPUT"
