#!/bin/bash
# =====================================================================
#  SORA - REZERVNOE KOPIROVANIE
#
#  ZACHEMU ETO KRITICHNO
#  --------------------
#  V /etc/sora/server.conf lezhat PRIVATNYE KLYUCHI VSEKH LYUDEY.
#  Poterya etogo fayla - poterya dostup VSEH, kto kogda-libo byl
#  podklyuchen. Ne vozstanovitsya: klyuchi ne vyvodimy iz realnogo
#  chisla, ih mozhno tolko sgenerirovat zanovo, posle chego starYE
#  konfigi u lyudey prodolzhat ne rabotat.
#
#  Po etoy prichine kopii hranitsya tolko na etom zhe servere, s
#  pravami 600. Kopiya na drugoy server - eto uzhe ne rezervnaya
#  kopiya, a peredacha chastnyh klyuchey tretim litsam.
#
#  ZAPUSK ot root:
#     bash sora_backup.sh                 sozdat kopiyu
#     bash sora_backup.sh list            pokazat kopii
#     bash sora_backup.sh restore KAT     vernut iz kopii
#     bash sora_backup.sh cleanup         udalit starye
#
#  KRON (stavitsya avtomatom):
#     17 4 * * *   bash /usr/local/bin/sora_backup.sh
#
#  VSE IMENA PEREMENNYKH - LATINTSEY. Bash ne prinimaet kirillitsu
#  v imenakh peremennykh: poluchitsya "bad substitution" pri zapuske.
#  Eto provereno realnym zapuskom, ne tolko cherez "bash -n".
# =====================================================================
set -uo pipefail

SORADIR="/etc/sora"
BACKUP="/var/backups/sora"
KEEP="${SORA_KEEP_BACKUPS:-30}"     # skolko kopiy derzhat
STAMP=$(date +%Y%m%d-%H%M%S)

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; RESET=$'\033[0m'

good() { echo "${GREEN}  [ok]${RESET} $*"; }
warn() { echo "${YELLOW}  [!]${RESET}  $*"; }
fail() { echo "${RED}  [ERROR]${RESET} $*"; }
info() { echo "${GREY}      $*${RESET}"; }

# Файлы, которые обязаны попасть в копию.
FILES="server.conf quotas.json blocked.json unbound.json traffic.json tracker.services"

if [ "$(id -u)" -ne 0 ]; then
    fail "Nuzhen root"
    exit 1
fi

# =====================================================================
#  Удалить старые копии
# =====================================================================
cleanup_old() {
    total=$(ls -1d "${BACKUP}"/sora-* 2>/dev/null | wc -l)
    if [ "${total}" -le "${KEEP}" ]; then
        return 0
    fi
    extra=$((total - KEEP))
    info "kopiy: ${total}, ostavlyu ${KEEP}, udalyayu ${extra}"
    # сортировка по имени = по времени, старые уходят первыми
    ls -1d "${BACKUP}"/sora-* 2>/dev/null | head -n "${extra}" | \
    while read -r d; do
        if [ -n "${d}" ] && [ -d "${d}" ]; then
            rm -rf "${d}" && echo "${GREY}      udalena ${d}${RESET}"
        fi
    done
}

# =====================================================================
#  Создать копию
# =====================================================================
create() {
    if [ ! -d "${SORADIR}" ]; then
        fail "Net ${SORADIR}. SORA ne ustanovlen?"
        exit 1
    fi

    install -d -m 700 "${BACKUP}"

    have=0
    for f in ${FILES}; do
        if [ -f "${SORADIR}/${f}" ]; then
            have=$((have + 1))
        fi
    done
    if [ "${have}" -eq 0 ]; then
        fail "V ${SORADIR} net nichego kopirovat"
        exit 1
    fi

    target="${BACKUP}/sora-${STAMP}"
    install -d -m 700 "${target}"

    copied=0
    for f in ${FILES}; do
        if [ -f "${SORADIR}/${f}" ]; then
            if cp -p "${SORADIR}/${f}" "${target}/${f}" 2>/dev/null; then
                chmod 600 "${target}/${f}"
                copied=$((copied + 1))
            fi
        fi
    done

    if [ "${copied}" -eq 0 ]; then
        rmdir "${target}" 2>/dev/null
        fail "Ne udalos skopirovat ni odin fayl"
        exit 1
    fi

    # Манифест: без него через полгода не разберёшься, какая копия
    # от какого дня и что внутри.
    {
        echo "SORA backup"
        echo "sozdana:     $(date '+%Y-%m-%d %H:%M:%S')"
        echo "server:      $(hostname)"
        echo "versiya:     1"
        echo "faylov:      ${copied}"
        echo "soderzhimoe: $(ls -1 "${target}" | tr '\n' ' ')"
        echo ""
        echo "VNIMANIE: etot katalog soderzhit PRIVATNYE KLYUCHI"
        echo "vseh polzovateley. Ego nelzya peredavat drugim lyudyam"
        echo "i nelzya kladyt v oblako."
    } > "${target}/MANIFEST"
    chmod 600 "${target}/MANIFEST"

    good "kopiya sozdana: ${target}"
    info "faylov: ${copied}, prava 600, katalog 700"

    # Сразу проверяем, что копию читается. Копия, которую нельзя
    # прочитать, хуже отсутствия копии: она создаёт ложное спокойствие.
    if [ -f "${target}/server.conf" ]; then
        if [ -s "${target}/server.conf" ] && \
           grep -q "PrivateKey" "${target}/server.conf"; then
            good "proverka: kopita chitaetsya i soderzhit klyuch"
        else
            warn "proverka ne proshla: kopita pusta ili bez klyucha"
        fi
    fi

    cleanup_old
}

# =====================================================================
#  Показать копии
# =====================================================================
show_list() {
    if [ ! -d "${BACKUP}" ]; then
        info "Kopiy poka net"
        exit 0
    fi
    echo
    echo "=================================================="
    echo "  KOPIHI: ${BACKUP}"
    echo "=================================================="
    echo
    printf "  %-32s %8s  %s\n" "KOPIYA" "RAZMER" "FAJLOV"
    printf "  %s\n" "------------------------------------------------"
    for d in "${BACKUP}"/sora-*; do
        if [ -d "${d}" ]; then
            size=$(du -sh "${d}" 2>/dev/null | cut -f1)
            n=$(ls -1 "${d}" 2>/dev/null | grep -v MANIFEST | wc -l)
            printf "  %-32s %8s  %s\n" "$(basename "${d}")" "${size}" "${n}"
        fi
    done
    echo
    echo "  Vsego: $(ls -1d "${BACKUP}"/sora-* 2>/dev/null | wc -l)"
    echo "  Ostanetsya maksimalno: ${KEEP}"
    echo
    echo "${GREY}  V kopiy lezhat privatnye klyuchi. Ne peredavat, ne v oblako.${RESET}"
    echo
}

# =====================================================================
#  Вернуть из копии
# =====================================================================
restore() {
    src="$1"

    if [ -z "${src}" ]; then
        fail "Ukazhite kopiyu:"
        info "  bash sora_backup.sh restore /var/backups/sora/sora-20261015-120000"
        exit 1
    fi
    if [ ! -d "${src}" ]; then
        fail "Net kataloga: ${src}"
        exit 1
    fi

    echo
    echo "${YELLOW}  Eto zamenit tekwshchie faily v ${SORADIR}:${RESET}"
    ls -1 "${src}" 2>/dev/null | grep -v MANIFEST | sed 's/^/      /'
    echo
    echo "${GREY}  Sluzhba VPN budet perezagruzena.${RESET}"
    echo
    printf "  Prodolzhit? (yes/NO) "
    read -r ANSWER
    case "${ANSWER}" in
        yes|YES|Yes|y|Y) ;;
        *) echo "Otmeneno."; exit 0 ;;
    esac

    # Текущее состояние — в отдельную копию. Откат должен быть
    # обратим: иначе второй откат уже некуда будет делать.
    if [ -f "${SORADIR}/server.conf" ]; then
        safety="${BACKUP}/sora-${STAMP}-before-restore"
        install -d -m 700 "${safety}"
        cp -p "${SORADIR}/server.conf" "${safety}/" 2>/dev/null
        info "tekushchee sostoyanie sohraneno: ${safety}"
    fi

    done=0
    for f in ${FILES}; do
        if [ -f "${src}/${f}" ]; then
            if cp -p "${src}/${f}" "${SORADIR}/${f}" 2>/dev/null; then
                chmod 600 "${SORADIR}/${f}" 2>/dev/null
                good "vosstanovlen ${f}"
                done=$((done + 1))
            else
                warn "NE udalos vosstanovit ${f}"
            fi
        fi
    done

    if [ "${done}" -eq 0 ]; then
        fail "Ne vosstanovlen ni odin fayl"
        exit 1
    fi

    if systemctl restart amnezia-awg-go 2>/dev/null; then
        good "VPN perezagruzhen"
    else
        warn "VPN ne perezagruzilsya, proverte zhurnal"
    fi

    echo
}

# =====================================================================
case "${1:-}" in
    ""|create|создать)
        create
        ;;
    list|список)
        show_list
        ;;
    restore|вернуть)
        if [ $# -lt 2 ]; then
            fail "Nuzhno imya kopii"
            exit 1
        fi
        restore "$2"
        ;;
    cleanup|чистить)
        cleanup_old
        good "starie kopii udaleny"
        ;;
    *)
        fail "Neznayaznaya komanda: $1"
        info "Dostupno: create, list, restore <papka>, cleanup"
        exit 1
        ;;
esac
