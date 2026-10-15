#!/bin/bash
# =====================================================================
#  SORA - PROVERKA SOSTOYANIYA
#
#  Pokazyvaet, rabotaet li VPN, skolko pamyati on yest i glavnoe -
#  ne vytesnil li on treker.
#
#  ZAPUSK:
#     bash sora-health.sh            polnyy otchet
#     bash sora-health.sh --tiho     tolko problemy (dlya taimera)
#
#  KOD VOZVRATA: 0 - vse v poryadke, 1 - est problemy
#
#  Vse imena peremennykh - latinitsey. Bash ne prinimaet kirillitsu
#  v imenakh peremennykh: poluchitsya "bad substitution" pri zapuske.
#  Eto provereno realnym zapuskom, ne tolko cherez "bash -n".
# =====================================================================
set -uo pipefail

PORT="${SORA_PORT:-39117}"
NETWORK="${SORA_NET:-10.77.0.0/24}"
IFACE="${SORA_IFACE:-auto}"
TIH=0
PROBLEMS=0
FAILED=0

for ARG in "$@"; do
    case "${ARG}" in
        --tiho|--quiet) TIH=1 ;;
        *) echo "neizvestnyi argument: ${ARG}" >&2; exit 2 ;;
    esac
done

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; RESET=$'\033[0m'

good()  { [ "${TIH}" -eq 1 ] || echo "${GREEN}  [ok]${RESET} $*"; }
warn()  { [ "${TIH}" -eq 1 ] || echo "${YELLOW}  [!]${RESET}  $*"; }
fail()  { echo "${RED}  [!!]${RESET} $*"; PROBLEMS=$((PROBLEMS + 1)); }
info()  { [ "${TIH}" -eq 1 ] || echo "${GREY}       $*${RESET}"; }
razdel(){ [ "${TIH}" -eq 1 ] || { echo; echo "-- $* --"; }; }

# Ошибки команд не должны обрывать проверку.
# Первая версия ставила set -e, и на машине без `free` скрипт падал
# целиком вместо того, чтобы показать остальные результаты.
FAILED_ISH=0

# ═════════════════════════════════════════════════════════════
if [ "${TIH}" -eq 0 ]; then
    echo
    echo "=============== SORA: SOSTOYANIE ==============="
    echo " $(date '+%d.%m.%Y %H:%M:%S')"
    echo "================================================"
fi

# ── 1. VPN ─────────────────────────────────────────────────────
razdel "VPN"

if systemctl is-active --quiet amnezia-awg-go 2>/dev/null; then
    good "sluzhba rabotaet"
else
    fail "sluzhba NE rabotaet"
    journalctl -u amnezia-awg-go -n 8 --no-pager 2>/dev/null \
        | sed 's/^/        /'
fi

if ss -lun 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
    good "port ${PORT} slushaetsya"
else
    fail "port ${PORT} NE slushaetsya"
fi

MEM_PID=$(systemctl show -p MainPID --value amnezia-awg-go 2>/dev/null)
if [ -n "${MEM_PID}" ] && [ "${MEM_PID}" != "0" ] \
        && [ -r "/proc/${MEM_PID}/status" ]; then
    RSS_KB=$(awk '/VmRSS/{print $2}' "/proc/${MEM_PID}/status" 2>/dev/null || echo 0)
    RSS=$(( RSS_KB / 1024 ))
    LIMIT=$(systemctl show -p MemoryMax --value amnezia-awg-go 2>/dev/null)
    if [ -n "${LIMIT}" ] && [ "${LIMIT}" != "infinity" ] \
            && [ "${LIMIT}" -gt 0 ] 2>/dev/null; then
        LIMIT_MB=$(( LIMIT / 1024 / 1024 ))
        if [ "${RSS}" -gt "${LIMIT_MB}" ]; then
            fail "protsess est ${RSS} MB, potolok ${LIMIT_MB} MB"
        else
            good "protsess est ${RSS} MB iz ${LIMIT_MB} MB"
        fi
    else
        good "protsess est ${RSS} MB (potolok ne zadan)"
    fi
fi

if command -v wg >/dev/null 2>&1; then
    LINKS=$(wg show 2>/dev/null | grep -c 'latest handshake' || true)
    [ -n "${LINKS}" ] && good "aktivnyh podklyucheniy: ${LINKS}"
fi

# ── 2. DNS ─────────────────────────────────────────────────────
razdel "DNS vnutri tunnelya"

if systemctl is-active --quiet unbound 2>/dev/null; then
    good "unbound rabotaet"
else
    fail "unbound NE rabotaet - DNS ukodet mimo tunnelya"
fi

# unbound sluchaet tolko na 10.77.0.1, poetomu obshchiy grep po portu 53
# byl by nepravilnym: on lovit lyubyy DNS na servere, v tom chuzhoy.
if ss -lun 2>/dev/null | grep -qE "10\.77\.0\.1:53[[:space:]]"; then
    good "rezolver slushaet 10.77.0.1:53"
else
    fail "rezolver ne slushaet na 10.77.0.1:53"
fi

# ── 3. Resursy ─────────────────────────────────────────────────
razdel "Resursy servera"

if command -v free >/dev/null 2>&1; then
    TOTAL=$(free -m | awk '/Mem:/{print $2}')
    USED=$(free -m  | awk '/Mem:/{print $3}')
    AVAIL=$(free -m | awk '/Mem:/{print $7}')
    SWAP=$(free -m  | awk '/Swap:/{print $3}')
    good "pamyat: ${USED} iz ${TOTAL} MB zanyato, dostupno ${AVAIL} MB"
    if [ "${AVAIL}" -lt 100 ]; then
        fail "dostupno menshe 100 MB - serveru ne hvatit"
    fi
    if [ "${SWAP}" -gt 150 ]; then
        fail "podkachka rastyet (${SWAP} MB) - ne xvatit pamyati"
    else
        good "podkachka pochti ne ispolzuetsya (${SWAP} MB)"
    fi
else
    info "free nedostupen (ne Linux?)"
fi

DISK=$(df -m / 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "${DISK}" ]; then
    good "disk: svobodno ${DISK} MB"
    if [ "${DISK}" -lt 1500 ]; then
        fail "na diske menshe 1.5 GB - provente logi"
    fi
fi

# ── 4. Treker i prochie sluzhby ───────────────────────────────
# Server chistyy, krome trackera. Zdesy vazhno ne "sluzhba upala",
# a "sluzhba propala": nazvanie zdes dolzno byt nastraivaemym.
razdel "Treker i prochie sluzhby"

if [ -f /etc/sora/tracker.services ]; then
    while read -r SVC; do
        [ -z "${SVC}" ] && continue
        case "${SVC}" in \#*) continue ;; esac
        STATE=$(systemctl is-active "${SVC}" 2>/dev/null || echo net)
        if [ "${STATE}" = "active" ]; then
            good "${SVC} rabotaet"
        else
            fail "${SVC} - ${STATE}"
        fi
    done < /etc/sora/tracker.services
else
    info "fajla /etc/sora/tracker.services net - proverka trekerow otklyuchena"
    info "sozdat ego, kogda budet treker:  echo treker > /etc/sora/tracker.services"
fi

# ── 5. Pravila seti ────────────────────────────────────────────
razdel "Pravila seti"

if iptables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    good "port ${PORT} otkryt"
else
    fail "pravila na port ${PORT} net"
fi

if [ "${IFACE}" = "auto" ]; then
    IFACE=$(ip -o route get 1.1.1.1 2>/dev/null \
            | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    IFACE="${IFACE:-eth0}"
fi

if iptables -t nat -C POSTROUTING -s "${NETWORK}" -o "${IFACE}" \
        -j MASQUERADE 2>/dev/null; then
    good "NAT dlya ${NETWORK} est"
else
    fail "NAT dlya ${NETWORK} net - trafik naruzhu ne poydyot"
fi

# Pravila dolzhny perezhivat perezagruzku, inache posle nee VPN umryot.
#
# БЫЛ БАГ: проверялось наличие /etc/network/interfaces.d/50-sora.
# Такого файла установщик не создаёт — он пользуется
# netfilter-persistent. Проверка всегда ругалась, даже когда
# правила сохранены и работают. На живом сервере:
#     [!] pravila seti ne sohraneny na perezagruzku
# притом что selftest в это же время отвечал
#     [ok] pravila sohraneny i perezhivut perezagruzku
#
# То есть два инструмента говорили противоположное об одном и том же.
#
# Теперь проверяем то, что действительно нужно: есть ли пакет,
# включён ли он и лежит ли файл правил с нашими цепочками.
if command -v netfilter-persistent >/dev/null 2>&1 \
   && [ -f /etc/iptables/rules.v4 ] \
   && grep -q "SORA" /etc/iptables/rules.v4 2>/dev/null; then
    good "pravila sohraneny: /etc/iptables/rules.v4"
    info "sluzhba: $(systemctl is-enabled netfilter-persistent 2>&1)"
elif [ -f /etc/network/interfaces.d/50-sora ]; then
    info "pravila sohraneny v /etc/network/interfaces.d/50-sora"
else
    warn "pravila seti ne sohraneny na perezagruzku."
    warn "Posle perezagruzki VPN ne zapustitsya. Postavit: apt install netfilter-persistent"
fi

# ── 6. Itog ────────────────────────────────────────────────────
if [ "${TIH}" -eq 0 ]; then
    echo
    echo "================================================"
    if [ "${PROBLEMS}" -eq 0 ]; then
        echo "${GREEN}  Vse v poryadke.${RESET}"
    else
        echo "${RED}  Problem: ${PROBLEMS}${RESET}"
        echo "  Esli treker zanyal - otkayvaytes NEMEDLENNO:"
        echo "      bash /путь/к/uninstall_sora.sh"
    fi
    echo "================================================"
    echo
fi

if [ "${PROBLEMS}" -eq 0 ]; then exit 0; else exit 1; fi
