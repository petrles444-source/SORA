#!/bin/bash
# =====================================================================
#  SORA - OТКРЫТЬ ПОРТ ДЛЯ ТРЕКЕРА
#
#  Когда на сервере появится трекер сайтов, ему понадобятся порты.
#  Не правьте iptables руками: правило забудется при перезагрузке.
#  Этот скрипт добавляет порт И СОХРАНЯЕТ правила, чтобы они пережили
#  перезапуск.
#
#  ЗАПУСК от root:
#     bash sora-open-port.sh 443
#     bash sora-open-port.sh 443 tcp
#     bash sora-open-port.sh 8443 tcp "treker-metriki"
#
#  ЗАКРЫТЬ ПОРТ:
#     bash sora-close-port.sh 443
#
#  ВАЖНО ПРО БЕЗОПАСНОСТЬ:
#  Каждый открытый порт — это вход в сервер. Открывать нужно только
#  то, что действительно должно быть видно снаружи. Трекеру для
#  сбора данных нужен исходящий трафик (подключение к сайтам), а не
#  входящий: порт трекеру НЕ НУЖЕН, если только вы не делаете
#  публичную страницу со статистикой.
# =====================================================================
set -uo pipefail

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; RESET=$'\033[0m'

good() { echo "${GREEN}  [ok]${RESET} $*"; }
warn() { echo "${YELLOW}  [!]${RESET}  $*"; }
fail() { echo "${RED}  [ERROR]${RESET} $*"; }
info() { echo "${GREY}      $*${RESET}"; }

if [ "$(id -u)" -ne 0 ]; then
    fail "Nuzhen root"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo
    echo "  Ispolzovanie:"
    echo "     bash sora-open-port.sh <port> [tcp|udp] [kommentariy]"
    echo
    echo "  Primer:"
    echo "     bash sora-open-port.sh 443 tcp 'treker — publichnyy sayt'"
    echo
    exit 1
fi

PORT="$1"
PROTO="${2:-tcp}"
COMMENT="${3:-}"

if ! echo "${PORT}" | grep -qE '^[0-9]+$'; then
    fail "Port dolzhen byt chiselom. Poluchili: '${PORT}'"
    exit 1
fi

if [ "${PORT}" -lt 1 ] || [ "${PORT}" -gt 65535 ]; then
    fail "Port vne diapazona 1..65535"
    exit 1
fi

case "${PROTO}" in
    tcp|udp) ;;
    *) fail "Protocol tolko tcp ili udp. Poluchili: '${PROTO}'"; exit 1 ;;
esac

# ── Уже открыт? ────────────────────────────────────────────────
if iptables -C INPUT -p "${PROTO}" --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    warn "Port ${PORT}/${PROTO} uzhe otkryt. Nichego ne menyayu."
    exit 0
fi

# ── Конфликт с VPN? ────────────────────────────────────────────
if [ "${PORT}" = "39117" ] && [ "${PROTO}" = "udp" ]; then
    fail "Etot port zanyat VPN. Vzyat drugoy."
    exit 1
fi

# ── Открываем ──────────────────────────────────────────────────
if [ "${PROTO}" = "tcp" ]; then
    if [ -n "${COMMENT}" ]; then
        iptables -A INPUT -p tcp --dport "${PORT}" -j ACCEPT \
            -m comment --comment "sora:${COMMENT}"
    else
        iptables -A INPUT -p tcp --dport "${PORT}" -j ACCEPT
    fi
else
    if [ -n "${COMMENT}" ]; then
        iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT \
            -m comment --comment "sora:${COMMENT}"
    else
        iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT
    fi
fi

if [ $? -ne 0 ]; then
    fail "Ne udalos dobavit pravilo"
    exit 1
fi
good "otkryt ${PORT}/${PROTO}${COMMENT:+  (${COMMENT})}"

# ── Сохраняем, чтобы пережило перезагрузку ──────────────────────
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 \
        && good "pravila sohraneny (perezhivut perezagruzku)" \
        || warn "sohranenie ne udalos"
else
    warn "netfilter-persistent ne stoit — posle perezagruzki port zakroyetsya"
    warn "Postavit:  apt install -y netfilter-persistent"
fi

echo
echo "  Otkat etogo poroda:   bash sora-close-port.sh ${PORT}"
echo
