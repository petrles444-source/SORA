#!/bin/bash
# =====================================================================
#  SORA - ЗАКРЫТЬ ПОРТ
#
#  Откат одного порта, открытого через sora-open-port.sh.
#  Всю систему целиком откатывает uninstall_sora.sh — это другое.
#
#  ЗАПУСК от root:
#     bash sora-close-port.sh 443
#     bash sora-close-port.sh 443 tcp
# =====================================================================
set -uo pipefail

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'; RESET=$'\033[0m'
good() { echo "${GREEN}  [ok]${RESET} $*"; }
warn() { echo "${YELLOW}  [!]${RESET}  $*"; }
fail() { echo "${RED}  [ERROR]${RESET} $*"; }

if [ "$(id -u)" -ne 0 ]; then
    fail "Nuzhen root"
    exit 1
fi

if [ $# -lt 1 ]; then
    fail "Ispolzovanie: bash sora-close-port.sh <port> [tcp|udp]"
    exit 1
fi

PORT="$1"
PROTO="${2:-tcp}"

case "${PROTO}" in
    tcp|udp) ;;
    *) fail "Protocol tolko tcp ili udp"; exit 1 ;;
esac

if ! iptables -C INPUT -p "${PROTO}" --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    warn "Port ${PORT}/${PROTO} i tak ne otkryt"
    exit 0
fi

# Правило могло попасть в таблицу несколько раз — удаляем все вхождения.
REMOVED=0
while iptables -C INPUT -p "${PROTO}" --dport "${PORT}" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p "${PROTO}" --dport "${PORT}" -j ACCEPT || break
    REMOVED=$((REMOVED + 1))
done

if [ "${REMOVED}" -eq 0 ]; then
    fail "Ne udalos udalit pravilo dlya ${PORT}/${PROTO}"
    exit 1
fi

good "zakryt ${PORT}/${PROTO} (udaleno pravil: ${REMOVED})"

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 \
        && good "pravila sohraneny"
else
    warn "netfilter-persistent ne stoit — posle perezagruzki port otkroyetsya snova"
fi
