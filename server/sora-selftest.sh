#!/bin/bash
# =====================================================================
#  SORA - SAMOPROVERKA POSLE USTANOVKI
#
#  CHTO DELAET I CHEMY OTLICHAETSYA OT sora-health.sh
#  ------------------------------------------------------
#  sora-health.sh smotrit na SOSTOYANIE: zhiv li VPN, est li mestо.
#  Etoт skript smotrit na PAVILNOST ustanovki: nalogi po vsemu
#  sostavu, a ne tolko "chto-to rabotaet".
#
#  Raznica vazhna. Ustanovka mozhet zakonchitsya kodom 0, vsyo
#  zelenoe, a schetchiki trafika ne ustanovilis i mesyats trafik
#  budet molchat. Sluzhba budet "zdorova", lyudi budut
#  podklyuchatsya, a denegi — ne schitatsya.
#
#  ZAPUSK ot root:
#     bash sora-selftest.sh            polnyy otchet
#     bash sora-selftest.sh --tiho     tolko problemy (dlya CI)
#
#  KOD VOZVRATA:
#     0 - vsyo pravilno
#     1 - est problemy ustanovki
#     2 - proverku nevozmozhno vypolnit
#
#  VSE IMENA PEREMENNYKH - LATINTSEY (inache "bad substitution").
# =====================================================================
set -uo pipefail

SORADIR="/etc/sora"
PORT="${SORA_PORT:-39117}"
NETWORK="${SORA_NET:-10.77.0.0/24}"
VAR="/var/lib/sora"

TIH=0
FAILED=0
SKIPPED=0
PASSED=0

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; BLUE=$'\033[96m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

for A in "$@"; do
    case "${A}" in
        --tiho|--quiet) TIH=1 ;;
    esac
done

say()   { [ "${TIH}" -eq 1 ] || echo "${GREY}      $*${RESET}"; }
ok()    { PASSED=$((PASSED + 1)); [ "${TIH}" -eq 1 ] || echo "${GREEN}  [ok]${RESET} $*"; }
bad()   { FAILED=$((FAILED + 1)); echo "${RED}  [!!]${RESET} $*"; }
warn()  { [ "${TIH}" -eq 1 ] || echo "${YELLOW}  [!]${RESET}  $*"; }
skip()  { SKIPPED=$((SKIPPED + 1)); [ "${TIH}" -eq 1 ] || echo "${GREY}  [--]${RESET} $*"; }
head_() { [ "${TIH}" -eq 1 ] || echo; [ "${TIH}" -eq 1 ] || echo "${BOLD}$*${RESET}"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Нужен root${RESET}"
    exit 2
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 1. ФАЙЛЫ И ПРАВА ==="

# Конфигурация сервера
if [ -f "${SORADIR}/server.conf" ]; then
    ok "server.conf на месте"
    MODE=$(stat -c '%a' "${SORADIR}/server.conf" 2>/dev/null)
    if [ "${MODE}" = "600" ]; then
        ok "server.conf — права 600"
    else
        bad "server.conf — права ${MODE}, надо 600"
        say "  chmod 600 ${SORADIR}/server.conf"
    fi
    if grep -q "PrivateKey" "${SORADIR}/server.conf"; then
        ok "server.conf содержит ключ сервера"
    else
        bad "server.conf БЕЗ ключа сервера — не запустится"
    fi
else
    bad "нет ${SORADIR}/server.conf"
fi

# Секция Interface заполнена
if [ -f "${SORADIR}/server.conf" ]; then
    for field in Address ListenPort Jc Jmin Jmax S1 S2 H1 H2 H3 H4; do
        if ! grep -qE "^${field} *=" "${SORADIR}/server.conf"; then
            bad "в [Interface] нет поля ${field}"
        fi
    done
    ok "все поля [Interface] заполнены"
fi

# Есть ли хоть один пользователь
PEERS=$(grep -c "^\[Peer\]" "${SORADIR}/server.conf" 2>/dev/null || echo 0)
if [ "${PEERS}" -gt 0 ]; then
    ok "пользователей в конфиге: ${PEERS}"
else
    bad "в конфиге НИ ОДНОГО пользователя — подключиться некому"
    say "  На компьютере владельца: python sora_keys.py add <имя>"
fi

# Есть ли имя человека рядом с каждой секцией
NAMES=$(grep -c "^# --- " "${SORADIR}/server.conf" 2>/dev/null || echo 0)
if [ "${NAMES}" -ge "${PEERS}" ] && [ "${PEERS}" -gt 0 ]; then
    ok "у каждого пользователя есть имя (нужно для учёта)"
else
    bad "имена пользователей: ${NAMES}, а секций ${PEERS}"
    say "  Учёт трафика без имён не работает: он не знает, кому"
    say "  принадлежит трафик, и припишет его ничему."
fi

# Резервные копии
head_ "=== 2. РЕЗЕРВНОЕ КОПИРОВАНИЕ ==="
if [ -d /var/backups/sora ]; then
    BMODE=$(stat -c '%a' /var/backups/sora 2>/dev/null)
    if [ "${BMODE}" = "700" ]; then
        ok "каталог копий — права 700"
    else
        bad "каталог копий — права ${BMODE}, надо 700"
    fi
    COPIES=$(ls -1d /var/backups/sora/sora-* 2>/dev/null | wc -l)
    if [ "${COPIES}" -gt 0 ]; then
        ok "копий на диске: ${COPIES}"
        NEWEST=$(ls -1d /var/backups/sora/sora-* 2>/dev/null | tail -1)
        if [ -f "${NEWEST}/server.conf" ]; then
            CMODE=$(stat -c '%a' "${NEWEST}/server.conf" 2>/dev/null)
            if [ "${CMODE}" = "600" ]; then
                ok "копия ключей — права 600"
            else
                bad "копия ключей — права ${CMODE}, надо 600"
            fi
        else
            bad "в последней копии нет server.conf"
        fi
    else
        bad "копий нет ни одной. Потеря server.conf = потеря всех ключей."
        say "  sora_backup.sh"
    fi
else
    bad "нет каталога /var/backups/sora"
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 3. СЛУЖБЫ ==="

for SVC in amnezia-awg-go unbound; do
    if systemctl list-unit-files 2>/dev/null | grep -q "${SVC}.service"; then
        if systemctl is-active --quiet "${SVC}"; then
            ok "${SVC} работает"
        else
            STATE=$(systemctl is-active "${SVC}" 2>/dev/null || echo "?")
            bad "${SVC} — ${STATE}"
            say "  journalctl -u ${SVC} -n 20"
        fi
    else
        skip "${SVC} не установлен"
    fi
done

# Автоподъём
if systemctl list-unit-files 2>/dev/null | grep -q "amnezia-awg-go.service"; then
    RE=$(systemctl show -p Restart --value amnezia-awg-go 2>/dev/null)
    if [ "${RE}" = "on-failure" ] || [ "${RE}" = "always" ]; then
        ok "VPN поднимается сам: Restart=${RE}"
    else
        bad "VPN не поднимется сам: Restart=${RE}"
    fi

    ENABLED=$(systemctl is-enabled amnezia-awg-go 2>/dev/null || echo "?")
    if [ "${ENABLED}" = "enabled" ]; then
        ok "VPN стартует при загрузке"
    else
        bad "VPN не включён в автозапуск: ${ENABLED}"
        say "  systemctl enable amnezia-awg-go"
    fi
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 4. РЕСУРСЫ И ОГРАНИЧЕНИЯ ==="

if systemctl list-unit-files 2>/dev/null | grep -q "amnezia-awg-go.service"; then
    MEMMAX=$(systemctl show -p MemoryMax --value amnezia-awg-go 2>/dev/null)
    if [ "${MEMMAX}" = "infinity" ] || [ -z "${MEMMAX}" ]; then
        bad "потолка памяти нет — VPN может вытеснить трекер"
        say "  /etc/systemd/system/amnezia-awg-go.service.d/limits.conf"
    else
        MB=$(( MEMMAX / 1024 / 1024 ))
        ok "потолок памяти VPN: ${MB} МБ"
        if [ "${MB}" -gt 200 ]; then
            warn "потолок ${MB} МБ великоват для чистого сервера"
        fi
    fi

    NICE=$(systemctl show -p Nice --value amnezia-awg-go 2>/dev/null)
    if [ -n "${NICE}" ] && [ "${NICE}" != "0" ]; then
        ok "VPN уступает процессор: Nice=${NICE}"
    else
        warn "Nice=0 — VPN не уступает процессор трекеру"
    fi

    if systemctl show -p NoNewPrivileges --value amnezia-awg-go 2>/dev/null \
            | grep -q yes; then
        ok "защита NoNewPrivileges включена"
    else
        warn "NoNewPrivileges не включена"
    fi
fi

if command -v free >/dev/null 2>&1; then
    AVAIL=$(free -m | awk '/Mem:/{print $7}')
    if [ "${AVAIL}" -gt 200 ]; then
        ok "свободно памяти: ${AVAIL} МБ"
    else
        bad "свободно только ${AVAIL} МБ — серверу тесно"
    fi
    SWAP=$(free -m | awk '/Swap:/{print $3}')
    if [ "${SWAP}" -lt 100 ]; then
        ok "подкачка почти не используется: ${SWAP} МБ"
    else
        bad "подкачка растёт: ${SWAP} МБ — системе не хватает памяти"
    fi
else
    skip "free недоступна (не Linux?)"
fi

DISK=$(df -m / 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "${DISK}" ]; then
    if [ "${DISK}" -gt 1500 ]; then
        ok "свободно места: ${DISK} МБ"
    else
        bad "свободно ${DISK} МБ — мало"
    fi
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 5. СЕТЬ ==="

if iptables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    ok "порт ${PORT} открыт"
else
    bad "правила на порт ${PORT} нет — подключиться нельзя"
fi

FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
if [ "${FWD}" = "1" ]; then
    ok "пересылка пакетов включена"
else
    bad "net.ipv4.ip_forward = ${FWD} — трафик наружу не пойдёт"
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
    if [ -f /etc/iptables/rules.v4 ]; then
        ok "правила сохранены и переживут перезагрузку"
    else
        bad "netfilter-persistent стоит, но правил нет: netfilter-persistent save"
    fi
else
    bad "netfilter-persistent не установлен — после перезагрузки VPN не поднимется"
    say "  apt install -y netfilter-persistent && netfilter-persistent save"
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 6. УЧЁТ ТРАФИКА ==="

if command -v python3 >/dev/null 2>&1 && [ -f /usr/local/bin/sora_traffic.py ]; then
    ok "учёт трафика установлен"
else
    skip "учёт трафика не установлен (это не обязательно)"
fi

if command -v iptables >/dev/null 2>&1; then
    if iptables -t filter -L SORA-TRAFFIC -n >/dev/null 2>&1; then
        ok "цепочка счётчиков создана"
        RULES=$(iptables -t filter -L SORA-TRAFFIC -n 2>/dev/null | grep -c ACCEPT)
        if [ "${RULES}" -gt 0 ]; then
            ok "счётчиков на пользователей: ${RULES}"
            if [ "${RULES}" -lt "${PEERS}" ]; then
                bad "счётчиков ${RULES}, а пользователей ${PEERS}"
                say "  Запустите: sora_traffic.py poll"
            fi
        else
            bad "цепочка есть, но ни одного счётчика"
            say "  Запустите: sora_traffic.py poll"
        fi
    else
        bad "цепочки счётчиков SORA-TRAFFIC нет — трафик не считается"
        say "  sora_traffic.py poll"
    fi
else
    skip "iptables нет, счётчики не проверяем"
fi

if [ -f "${VAR}/traffic.json" ]; then
    ok "состояние счёта существует"
else
    warn "счёта ещё нет — это нормально в первые сутки"
fi

if [ -d "${VAR}/history" ]; then
    MONTHS=$(ls -1 "${VAR}/history" 2>/dev/null | wc -l)
    ok "помесячная история: ${MONTHS} файл(ов)"
else
    warn "нет ${VAR}/history — история месяцев не сохраняется"
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 7. АВТОМАТИКА ==="

if [ -f /etc/cron.d/sora ]; then
    ok "/etc/cron.d/sora на месте"
    for needle in "sora_traffic.py poll" "sora_backup.sh" "sora-health.sh"; do
        if grep -q "${needle}" /etc/cron.d/sora; then
            ok "задача есть: ${needle}"
        else
            bad "нет задачи: ${needle}"
        fi
    done
else
    bad "нет /etc/cron.d/sora — автоматика не работает"
    say "  Переустановите: bash install_sora.sh"
fi

# ─────────────────────────────────────────────────────────────
head_ "=== 8. ТРЕКЕР НЕ ПОСТРАДАЛ ==="

if [ -f "${SORADIR}/tracker.services" ]; then
    while read -r SVC; do
        [ -z "${SVC}" ] && continue
        case "${SVC}" in \#*) continue ;; esac
        STATE=$(systemctl is-active "${SVC}" 2>/dev/null || echo net)
        if [ "${STATE}" = "active" ]; then
            ok "${SVC} работает"
        else
            bad "${SVC} — ${STATE}"
        fi
    done < "${SORADIR}/tracker.services"
else
    skip "нет ${SORADIR}/tracker.services — трекер не отслеживается"
    say "  echo treker > ${SORADIR}/tracker.services"
fi

RUNNING=$(systemctl list-units --type=service --state=running \
          --no-pager --plain 2>/dev/null | wc -l)
ok "всего работающих служб: ${RUNNING}"

# ── Кириллица в идентификаторах ──────────────────────────────────
# Проверка не косметическая. За день установки на живом сервере
# кириллица в именах переменных всплыла три раза: в bash-скрипте,
# в awk и в функции, которая должна была читать stdin.
#
# Опаснее всего то, что `bash -n` такой код ПРОПУСКАЕТ: он
# проверяет синтаксис и не разрешает переменные. Скрипт с
# кириллицей проходит проверку и падает только в рантайме.
#
# Поэтому ищем явно, а не доверяем `bash -n`.
#
# Имена переменных НИЖЕ — латиницей. Это не украшение: первая
# версия этой же проверки была написана с русскими именами
# found/цикл и поймала бы саму себя.
for f in /root/sora/server/*.sh; do
    [ -f "$f" ] || continue
    ASSIGN=$(grep -nE '^[[:space:]]*[а-яА-Я_]+[[:space:]]*=' "$f" 2>/dev/null | head -3)
    FORVAR=$(grep -nE 'for[[:space:]]+[а-яА-Я_]+[[:space:]]+in' "$f" 2>/dev/null | head -2)
    if [ -n "${ASSIGN}${FORVAR}" ]; then
        bad "кириллица в идентификаторах: $(basename "$f")"
        printf '%s\n' "${ASSIGN}${FORVAR}" | head -4 | sed 's/^/      /'
    fi
done
if ! grep -nE '^[[:space:]]*[а-яА-Я_]+[[:space:]]*=' /root/sora/server/*.sh >/dev/null 2>&1; then
    ok "во всех скриптах идентификаторы латиницей"
else
    bad "кириллица в идентификаторах — см. выше"
fi

# ═════════════════════════════════════════════════════════════
if [ "${TIH}" -eq 0 ]; then
    echo
    echo "════════════════════════════════════════════════════"
    echo "  ПРОВЕРЕНО ${PASSED}    ${GREEN}ок ${PASSED}${RESET}    ${RED}ошибок ${FAILED}${RESET}    ${GREY}пропущено ${SKIPPED}${RESET}"
    echo "════════════════════════════════════════════════════"
    echo
fi

if [ "${FAILED}" -gt 0 ]; then
    echo "${RED}  Установка неполная.${RESET}"
    echo "${YELLOW}  VPN может работать, но что-то не работает как задумано.${RESET}"
    echo "${GREY}  Перезапустите установку: bash install_sora.sh${RESET}"
    echo
    exit 1
fi

exit 0
