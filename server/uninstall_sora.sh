#!/bin/bash
# =====================================================================
#  SORA - POLNYI OTKAT
#
#  Ubiraet VPN i vozvrashchaet server v sostoyanie do ustanovki.
#  Treker i prochie sluzhby ne trogayet.
#
#  POSLE OTKATA SORA NE RABOTAET. Esli prigoditsya snova -
#  install_sora.sh zanovo.
#
#  ZAPUSK ot root:
#     bash uninstall_sora.sh
#
#  Vse imena peremennykh - latinitsey (inache "bad substitution").
# =====================================================================
set -uo pipefail

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; RESET=$'\033[0m'

step() { echo; echo "=== $* ==="; }
good() { echo "${GREEN}  [ok]${RESET} $*"; }
warn() { echo "${YELLOW}  [!]${RESET}  $*"; }
fail() { echo "${RED}  [ERROR]${RESET} $*"; }
info() { echo "${GREY}      $*${RESET}"; }

if [ "$(id -u)" -ne 0 ]; then
    fail "Nuzhen root"
    exit 1
fi

HAVE_SNAPSHOT=no
if [ -f /etc/sora/iptables.before ]; then
    have_snapshot_ok=yes
    HAVE_SNAPSHOT=yes
    good "snimok pravil seti est"
else
    warn "snimka pravil net"
fi

# Что откатываем — перечислить ДО согласия пользователя.
step "0. Sostoyanie"

if systemctl list-unit-files 2>/dev/null | grep -q amnezia-awg-go.service; then
    good "SORA ustanovlen"
else
    warn "sluzhby SORA ne naydeno — mozhet byt, uzhe otkatili"
fi

if [ -d /etc/sora ]; then
    good "katalog /etc/sora est"
else
    warn "kataloga /etc/sora net"
fi

echo
echo "${YELLOW}  Budet vypolneno:${RESET}"
echo "    - ostanovleny sluzhby amnezia-awg-go i sora-health.timer"
echo "    - vosstanovleny pravila seti iz snimka (esli on est)"
echo "    - udaleny yunit-fayly, konfiguratsiya i binary"
echo "    - udalen /etc/cron.d/sora (inache budet iskat udalyonnye fayly)"
echo "    - udaleny vse utility v /usr/local/bin"
echo "    - otklyuchen net.ipv4.ip_forward"
echo "    - udalen /etc/sora"
echo "    - istoriya trafika v /var/lib/sora OSTAETSYA (ruchnaya udacha)"
echo
echo "${GREY}  Treker i prochie sluzhby NE trogayutsya.${RESET}"
echo
printf "  Prodolzhit? (yes/NO) "
read -r ANSWER
case "${ANSWER}" in
    yes|YES|Yes|y|Y) ;;
    *) echo "Otmeneno."; exit 0 ;;
esac

# ─────────────────────────────────────────────────────────────
# ПОРЯДОК ВАЖЕН.
# Снимок сети читается ДО удаления /etc/sora — иначе восстанавливать
# будет нечего. В первой версии скрипта iptables-save стоял ПОСЛЕ
# rm -rf /etc/sora, и откат сети был невозможен в принципе.
# ─────────────────────────────────────────────────────────────
step "1. Snimok seti (DO udaleniya kataloga)"

if [ "${HAVE_SNAPSHOT}" = "yes" ]; then
    cp /etc/sora/iptables.before /tmp/ipt.sora.before
    good "snimok sohranen v /tmp/ipt.sora.before"
else
    warn "snimka net. Pravila SORA ostanutsya v iptables."
    info "Ubrat rukami:"
    info "  iptables -D INPUT -p udp --dport 39117 -j ACCEPT"
    info "  iptables -t nat -D POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE"
fi

step "2. Ostanovka sluzhb"

systemctl disable --now amnezia-awg-go 2>/dev/null \
    && good "VPN ostanovlen" || info "VPN ne byl zapushchen"

systemctl disable --now sora-health.timer 2>/dev/null \
    && good "timer proverki ostanovlen" || info "timer ne byl zapushchen"

systemctl disable --now sora-health.service 2>/dev/null || true

# unbound stavili dlya SORA. Esli on nastroyen na chto-то drugoe —
# ne trogayu. Inache chestno.
if [ -f /etc/sora/unbound.conf ] \
        && grep -q "10.77.0.1" /etc/sora/unbound.conf 2>/dev/null; then
    systemctl disable --now unbound 2>/dev/null \
        && good "unbound ostanovlen (on nash dlya SORA)" \
        || info "unbound ne byl zapushchen"
else
    warn "unbound nastroyen ne na SORA - NE TROGAYU"
fi

step "3. Vosstanovlenie seti"

if [ "${HAVE_SNAPSHOT}" = "yes" ]; then
    if iptables-restore < /tmp/ipt.sora.before 2>/dev/null; then
        good "pravila seti vosstanovleny iz snimka"
    else
        warn "iptables-restore ne srabotal - proverite rukami"
    fi
fi

step "4. Limity i parametry yadra"

rm -f /etc/systemd/system/amnezia-awg-go.service.d/limits.conf
rm -f /etc/sysctl.d/90-sora.conf
systemctl daemon-reload 2>/dev/null
sysctl --system >/dev/null 2>&1
FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")
info "ip_forward teper: ${FWD} (bylo 1 po ustanovke SORA)"
if [ -f /etc/sysctl.d/99-sora-cleanup.conf ]; then
    rm -f /etc/sysctl.d/99-sora-cleanup.conf
    sysctl --system >/dev/null 2>&1
    good "ip_forward vozvraschen v iskhodnoe sostoyanie"
else
    warn "esli ip_forward byl vam ne nuzhen — vyruchno ego:"
    warn "  sysctl -w net.ipv4.ip_forward=0"
    warn "  echo 'net.ipv4.ip_forward=0' > /etc/sysctl.d/99-sora-cleanup.conf"
fi

step "5. Udalenie faylov"

rm -f /etc/systemd/system/amnezia-awg-go.service \
      /etc/systemd/system/sora-health.service \
      /etc/systemd/system/sora-health.timer \
      /usr/local/bin/sora-health.sh
good "yunit-fayly udaleny"

# CRON. Bez etogo server budet kazhdye 5 minut pyatat fayly, kotorykh
# uzhe net: sora_traffic.py report v korn.yaml. Pri etom v zhurnale
# kazhdyy raz pishetsya oshibka, i realnaya polomka tonet v shume.
rm -f /etc/cron.d/sora
good "cron udalen"

rm -f /usr/local/bin/sora_traffic.py /usr/local/bin/sora_backup.sh \
      /usr/local/bin/sora-selftest.sh
good "uchet trafika i bakap udaleny"

# Dannie ucheta NE udalyayutsya: tam istoriya trafika za mesyatsy,
# po nej schitayutsya dengi. Arhiv mozno udalit rukuami pozhe.
if [ -d /var/lib/sora ]; then
    info "istoriya trafika sohranena v /var/lib/sora (${REDIRECT:-}udalenie ne avtomaticheskoe)"
fi

rm -f /usr/local/bin/amnezia-awg-go && good "binary VPN udalen" \
    || info "binarya ne bylo"

rm -f /etc/logrotate.d/sora && info "rotaciya logov udalena"

rm -rf /etc/sora && good "katalog /etc/sora udalen"

systemctl daemon-reload 2>/dev/null

step "6. Treker zhiv?"

if [ -f /etc/sora/tracker.services ]; then
    while read -r SVC; do
        [ -z "${SVC}" ] && continue
        STATE=$(systemctl is-active "${SVC}" 2>/dev/null || echo net)
        if [ "${STATE}" = "active" ]; then
            good "${SVC} rabotaet"
        else
            fail "${SVC} - ${STATE}"
        fi
    done < /etc/sora/tracker.services
else
    RUNNING=$(systemctl list-units --type=service --state=running \
              --no-pager --plain 2>/dev/null | wc -l)
    good "rabotayushchikh sluzhb: ${RUNNING} (spisok ne sohranen)"
fi

step "7. Resursy"

if command -v free >/dev/null 2>&1; then
    AVAIL=$(free -m | awk '/Mem:/{print $7}')
    good "svobodno pamyati: ${AVAIL} MB"
fi

step "GOTOVO"
echo
echo "${GREEN}  Otkat zavershen.${RESET}"
echo
echo "  Treker ne tronut. SORA net."
echo "  Esli prigoditsya snova:  bash install_sora.sh"
echo
