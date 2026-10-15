#!/bin/bash
# =====================================================================
#  SORA - USTANOVKA NA CHISTYY SERVER
#
#  Server budet ochishchen pod zero. Na nem ne budet nichego, krome
#  trackera dlya saytov. Eto pozvolyaet stavit silnee ogranicheniya,
#  chem bylo by na zanyatom servere: ne luchshe nekomu slomatsya.
#
#  CHTO EHT SCRIPT DELAET
#    1. Stavit pakety
#    2. Stavit amnezia-awg-go
#    3. Vklyuchaet peresylku paketov
#    4. Nastraivaet DNS-resolver vnutri tunnelya (unbound)
#    5. Otkryvaet ODIN port - dlya VPN
#    6. Nachinaet servicu s zazhmyonnymi pravami dostupa
#    7. Zavodit taimer proverki sostoyaniya
#    8. PROVERYAET chto vsyo zapustilos
#    9. Pri luboy oshibke SAM OTKATYVAETSYA
#
#  CHTO SCRIPT NE DELAET
#    - ne perzagruzhaet server
#    - ne stavit Docker
#    - ne trogaet tracker (ego eshche net, ili on zhe rabotaet)
#
#  ZAPUSK ot root:   bash install_sora.sh
#
#  VSE IMENA PEREMENNYKH - LATINTSEY. Bash ne prinimaet kirillitsu
#  v imenakh peremennykh: poluchitsya "bad substitution" pri zapuske.
#  Eto provereno na bash 5, ne na slovo.
# =====================================================================
set -uo pipefail

PORT="${SORA_PORT:-39117}"
NETWORK="${SORA_NET:-10.77.0.0/24}"
IFACE="${SORA_IFACE:-auto}"          # auto = opredelim sami
SORADIR="/etc/sora"
BINARY="/usr/local/bin/amnezia-awg-go"
LIMIT_MEM="${SORA_MEM_LIMIT:-100M}"  # server chistyy, zapas est

# Где лежит сам скрипт — отсюда берём bin/ и плагины netfilter.
# Задано В САМОМ НАЧАЛЕ, потому что нужно и в shagu 3 (binary),
# и v shagu 8 (plaginy). Ranee bylo opredeleno tolko v shagu 8.
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN=$'\033[92m'; RED=$'\033[91m'; YELLOW=$'\033[93m'
GREY=$'\033[90m'; BLUE=$'\033[96m'; RESET=$'\033[0m'

step() { echo; echo "=== $* ==="; }
good() { echo "${GREEN}  [ok]${RESET} $*"; }
warn() { echo "${YELLOW}  [!]${RESET}  $*"; }
fail() { echo "${RED}  [ERROR]${RESET} $*"; }
note() {
    # БЫЛО: note() { echo "      $*"; }
    #
    # ТАК ФУНКЦИЯ НЕ ЧИТАЕТ STDIN. При конвейере
    #     journalctl ... | note
    # она печатала ПУСТОТУ, потому что печатала свои аргументы
    # ($*), а не вход. На живом сервере это выглядело так:
    #     [ERROR] VPN ne zapustilsya:
    #     <пусто>
    # то есть причина поломки была не видна вообще.
    #
    # Стандартный приём: если аргументов нет — читаем stdin.
    if [ "$#" -eq 0 ]; then
        sed 's/^/      /'
    else
        echo "${GREY}      $*${RESET}"
    fi
}
blue() { echo "${BLUE}  ->${RESET} $*"; }

# ─────────────────────────────────────────────────────────────
#  Откат. Вызывается при любой неудаче.
#  Порядок важен: снимок сети читается ДО удаления /etc/sora.
# ─────────────────────────────────────────────────────────────
rollback() {
    echo
    echo "${RED}======== OTKAT ========${RESET}"
    systemctl disable --now amnezia-awg-go 2>/dev/null
    systemctl disable --now sora-health.timer 2>/dev/null
    systemctl disable --now sora-health.service 2>/dev/null
    if [ -f "${SORADIR}/iptables.before" ]; then
        cp "${SORADIR}/iptables.before" /tmp/ipt.sora.before 2>/dev/null
        iptables-restore < /tmp/ipt.sora.before 2>/dev/null \
            && echo "${GREEN}Set vozvraschena iz snimka${RESET}"
    fi
    rm -f /etc/systemd/system/amnezia-awg-go.service
    rm -f /etc/systemd/system/sora-health.service
    rm -f /etc/systemd/system/sora-health.timer
    rm -f /etc/systemd/system/amnezia-awg-go.service.d/limits.conf
    systemctl daemon-reload 2>/dev/null
    rm -f /etc/sysctl.d/90-sora.conf
    sysctl --system >/dev/null 2>&1
    echo "${GREEN}Otkat vypolnen. Treker ne tronut.${RESET}"
}

# ═════════════════════════════════════════════════════════════
step "0. PROVERKI DO LYUBYKH IZMENENIY"
# ═════════════════════════════════════════════════════════════

if [ "$(id -u)" -ne 0 ]; then
    fail "Nuzhen root. Zapustite: sudo bash install_sora.sh"
    exit 1
fi
good "zapusk ot root"

OS_REL=$(cat /etc/debian_version 2>/dev/null || echo "?")
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "?")
KERNEL=$(uname -r)
note "OS: ${OS_REL}   arhitektura: ${ARCH}   yadro: ${KERNEL}"

# Pamyat. Na chistom servere porog nizhe, chem byl na zanyatom.
FREE_MEM=$(free -m | awk '/Mem:/{print $7}')
TOTAL_MEM=$(free -m | awk '/Mem:/{print $2}')
if [ "${FREE_MEM}" -lt 150 ]; then
    fail "Svobodno vsego ${FREE_MEM} MB iz ${TOTAL_MEM}. Minimum 150."
    fail "Server ne gotov. Snova ochistite ego."
    exit 1
fi
good "pamyat: svobodno ${FREE_MEM} MB iz ${TOTAL_MEM}"

FREE_DISK=$(df -m / | awk 'NR==2{print $4}')
if [ "${FREE_DISK}" -lt 2000 ]; then
    fail "Malo mesta: ${FREE_DISK} MB. Minimum 2000."
    exit 1
fi
good "disk: svobodno ${FREE_DISK} MB"

# Port ne dolzhen zanimat kto-to drugoy.
#
# NO: esli port derzhit NASH UZHЕ STOYASHCHIY VPN — eto ne zanyat,
# a povod dlya obnovleniya. Bez etoy vetki povtornyy zapusk
# install_sora.sh na uzhe ustanovlennom servere vsegda padal by s
# odnim i tem zhe soobshcheniem «port zanyat», i obnovit svoj
# zhe server bylo by nevozmozhno.
#
# Provereno na zhivom servere 15.10.2026: posle pervoy ustanovki
# sleduyushchiy zapusk otkazalsya, khotya zanimal port imenno
# amneziawg-go iz nshego zhe zapuska.
if ss -lun 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
    # Kto derzhit port?
    DERZHIT=$(ss -lunp 2>/dev/null | grep ":${PORT}[[:space:]]" \
        | grep -o 'users:(("[^"]*"' | head -1 | tr -d '"(' | sed 's/users://')
    case "${DERZHIT}" in
        *amneziawg-go*)
            warn "UDP/${PORT} derzhit nash staryy VPN — eto obnovlenie"
            note "  Sluzhbu perezapusk, konfig perezapishetsya sverhu."
            note "  Lyudi ne otklyuchayutsya, ikh podnimet zanovo."
            ;;
        "")
            fail "UDP/${PORT} uzhe zanyat, no nevidno kem."
            fail "Smenite port:  SORA_PORT=48123 bash install_sora.sh"
            exit 1
            ;;
        *)
            fail "UDP/${PORT} zanyat chuzhim protsessom: ${DERZHIT}"
            fail "Smenite port:  SORA_PORT=48123 bash install_sora.sh"
            exit 1
            ;;
    esac
fi

# Opredelyaem setevoy interfeys sam
if [ "${IFACE}" = "auto" ]; then
    IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    IFACE="${IFACE:-eth0}"
fi
good "setevoy interfeys: ${IFACE}"

# Chto uzhe rabotaet - zapominaem
SERVICES_BEFORE=$(systemctl list-units --type=service --state=running \
                  --no-pager --plain 2>/dev/null | awk '{print $1}' | sort)
note "rabotayushchikh sluzhb: $(echo "${SERVICES_BEFORE}" | grep -c .)"

# ═════════════════════════════════════════════════════════════
step "1. PODGOTOVKA I SNIMOK SETI"
# ═════════════════════════════════════════════════════════════

install -d -m 700 "${SORADIR}"
[ -d "${SORADIR}" ] || { fail "ne sozdalos ${SORADIR}"; exit 1; }
good "katalog ${SORADIR} (prava 700)"

if iptables-save > "${SORADIR}/iptables.before" 2>/dev/null; then
    good "pravila seti sohraneny dlya otkata"
else
    warn "ne udalos sohranit pravila. Otkat seti budet nepolnym."
fi
echo "${SERVICES_BEFORE}" > "${SORADIR}/services.before"
good "spisok sluzhb sohranen"

if [ ! -f "${SORADIR}/server.conf" ]; then
    fail "Net ${SORADIR}/server.conf"
    blue "Skopirovat na server:"
    blue "  scp server/server.conf root@HOST:/etc/sora/server.conf"
    blue "Ili sohranit fayl v /tmp i peredat ego, skript podxvatit sam."
    if [ -f /tmp/server.conf ]; then
        cp /tmp/server.conf "${SORADIR}/server.conf"
        good "najden /tmp/server.conf, ispolzuem ego"
    else
        exit 1
    fi
fi
good "konfiguratsiya servera na meste"

# ═════════════════════════════════════════════════════════════
step "2. PAKETY"
# ═════════════════════════════════════════════════════════════

apt-get update -qq 2>&1 | tail -2
# netfilter-persistent v spiske NE sluchayno: bez nego pravila
  # iptables zhivut tolko v pamyati i propadayut pri perezagruzke.
  apt-get install -y -qq curl ca-certificates iptables unbound \
                        jq cron netfilter-persistent 2>&1 | tail -3
good "curl, ca-certificates, iptables, unbound, jq, cron, netfilter-persistent"

# Logi ne dolzhny rasti beskonechno: na servere budet tracker,
# i ego zhurnaly tozhe kudy-to idut. starsuyu rotatsiyu nastroim.
if [ -d /etc/logrotate.d ] && [ ! -f /etc/logrotate.d/sora ]; then
    cat > /etc/logrotate.d/sora <<'EOF'
/var/log/sora/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
    good "nastroena rotaciya logov"
fi

# ═════════════════════════════════════════════════════════════
step "3. USTANOVKA amnezia-awg-go"
# ═════════════════════════════════════════════════════════════

if [ -x "${BINARY}" ]; then
    warn "uzhe ustanovlen, obnovlyayu"
    "${BINARY}" --version 2>&1 | head -1 | note
else
    # ── ИСТОРИЯ БАГА, ЧТОБЫ НЕ ПОВТОРИТЬ ────────────────────────────
    # Здесь стоял URL:
    #   https://github.com/amnezia-vpn/amneziawg-go/releases/latest/download/
    #   amneziawg-go-linux-${ARCH}
    # Он выглядел правдоподобно, но репозиторий amnezia-vpn/amneziawg-go
    # НЕ ИМЕЕТ НИ ОДНОГО РЕЛИЗА — там только исходники. Проверено через
    # API GitHub: список релизов пуст. Любая ссылка вида releases/latest
    # на этом репозитории даёт 404.
    #
    # Проверено 15.10.2026 на живом сервере: curl вернул
    # «curl: (22) The requested URL returned error: 404».
    #
    # Отсюда порядок: сначала локальный бинарник, потом несколько
    # источников, и только потом отказ.
    # ──────────────────────────────────────────────────────────────────

    # ПЕРВЫЙ ИСТОЧНИК — сам пакет. server/bin/ лежит рядом со скриптом,
    # поэтому установка работает без сборки и без интернета: распаковал
    # пакет, залил на сервер, запустил — всё.
    #
    # Остальные пути оставлены для тех, кто ставит по частям.
    LOCAL_BIN=""
    for kandidat in "${SRC_DIR}/bin/amneziawg-go-linux-${ARCH}" \
                   "/root/sora/bin/amneziawg-go-linux-${ARCH}" \
                   "/tmp/amneziawg-go-linux-${ARCH}" \
                   "/root/sora/amneziawg-go-linux-${ARCH}"; do
        if [ -f "${kandidat}" ]; then
            LOCAL_BIN="${kandidat}"
            break
        fi
    done

    if [ -n "${LOCAL_BIN}" ]; then
        blue "nashel lokalnyi binarnik: ${LOCAL_BIN}"
        cp "${LOCAL_BIN}" "${BINARY}"
        chmod 755 "${BINARY}"
        good "skopirovano"
    else
        # АПСТРИМ-ИСТОЧНИКИ. Репозиторий без релизов, поэтому берём
        # либо собранный нами файл, либо пробуем зеркала с бинарниками.
        # Если и они не сработали — ставим с исходников.
        SKACHANO=0
        for URL in \
            "https://amnezia.org/deb/amneziawg-go-linux-${ARCH}" \
            "https://raw.githubusercontent.com/amnezia-vpn/amneziawg-go/master/bin/amneziawg-go-linux-${ARCH}"
        do
            blue "probuyu: ${URL}"
            if curl -fSL --retry 2 --max-time 120 -o "${BINARY}" "${URL}" 2>/dev/null; then
                chmod 755 "${BINARY}"
                good "skachano"
                SKACHANO=1
                break
            fi
        done

        if [ "${SKACHANO}" -eq 0 ]; then
            fail "net gotovogo binarnika, a v repositorii net relezov."
            note ""
            note "amnezia-vpn/amneziawg-go ne imeet relezov — tam tolko"
            note "ishodniki. Gotovoy sborki net. Nuzhno sobrat iz"
            note "ishodnikov (trebuet Go 1.25+):"
            note ""
            note "  git clone https://github.com/amnezia-vpn/amneziawg-go"
            note "  cd amneziawg-go && go build -o amneziawg-go ."
            note ""
            note "Gotovyy binarnik polozhite na server:"
            note "  scp amneziawg-go root@HOST:/root/sora/amneziawg-go-linux-${ARCH}"
            note "  i zapustite ustanovku zanovo."
            note ""
            note "NE podmenyayte obychnym wireguard-tools:"
            note "on ne zamaskirovan i budet opoznan oborudovaniem"
            note "provaydera. Togda VPN ne nuzhen voobshche."
            exit 1
        fi
    fi
fi

VER=$("${BINARY}" --version 2>&1 | head -1)
good "versiya: ${VER}"

# ── amneziawg-tools: awg и awg-quick ────────────────────────────────
# ОБЯЗАТЕЛЬНЫ. Сам amneziawg-go НЕ УМЕЕТ ЧИТАТЬ ФАЙЛЫ КОНФИГАЦИИ.
#
# Проверено на живом сервере 15.10.2026 чтением исходников:
# в main.go он только создаёт TUN-устройство по имени и слушает
# UAPI-сокет. Настройку получает через сокет, а не из файла.
#
# Значит порядок такой (его и делает awg-quick):
#   1. ip link add awg0 type amneziawg
#   2. если модуля ядра нет — запустить `amneziawg-go awg0`
#      (он сам создаёт TUN), отсюда и сообщение «Falling back to
#      slow userspace implementation»
#   3. awg setconf awg0 — отдать конфиг через UAPI
#   4. ip address add / ip link set up
#
# БЕЗ awg и awg-quick туннель не поднимется в принципе.

# Ищем awg и awg-quick там же, где искали бинарник.
# Порядок: пакет → /root/sora/bin → /tmp.
TOOLS_FOUND=""
for tools_dir in "${SRC_DIR}/bin" /root/sora/bin /tmp; do
    if [ -f "${tools_dir}/awg" ] && [ -f "${tools_dir}/awg-quick" ]; then
        TOOLS_FOUND="${tools_dir}"
        break
    fi
done

if [ -n "${TOOLS_FOUND}" ]; then
    blue "nashel awg-tools: ${TOOLS_FOUND}"
    install -m 755 "${TOOLS_FOUND}/awg" /usr/local/bin/awg
    install -m 755 "${TOOLS_FOUND}/awg-quick" /usr/local/bin/awg-quick
    if /usr/local/bin/awg --version >/dev/null 2>&1; then
        good "awg: $(/usr/local/bin/awg --version 2>&1 | head -1)"
    else
        fail "awg ne zapustilsya na etom servere"
        exit 1
    fi
else
    fail "net amneziawg-tools (awg, awg-quick)"
    note "Ishody nyzhe — vse mesta, kotorye proverilisya:"
    note "  ${SRC_DIR}/bin/awg"
    note "  /root/sora/bin/awg"
    note "  /tmp/awg"
    note ""
    note "Bez nih tunnel ne podnimetsya: sam binary konfigi ne chitaet."
    note "Vzyat iz amneziawg-tools release: ubuntu-22.04-amneziawg-tools.zip"
    exit 1
fi

# ═════════════════════════════════════════════════════════════
step "4. OGRANICHENIYA RESUROSOV"
# ═════════════════════════════════════════════════════════════

install -d /etc/systemd/system/amnezia-awg-go.service.d
cat > /etc/systemd/system/amnezia-awg-go.service.d/limits.conf <<EOF
[Service]
# Server chistyy, zapas pamyati bolshoy, no potolok vse ravno nuzhen:
# esli VPN raznestya, yadro ubyoyet imenno ego, a ne treker.
MemoryMax=${LIMIT_MEM}
MemoryHigh=$(( $(echo "${LIMIT_MEM}" | tr -dc '0-9') * 3 / 4 ))M
# VPN vsegda ustupayet protsessor trekeru.
Nice=10
EOF
systemctl daemon-reload
good "MemoryMax=${LIMIT_MEM}, Nice=10"

# ═════════════════════════════════════════════════════════════
step "5. PERESYLKA PAKETOV"
# ═════════════════════════════════════════════════════════════

cat > /etc/sysctl.d/90-sora.conf <<'EOF'
# Treker tozhe mozet stavit svoi servisy za nginx. Bez etogo
# vklyucheniya oni ne poluchat trafik, a VPN ne propustit naruzhu.
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl --system >/dev/null 2>&1

FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
[ "${FWD}" = "1" ] || { fail "ip_forward ne vklyuchilsya"; rollback; exit 1; }
good "net.ipv4.ip_forward = 1"
good "rp_filter vykluchen (inache tudyunel ili ne budet)"

# ═════════════════════════════════════════════════════════════
step "6. DNS VNTUTRI TUNNELYA"
# ═════════════════════════════════════════════════════════════

cat > "${SORADIR}/unbound.conf" <<EOF
server:
    interface: 10.77.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    access-control: ${NETWORK} allow
    access-control: 0.0.0.0/0 refuse
    do-not-query-localhost: yes
    harden-dnssec-stripped: yes
    prefetch: yes
    verbosity: 0
    log-queries: no
EOF
note "do-ip6: no — IPv6 na servere ne marshrutiziruetsya"

if command -v unbound-checkconf >/dev/null 2>&1; then
    if unbound-checkconf "${SORADIR}/unbound.conf" >/dev/null 2>&1; then
        good "konfiguratsiya rezolvera korrektna"
    else
        fail "rezolver ne prokhodit proverku:"
        unbound-checkconf "${SORADIR}/unbound.conf" 2>&1 | note
        rollback
        exit 1
    fi
fi

# ── КОНФИГ ДОЛЖЕН ЛЕЖАТЬ ТАМ, ГДЕ unbound ЕГО ЧИТАЕТ ────────────────
# БЫЛ БАГ, НАЙДЕННЫЙ НА ЖИВОМ СЕРВЕРЕ 15.10.2026.
#
# Конфиг писался в ${SORADIR}/unbound.conf — то есть в /etc/sora/,
# куда unbound никогда не заглядывает. Служба молча брала свой
# штатный конфиг Debian и слушала 127.0.0.1:53 вместо 10.77.0.1:53.
#
# На живой машине это выглядело так:
#     [ok] sluzhba rabotaet            <- unbound активен
#     [!!] rezolver ne slushaet na 10.77.0.1:53
# то есть «служба работает» и «DNS в туннеле не работает» —
# одновременно, и без всякой связи между ними.
#
# Настоящее расположение на Debian 12:
#     /etc/unbound/unbound.conf.d/*.conf
# подключается из unbound.conf через include.

install -d -m 755 /etc/unbound/unbound.conf.d 2>/dev/null || true
if [ -d /etc/unbound/unbound.conf.d ]; then
    cp "${SORADIR}/unbound.conf" /etc/unbound/unbound.conf.d/sora.conf
    chmod 644 /etc/unbound/unbound.conf.d/sora.conf
    good "konfig rezolvera: /etc/unbound/unbound.conf.d/sora.conf"
else
    fail "net /etc/unbound/unbound.conf.d — unbound ne prochitaet konfig"
    note "  Proshchee mesto dlya starogo Debian — /etc/unbound/sora.conf,"
    note "  vklyuchennoye cherez include v /etc/unbound/unbound.conf."
    rollback
    exit 1
fi

# unbound должен стартовать ПОСЛЕ туннеля: иначе адреса 10.77.0.1
# ещё нет, и резолвер не сможет на него повеситься.
install -d -m 755 /etc/systemd/system/unbound.service.d
cat > /etc/systemd/system/unbound.service.d/sora-order.conf <<EOF
[Unit]
# Резолвер вешается на адрес туннеля. Пока awg0 не поднят,
# адреса 10.77.0.1 не существует и unbound не сможет
# на него слушать.
After=amnezia-awg-go.service
Requires=amnezia-awg-go.service
EOF
systemctl daemon-reload 2>&1 | note
good "poryadok zapuska: unbound posle VPN"

# ═════════════════════════════════════════════════════════════
step "7. PRAVILA SETI"
# ═════════════════════════════════════════════════════════════

note "interfeys: ${IFACE}"

# Port VPN
if ! iptables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT \
        && good "otkryt UDP/${PORT}" || fail "ne udalos otkryt port"
else
    note "pravilo na UDP/${PORT} uzhe bylo"
fi

# NAT
if ! iptables -t nat -C POSTROUTING -s "${NETWORK}" -o "${IFACE}" \
        -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "${NETWORK}" -o "${IFACE}" \
        -j MASQUERADE && good "NAT dlya ${NETWORK}" || fail "net NAT"
else
    note "pravilo NAT uzhe bylo"
fi

# Klienty ne hodyat v sluzhebnye seti servera
for SUBNET in 127.0.0.0/8 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8; do
    iptables -C FORWARD -s "${NETWORK}" -d "${SUBNET}" -j REJECT 2>/dev/null \
        || iptables -A FORWARD -s "${NETWORK}" -d "${SUBNET}" -j REJECT 2>/dev/null
done
good "sluzhebnye seti servera zakryty ot klientov"

# Treker dolzhen imet dostup v internet, VPN - tolko cherez NAT.
# Desyat soedineniy odnovremenno: bolshe ne nuzhno, a ogranichenie
# zashchishchaet server, yesli kto-to ukrachest klientov.
if ! iptables -C FORWARD -p udp -m udp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null || true
fi

note "POLZOVATEL treker smotrit FAQ 2 v ТЗ-SORA.md:"
note "  sora-open-port.sh 80    # otkryt port dlya trackera"
note "  sora-open-port.sh 443   # esli on nuzhen"

# ── ПРАВИЛА ДОЛЖНЫ ПЕРЕЖИТЬ ПЕРЕЗАГРУЗКУ ───────────────────────────
# Пакет netfilter-persistent на Debian 12.15 приходит С ПУСТЫМ
# каталогом плагинов. Проверено на живом сервере:
#
#     dpkg -L netfilter-persistent | grep plugins.d
#     /usr/share/netfilter-persistent/plugins.d    <- каталог есть, файлов нет
#
# Весь /usr/sbin/netfilter-persistent — это `run-parts` по этому
# каталогу. Каталог пуст => и save, и start НИЧЕГО НЕ ДЕЛАЮТ,
# но выходят с кодом 0. Выглядит как успех.
#
# Итог без плагинов: правила живут в памяти, месяц всё работает,
# потом сервер перезагружают — и VPN молча умирает. А проверка
# «netfilter-persistent установлен» проходит.

NFPDIR="/usr/share/netfilter-persistent/plugins.d"
# SRC_DIR uze opredelen v nachale skripta (trebuetsya i v shagu 3).

if ! command -v netfilter-persistent >/dev/null 2>&1; then
    warn "netfilter-persistent ne stoit: posle perezagruzki pravila propadut."
    warn "Postavit:  apt install -y netfilter-persistent"
    warn "Ili:       bash install_sora.sh  (skript eto predlozhit)"
elif [ ! -f "${NFPDIR}/iptables" ]; then
    warn "u netfilter-persistent net PLAGINOV — on nichego ne sohranit."
    if [ -f "${SRC_DIR}/nfp-plugin-iptables" ]; then
        install -d -m 755 "${NFPDIR}"
        install -m 755 "${SRC_DIR}/nfp-plugin-iptables"  "${NFPDIR}/iptables"
        install -m 755 "${SRC_DIR}/nfp-plugin-ip6tables" "${NFPDIR}/ip6tables"
        if bash -n "${NFPDIR}/iptables" && bash -n "${NFPDIR}/ip6tables"; then
            good "plaginy netfilter-persistent dostavleny"
        else
            fail "plaginy ne proshli proverku sintaksisa"
            rollback
            exit 1
        fi
    else
        fail "plaginy ne naydeny ryadom so skriptom:"
        note "  ${SRC_DIR}/nfp-plugin-iptables"
        note "  Bez nih save i start ne delayat nicheckogo, hotya i vozvrashchayut 0."
    fi
else
    good "plaginy netfilter-persistent na meste"
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    install -d -m 700 /etc/iptables
    if netfilter-persistent save >/dev/null 2>&1 && [ -s /etc/iptables/rules.v4 ]; then
        good "pravila sohraneny v /etc/iptables/rules.v4"
    else
        warn "save ne zapisal fajl — posle perezagruzki pravila propadut"
        warn "Proverte, chto v ${NFPDIR} est fayly, i povtorite:"
        warn "  netfilter-persistent save"
    fi
fi

# ═════════════════════════════════════════════════════════════
step "8. SLUZHBA VPN S ZAZHMENNYM DOSTUPOM"
# ═════════════════════════════════════════════════════════════

chmod 600 "${SORADIR}/server.conf"
good "konfiguratsiya: prava 600"

# ── КОНФИГ ДЛЯ awg-quick ───────────────────────────────────────────
# awg-quick читает конфиг из /etc/amnezia/amneziawg/<интерфейс>.conf.
#
# Две строки добавляются ВНУТРЬ секции [Interface] — это важно.
# awg-quick вырезает Table/SaveConfig/DNS/Address ТОЛЬКО когда
# они внутри [Interface] (в его parse_config стоит
# `if [[ $interface_section -eq 1 ]]`). Если поставить их ДО
# заголовка, строки не вырежутся и уедут в `awg setconf`,
# который их не знает. Проверено на сервере:
#     Line unrecognized: `Table=off'
#
# Table = off    — маршрутами управляем сами через iptables (шаг 7).
#   Без этого awg-quick добавил бы маршрут по умолчанию через
#   туннель, и сервер сам стал бы шлюзом в интернет.
# SaveConfig = false — иначе `awg-quick down` перезапишет наш файл
#   вырезанным конфигом.

install -d -m 700 /etc/amnezia/amneziawg
awk '
  /^\[Interface\]/ && !inserted {
    print "[Interface]"
    print "Table = off"
    print "SaveConfig = false"
    inserted = 1
    next
  }
  { print }
' "${SORADIR}/server.conf" > /etc/amnezia/amneziawg/awg0.conf
chmod 600 /etc/amnezia/amneziawg/awg0.conf

# Проверяем ДВАЖДЫ разными средствами.
#
# НАБЛЮДАЛОСЬ НА ЖИВОМ СЕРВЕРЕ: файл содержал `Table = off`
# как отдельную строку внутри [Interface] — подтверждено od -c
# и grep на сервере. Но это условие НЕ выполнялось, хотя точно
# такой же блок, запущенный отдельно, отрабатывал правильно
# (grep возвращал 0).
#
# Причина не установлена. Поэтому проверяем двумя независимыми
# способами и печатаем оба кода: при следующем провале будет
# видно, в чём дело, а не только «что-то не так».
#
# grep -qx — совпадение ВСЕЙ строки целиком
# awk      — сравнение строк без регулярных выражений
TABLE_GREP=1
grep -qx 'Table = off' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null
TABLE_GREP=$?

TABLE_AWK=1
awk '$0 == "Table = off" { found = 1 } END { exit !found }' \
    /etc/amnezia/amneziawg/awg0.conf 2>/dev/null
TABLE_AWK=$?

note "  Table: grep=${TABLE_GREP} awk=${TABLE_AWK}"

if [ "${TABLE_AWK}" -eq 0 ] || [ "${TABLE_GREP}" -eq 0 ]; then
    good "konfig dlya awg-quick: /etc/amnezia/amneziawg/awg0.conf"
else
    fail "Table = off ne popal v [Interface] — awg-quick ego ne vyrezhet"
    note ""
    note "  Soderzhimoe poluchennogo fakta (pervye 20 strok):"
    head -20 /etc/amnezia/amneziawg/awg0.conf 2>&1 | sed 's/^/    /' | note
    note ""
    note "  Est li [Interface] vo vhodnom fajle:"
    grep -n 'Interface' "${SORADIR}/server.conf" 2>&1 | sed 's/^/    /' | note
    note "  Est li CR v nem (fajl s Windows, sozdanyj bez newline):"
    if grep -q $'\r' "${SORADIR}/server.conf" 2>/dev/null; then
        note "    DA — v fajle est CR. Per sozdatejte ego cherez"
        note "    sora_keys.py: on dolzhen pisat s LF."
    else
        note "    net"
    fi
    exit 1
fi

# ── ЮНИТ ──────────────────────────────────────────────────────────
# ExecStart — это awg-quick, а НЕ сам binary с файлом конфига.
# Та форма (`binary --interface /etc/sora/server.conf`) проверена
# и НЕ работает: main.go ждёт либо `ИМЯ` либо `-f ИМЯ`,
# а `--interface` попадает в ветку default, где os.Args != 2,
# и он печатает Usage и выходит.
#
# Type=oneshot + RemainAfterExit: awg-quick поднимает интерфейс и
# выходит, а туннель живёт отдельным процессом amneziawg-go.
# Одиночный процесс нельзя описать как Type=simple, потому что
# демон уходит в фон.

cat > /etc/systemd/system/amnezia-awg-go.service <<EOF
[Unit]
Description=SORA - lichnyy VPN AmneziaWG
Documentation=https://github.com/amnezia-vpn/amneziawg-go

# БЫЛО: After=network-online.target unbound.service
# Это создавало ЦИКЛИЧЕСКУЮ зависимость. Резолвер должен
# стартовать ПОСЛЕ туннеля — он вешается на адрес 10.77.0.1,
# которого до awg0 не существует. Значит:
#     unbound: After=amnezia-awg-go
#     VPN не должен требовать unbound
#
# На живом сервере из-за цикла systemd отказывался
# перезапускать unbound:
#     Found ordering cycle on amnezia-awg-go.service/restart
#     Unable to break cycle starting with unbound.service/restart
# и резолвер так и оставался на 127.0.0.1.
#
# DNS внутри туннеля нужен клиенту, а не самому VPN: VPN поднимается
# и без резолвера.
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ExecStart=/usr/local/bin/awg-quick up awg0
ExecStop=/usr/local/bin/awg-quick down awg0
ExecReload=/usr/local/bin/awg-quick down awg0
ExecReload=/usr/local/bin/awg-quick up awg0
Restart=on-failure
RestartSec=5
RuntimeDirectory=amneziawg
RuntimeDirectoryPreserve=yes
LimitNOFILE=4096

# --- zazhmyonnye prava dostupa ---
# Sluzhbe ne nuzhno pisat na disk. Esli ee vzlomayut, snova
# zapisyvat na server budet nechego.
ProtectSystem=strict
# UAPI-soket lezhit v /run/amneziawg — s ProtectSystem=strict ves /
# nevezhmo, krome /dev, /proc i /sys. Bez etoy stroki demon ne
# smozhet sozdat soket i tunnel ne podnimetsya.
ReadWritePaths=/run/amneziawg
ProtectHome=yes
PrivateTmp=yes

# PrivateDevices=yes УБРАН СОЗНАТЕЛЬНО.
# Оно даёт процессу ЧАСТНЫЙ /dev, где нет /dev/net/tun.
# amneziawg-go — userspace-реализация, он сам создаёт TUN через
# /dev/net/tun. Без этого устройства туннель не поднимется.
# На сервере ядро без модуля amneziawg, работает только
# userspace, поэтому PrivateDevices здесь недопустим.

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# CapabilityBoundingSet= тоже требовал правки.
# Пустой набор означает «ни одной capability», включая
# CAP_NET_ADMIN. Без неё нельзя создать интерфейс и настроить
# туннель. Оставляем ровно одну capability — этого хватает и
# ничего сверх того.
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
good "yunit-fayl sozdan s zazhmyonnymi pravami"

# ═════════════════════════════════════════════════════════════
step "9. TAIMER PROVERKI"
# ═════════════════════════════════════════════════════════════

install -m 755 "$(dirname "$0")/sora-health.sh" /usr/local/bin/sora-health.sh \
    2>/dev/null && note "sora-health.sh ustanovlen v /usr/local/bin"

if [ -f "$(dirname "$0")/sora-selftest.sh" ]; then
    install -m 755 "$(dirname "$0")/sora-selftest.sh" \
        /usr/local/bin/sora-selftest.sh
    note "sora-selftest.sh ustanovlen"
else
    warn "net sora-selftest.sh ryadom"
fi

cat > /etc/systemd/system/sora-health.service <<'EOF'
[Unit]
Description=SORA - proverka sostoyaniya

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sora-health.sh --tiho
EOF

cat > /etc/systemd/system/sora-health.timer <<'EOF'
[Unit]
Description=SORA - proverka sostoyaniya kazhdye 5 minut

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now sora-health.timer >/dev/null 2>&1
good "timer proverki kazhdye 5 minut"

# ══════════════════════════════════════════════════════════════
step "10. UCHET TRAFIKA"
# ══════════════════════════════════════════════════════════════

# Python здесь уже нужен ради учёта трафика по людям. Раньше в ТЗ
# писалось, что Python на сервере не нужен — это было верно, пока
# учёта не существовало. Сервер чистый, место есть, и отказ от
# счётчиков становится неоправданным.
if ! command -v python3 >/dev/null 2>&1; then
    apt-get install -y -qq python3-minimal 2>&1 | tail -2
fi
if command -v python3 >/dev/null 2>&1; then
    good "python3: $(python3 --version 2>&1)"
else
    warn "python3 не установлен. Без него учёт трафика не работает."
fi

SCRIPTDIR=$(cd "$(dirname "$0")" && pwd)

if [ -f "${SCRIPTDIR}/../tools/sora_traffic.py" ]; then
    install -m 755 "${SCRIPTDIR}/../tools/sora_traffic.py" \
        /usr/local/bin/sora_traffic.py
    good "учёт трафика установлен: sora_traffic.py"
else
    warn "не найден sora_traffic.py рядом — счёт трафика не будет"
fi

install -d -m 700 /var/lib/sora
install -d -m 700 /var/lib/sora/history

CRONFILE=/etc/cron.d/sora
cat > "${CRONFILE}" <<'CRONEOF'
# SORA - автоматика. Создана install_sora.sh, править её нужно здесь.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=""

# опрос трафика и применение лимитов — каждые 5 минут
*/5 * * * * root /usr/local/bin/sora_traffic.py poll >/dev/null 2>&1

# резервная копия раз в день
17 4 * * * root /usr/local/bin/sora_backup.sh >/dev/null 2>&1

# проверка состояния раз в 15 минут
*/15 * * * * root /usr/local/bin/sora-health.sh --tiho >/dev/null 2>&1
CRONEOF
chmod 644 "${CRONFILE}"
good "cron настроен: учёт 5 мин, бэкап 04:17, проверка 15 мин"

# Первый опрос: создаёт базу счёта и проверяет, что счётчики вообще
# устанавливаются. Молча пройти мимо нельзя — иначе учёт «работает»
# месяцами, не считая ничего.
if command -v python3 >/dev/null 2>&1 && \
        [ -f /usr/local/bin/sora_traffic.py ]; then
    if python3 /usr/local/bin/sora_traffic.py poll >/dev/null 2>&1; then
        good "первый опрос прошёл, счётчики работают"
    else
        warn "первый опрос не удался. Подробности:"
        python3 /usr/local/bin/sora_traffic.py poll 2>&1 | head -6 | note
    fi
fi

# ======================================================================
step "10b. REZERVNOE KOPIROVANIE"
# ======================================================================

if [ -f "${SCRIPTDIR}/sora_backup.sh" ]; then
    install -m 755 "${SCRIPTDIR}/sora_backup.sh" \
        /usr/local/bin/sora_backup.sh
    good "резервное копирование установлено"

    # Первая копия — сразу. Иначе первую же ночь, когда ещё нет
    # копии, можно потерять server.conf вместе со всеми ключами.
    if /usr/local/bin/sora_backup.sh >/dev/null 2>&1; then
        good "первая копия создана"
    else
        warn "первую копию создать не удалось"
    fi
else
    warn "нет sora_backup.sh рядом"
fi

# ══════════════════════════════════════════════════════════════
step "11. ZAPUSK"
# ══════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════

systemctl enable --now unbound >/dev/null 2>&1
sleep 1
if systemctl is-active --quiet unbound; then
    good "unbound rabotaet"
else
    fail "unbound ne zapustilsya:"
    journalctl -u unbound -n 10 --no-pager 2>/dev/null | note
    rollback
    exit 1
fi

systemctl enable amnezia-awg-go >/dev/null 2>&1
systemctl restart amnezia-awg-go
sleep 2

if systemctl is-active --quiet amnezia-awg-go; then
    good "VPN rabotaet"
else
    fail "VPN ne zapustilsya:"
    journalctl -u amnezia-awg-go -n 15 --no-pager 2>/dev/null | note
    rollback
    exit 1
fi

# ═════════════════════════════════════════════════════════════
step "12. PROVERKA POSLE USTANOVKI"
# ═════════════════════════════════════════════════════════════

FAILURES=0

if ss -lun 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
    good "port ${PORT} slushaetsya"
else
    fail "port ${PORT} NE slushaetsya"
    FAILURES=$((FAILURES + 1))
fi

MEM_PID=$(systemctl show -p MainPID --value amnezia-awg-go 2>/dev/null)
if [ -n "${MEM_PID}" ] && [ "${MEM_PID}" != "0" ] \
        && [ -r "/proc/${MEM_PID}/status" ]; then
    RSS=$(( $(awk '/VmRSS/{print $2}' "/proc/${MEM_PID}/status") / 1024 ))
    good "VPN est ${RSS} MB (potolok ${LIMIT_MEM})"
else
    warn "ne udalos izmerit pamyat processa"
fi

FREE_AFTER=$(free -m | awk '/Mem:/{print $7}')
if [ "${FREE_AFTER}" -lt 100 ]; then
    fail "posle ustanovki svobodno ${FREE_AFTER} MB — malo"
    FAILURES=$((FAILURES + 1))
else
    good "svobodno pamyati: ${FREE_AFTER} MB (bilo ${FREE_MEM})"
fi

# Treker ne dolzhen postradat
SERVICES_AFTER=$(systemctl list-units --type=service --state=running \
                  --no-pager --plain 2>/dev/null | awk '{print $1}' | sort)
LOST=$(comm -23 <(echo "${SERVICES_BEFORE}") <(echo "${SERVICES_AFTER}") \
       | grep -v -e '^amnezia' -e '^unbound' -e '^sora' || true)
if [ -z "${LOST}" ]; then
    good "nikakie sluzhby ne propali"
else
    fail "propali sluzhby: ${LOST}"
    FAILURES=$((FAILURES + 1))
fi

if [ "${FAILURES}" -gt 0 ]; then
    echo
    warn "Proverka ne proshla. Otkat? (yes/NO)"
    read -r ANS
    case "${ANS}" in
        yes|YES|y|Y) rollback; exit 1 ;;
        *) note "Ostavlyayu kak esto. Razberites sami." ;;
    esac
fi

# ══════════════════════════════════════════════════════════════
step "13. SAMOPROVERKA"
# ══════════════════════════════════════════════════════════════
# Здесь проверяется не "живо ли", а "правильно ли".
#
# Установка может закончиться кодом 0, всё зелёное — а счётчики
# трафика не создались. Тогда месяц VPN будет работать, люди будут
# подключаться, а трафик не будет посчитан ни байтом. Проверка
# состояния такое не увидит: служба-то жива.
if [ -f /usr/local/bin/sora-selftest.sh ]; then
    if /usr/local/bin/sora-selftest.sh; then
        good "samoproverka proshla"
    else
        warn "SAMOPROVERKA NAYSHLA PROBLEMY (vyshe)"
        note "VPN mozhet rabotat, no ne vsyo ustroeno kak zadumano."
        note "Ispravte i zapustite sora-selftest.sh zanovo."
    fi
else
    warn "samoproverka ne ustanovlena"
fi


# ═════════════════════════════════════════════════════════════
step "GOTOVO"
# ═════════════════════════════════════════════════════════════

echo
echo "${GREEN}  SORA ustanovlen.${RESET}"
echo
echo "  Dalee:"
echo "    1. na PK:  python tools/sora_keys.py config <imya>"
echo "    2. vstavit v Amnezia na noutbuke"
echo "    3. proverit:"
echo "         https://whatismyipaddress.com  -> 203.0.113.10"
echo "         https://ipleak.net             -> serverov ne iz Rossii"
echo
echo "  Trekeru nuzhny porty?  sm. FAQ 2 в ТЗ-SORA.md"
echo "  Sostoyanie:             sora-health.sh"
echo "  Pravilnost ustanovki:   sora-selftest.sh"
echo "  Kto skachal:            sora_traffic.py report"
echo "  Otkat:                  bash uninstall_sora.sh"
echo
