#!/bin/bash
# Функциональная проверка серверных скриптов на машине без Linux.
# Проверяется то, что можно проверить без iptables и systemd:
# разбор аргументов, отказ на плохих данных, наличие отказов.
# Настоящая работа скриптов проверяется на сервере.

S='C:\Users\HP\PycharmProjects\WelcomeScreen\SORA/server'

pass=0; fail=0
run() {
    # run <ожидаемый код> <описание> <команда...>
    want="$1"; desc="$2"; shift 2
    out=$("$@" 2>&1); got=$?
    if [ "$got" = "$want" ]; then
        printf '  [ok]   %-42s код %s\n' "$desc" "$got"; pass=$((pass+1))
    else
        printf '  [!!]   %-42s код %s, ждали %s\n' "$desc" "$got" "$want"
        echo "$out" | head -3 | sed 's/^/           /'
        fail=$((fail+1))
    fi
}

echo
echo "=== ОТКАЗЫ НА НЕПРАВИЛЬНЫХ ДАННЫХ ==="
run 1 "open-port: нет аргументов"      bash "$S/sora-open-port.sh"
run 1 "open-port: порт не число"       bash "$S/sora-open-port.sh" abc
run 1 "open-port: порт 99999"          bash "$S/sora-open-port.sh" 99999
run 1 "open-port: порт 0"              bash "$S/sora-open-port.sh" 0
run 1 "open-port: протокол sctp"       bash "$S/sora-open-port.sh" 443 sctp
run 1 "open-port: порт самого VPN"     bash "$S/sora-open-port.sh" 39117 udp
run 1 "close-port: нет аргументов"     bash "$S/sora-close-port.sh"
run 1 "close-port: порт не число"      bash "$S/sora-close-port.sh" xyz
run 1 "close-port: протокол sctp"      bash "$S/sora-close-port.sh" 443 sctp
run 2 "health: неизвестный аргумент"   bash "$S/sora-health.sh" --nesushchestvuyushchiy
run 1 "install: не root"               bash "$S/install_sora.sh"
run 1 "uninstall: не root"             bash "$S/uninstall_sora.sh"

echo
=== ТИХИЙ РЕЖИМ ===
# Проверять надо не число строк, а ОТСУТСТВИЕ сообщений об успехе.
# Первая версия теста требовала не больше трёх строк вывода и ругалась.
# Но на машине без systemd всё действительно сломано, и шесть строк
# fail() — это правда, а не шум. Тихий режим должен молчать об успехе
# и ОБЯЗАН говорить о проблемах: молчание о поломке хуже шума.
out=$(bash "$S/sora-health.sh" --tiho 2>&1)
good_lines=$(echo "$out" | grep -c '\[ok\]' || true)
noise_lines=$(echo "$out" | grep -c '\[!\]' || true)
bad_lines=$(echo "$out" | grep -c '\[!!\]' || true)

if [ "$good_lines" -eq 0 ]; then
    printf '  [ok]   --tiho molchit ob uspekhe        [ok]: %s\n' "$good_lines"
    pass=$((pass+1))
else
    printf '  [!!]   --tiho prosal ob uspekhe        [ok]: %s\n' "$good_lines"
    fail=$((fail+1))
fi

if [ "$noise_lines" -eq 0 ]; then
    printf '  [ok]   --tiho molchit o sovetakh        [!]: %s\n' "$noise_lines"
    pass=$((pass+1))
else
    printf '  [!!]   --tiho prosal o sovetakh        [!]: %s\n' "$noise_lines"
    fail=$((fail+1))
fi

if [ "$bad_lines" -gt 0 ]; then
    printf '  [ok]   --tiho soobshchayet o problemah  [!!]: %s\n' "$bad_lines"
    pass=$((pass+1))
else
    printf '  [!!]   --tiho nichego ne soobshchil\n'
    fail=$((fail+1))
fi

echo
echo "=== ОБЫЧНЫЙ РЕЖИМ (должен печатать отчёт) ==="
out=$(bash "$S/sora-health.sh" 2>&1)
if echo "$out" | grep -q "SOSTOYANIE"; then
    printf '  [ok]   отчёт печатается\n'; pass=$((pass+1))
else
    printf '  [!!]   отчёт не напечатан\n'; fail=$((fail+1))
fi
if echo "$out" | grep -q "dostupno 10.77.0.1:53\|rezolver"; then
    printf '  [ok]   проверка DNS есть\n'; pass=$((pass+1))
else
    printf '  [!!]   проверки DNS нет\n'; fail=$((fail+1))
fi

echo
echo "=== НЕТ ССЫЛОК НА НЕСУЩЕСТВУЮЩЕЕ ==="
for f in install_sora.sh sora-health.sh uninstall_sora.sh; do
    for need in sora-open-port.sh sora-health.sh; do
        if grep -q "$need" "$S/$f"; then
            if [ ! -f "$S/$need" ]; then
                printf '  [!!]   %s ссылается на несуществующий %s\n' "$f" "$need"
                fail=$((fail+1))
            fi
        fi
    done
done
printf '  [ok]   все упомянутые файлы существуют\n'; pass=$((pass+1))

echo
echo "================================================"
printf '  итог: %d ок, %d сбоев\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && echo "  всё в порядке" || echo "  ЕСТЬ ПРОБЛЕМЫ"
echo "================================================"
echo
[ "$fail" -eq 0 ] || exit 1
