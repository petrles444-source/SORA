#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДОСТУП К TELEGRAM BOT API С VPS — диагностика и обход фильтрации.

ЗАЧЕМ ЭТОТ ИНСТРУМЕНТ
======================

Бот на сервере не отвечает. curl возвращает 000, urllib — таймаут.
Классическое подозрение: «хостер заблокировал Telegram». Обычно это
неверно, и инструмент существует именно чтобы это выяснить, а не
предположить.

ЧТО ПРОИСХОДИТ НА САМОМ ДЕЛЕ
=============================

Проверено на Debian 12, VPS в российском дата-центре, 15.10.2026:

    149.154.166.110:443   таймаут 12 с     <- сюда резолвится api.telegram.org
    149.154.167.220:443   отвечает 150 мс  <- тот же Telegram, другой адрес
    91.108.56.130:443     порт открыт, HTTPS не отвечает
    github.com:443        отвечает
    google.com:443        таймаут          <- фильтр не про Telegram

    ICMP до 149.154.166.110: 0% потерь, 47 мс

Из этого следуют три вывода, и все три проверяются инструментом:

  1. Блокировка выборочная. Два адреса Telegram из пяти открыты,
     значит «Telegram заблокирован» — неверная формулировка.
  2. ICMP проходит, режется именно TCP/443. Это не бан по адресу,
     это фильтрация по порту.
  3. Фильтр не про Telegram. google.com закрыт наравне с ним.

ПОЧЕМУ НЕ /etc/hosts
====================

Самое естественное решение — дописать в /etc/hosts рабочий адрес.
На проверенном хосте ОНО НЕ РАБОТАЕТ, и это отдельная находка:

    /etc/nsswitch.conf:  hosts: files dns        <- файлы идут первыми
    getent hosts test.local          -> 1.2.3.4 <- /etc/hosts читается
    getent hosts api.telegram.org    -> 149.154.166.110 <- и всё равно DNS
    curl -v: Trying [2001:67c:4e8:f004::9]:443...
           Trying 149.154.166.110:443...

Запись в hosts синтаксически верна (проверено od -c), порядок источников
правильный, механизм резолвера файл читает — но имя всё равно
разрешается через DNS. Причина в том, что система отдаёт AAAA-запись
раньше A, и соединение уходит на IPv6, который на этом хосте сломан.

Вывод, который стоит запомнить: если резолвер возвращает IPv6 раньше
IPv4, запись в /etc/hosts не поможет. Помогает только вмешательство
на уровне пакетов.

ЧТО ДЕЛАЕТ ИНСТРУМЕНТ
=====================

    check    найти, что именно сломано, ничего не меняя
    fix      найти рабочий адрес Telegram и включить перенаправление
    verify   проверить, что перенаправление живо и после него виден API
    revert   снять перенаправление

Перенаправление делается правилом DNAT: трафик к заблокированному
адресу на порту 443 уходит рабочему адресу. Имя не участвует вообще,
поэтому результат не зависит от того, как система разрешает имена.
Соответствие TLS сохраняется: SNI остаётся api.telegram.org,
сертификат проверяется как обычно.

ЧТО ИНСТРУМЕНТ НЕ ДЕЛАЕТ
=========================

  - не трогает маршрут по умолчанию
  - не трогает интерфейсы awg0/wg0 и не меняет число пиров
  - не пишет в /etc/hosts
  - не отправляет сообщений и не вызывает getUpdates

Одно правило DNAT в цепочке OUTPUT таблицы nat на один адрес и один
порт. Всё остальное на сервере продолжает идти как раньше — это
проверяется до и после, а не предполагается.

ЧТО ПОТОБУЕТСЯ
==============

    python3 tools/sora_telegram.py check
    sudo python3 tools/sora_telegram.py fix

Ничего устанавливать не нужно: только стандартная библиотека
Python 3, iptables и systemctl. На Debian 12 всё это уже есть.

ОГРАНИЧЕНИЕ, О КОТОРОМ НАДО ЗНАТЬ ЗАРАНЕЕ
========================================

Список адресов Telegram зашит в инструмент. Telegram имеет право в
любой момент их сменить, и тогда зашитое станет неверным. Поэтому
есть подкоманда verify: она говорит, жив ли адрес, на который сейчас
настроено перенаправление. Если verify вернул «мёртв» — нужен новый
запуск fix, который переберёт список заново.

ЗАПУСК
    python3 tools/sora_telegram.py check
    sudo   python3 tools/sora_telegram.py fix
    sudo   python3 tools/sora_telegram.py verify
    sudo   python3 tools/sora_telegram.py revert
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Идентификаторы латиницей — намеренно. В проекте кириллица в именах
# разрешена, но при такой плотности русских имён вероятность словить
# неразличимый на вид опечатанный идентификатор слишком велика.
# Комментарии и вывод остаются русскими.

TELEGRAM_HOST = "api.telegram.org"
TELEGRAM_PORT = 443

# Адреса Telegram Bot API. Проверены вручную 15.10.2026.
# Именно проверяются, а не используются вслепую: см. probe_tls.
KNOWN_IPS = [
    "149.154.166.110",   # то, что отдаёт DNS; на проверенном хосте заблокирован
    "149.154.167.220",   # отвечает
    "149.154.167.198",
    "149.154.175.100",
    "91.108.56.130",
    "91.108.56.100",
]

# Контрольные адреса: показывают, что фильтр не относится к Telegram.
CONTROL_IPS = [
    ("github.com", "443"),
    ("cloudflare.com", "443"),
    ("google.com", "443"),
]

SCRIPT_NAME = "telegram-route-fix.sh"
SERVICE_NAME = "telegram-route-fix.service"
SCRIPT_PATH = f"/usr/local/sbin/{SCRIPT_NAME}"
SERVICE_PATH = f"/etc/systemd/system/{SERVICE_NAME}"

# Токен заведомо несуществующий. Настоящий токен инструменту не нужен
# и не передаётся: проверяется ответ сервера на НЕВЕРНЫЙ токен.
DEAD_TOKEN = "000000:AAHinvalidtokenforreachabilitycheck"


def out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def die(text: str, code: int = 1) -> None:
    sys.stdout.write(f"ОШИБКА: {text}\n")
    raise SystemExit(code)


# ---------------------------------------------------------------- probes

def resolve(host: str) -> list[str]:
    """Все адреса имени, IPv4 и IPv6, в том порядке как их отдаёт система."""
    try:
        данные = socket.getaddrinfo(host, TELEGRAM_PORT,
                                    proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return []
    адреса = []
    for семейство, _тип, _прото, _канон, sockaddr in данные:
        ip = sockaddr[0]
        if ip not in адреса:
            адреса.append(ip)
    return адреса


def tcp_open(host: str, port: int, timeout: float = 8.0) -> bool:
    """Открывается ли TCP. Не различает «отказано» и «нет ответа»."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@contextlib.contextmanager
def заперто_на_адрес(ip: str):
    """Направить обращение к TELEGRAM_HOST на конкретный IP.

    Подменяется только getaddrinfo, больше ничего. Имя, SNI и
    проверка сертификата остаются настоящими — иначе проверка
    ничего бы не значила: соединение с чужим адресом под именем
    Telegram как раз и выглядит как атака, а не как обход фильтра.

    Аналог того, что делает `curl --resolve`, только на уровне
    Python. После выхода состояние восстановлено, глобально
    ничего не остаётся изменённым.
    """
    настоящий = socket.getaddrinfo

    def подменённый(host, port, *args, **kwargs):
        if host == TELEGRAM_HOST:
            host = ip
        return настоящий(host, port, *args, **kwargs)

    socket.getaddrinfo = подменённый
    try:
        yield
    finally:
        socket.getaddrinfo = настоящий


def probe_tls(ip: str, timeout: float = 12.0) -> tuple[bool, str]:
    """Настоящий ответ Telegram API через конкретный адрес.

    TCP-порта недостаточно: на проверенном хосте порт 443 у
    91.108.56.130 открыт, а HTTPS не отвечает вовсе. Поэтому
    проверка идёт до конца — до разобранного JSON в теле ответа.

    Заведомо неверный токен — это не ошибка, а признак того, что
    ответ дошёл. Telegram на такой запрос отвечает 401 с описанием
    «invalid token», и это самый надёжный признак живой связи.
    """
    url = f"https://{TELEGRAM_HOST}/bot{DEAD_TOKEN}/getMe"
    req = urllib.request.Request(url, method="GET")
    t0 = time.time()
    try:
        with заперто_на_адрес(ip):
            with urllib.request.urlopen(
                    req, timeout=timeout,
                    context=ssl.create_default_context()) as resp:
                raw = resp.read()
                return _telegram_answered(resp.status, raw,
                                          f"HTTP {resp.status}",
                                          time.time() - t0)
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read()
        except Exception:
            pass
        return _telegram_answered(exc.code, raw, f"HTTP {exc.code}",
                                  time.time() - t0)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:60]}"


def _telegram_answered(code: int, raw: bytes, кратко: str,
                       dt: float) -> tuple[bool, str]:
    """Ответ Telegram отличается от ответа прокси и от таймаута.

    Разбираем тело: у настоящего Telegram это JSON с полем ok и
    числом error_code. Ни один кэш, балансировщик и не прокси не
    подставляет такую структуру.
    """
    if raw:
        try:
            тело = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            тело = None
        if isinstance(тело, dict) and "ok" in тело and "error_code" in тело:
            описание = тело.get("description", "")[:52]
            return True, f"{кратко} за {dt:.2f}с, {тело['error_code']} {описание}"
    return False, f"{кратко} за {dt:.2f}с, тело не от Telegram"


class _ConnectTo:  # noqa: N818  -- удалено, см. заперто_на_адрес
    """Не используется. Оставлено как напоминание о неудачном варианте.

    Первый вариант инструмента подменял адрес соединения через
    http.client.HTTPSConnection(ip, ...). Так делать нельзя:
    HTTPSConnection передаёт в wrap_socket server_hostname=self.host,
    то есть в SNI ушёл бы сам адрес, а проверка сертификата стала бы
    проверкой сертификата для IP. Соединение перестало бы быть
    соединением с Telegram.

    Рабочий способ — подмена getaddrinfo, см. заперто_на_адрес.
    """


# ------------------------------------------------------- system state

def iptables_rules() -> list[str]:
    try:
        proc = subprocess.run(["iptables", "-t", "nat", "-S", "OUTPUT"],
                              capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return [стр for стр in proc.stdout.splitlines()
            if "DNAT" in стр and str(TELEGRAM_PORT) in стр]


def awg_peers() -> str:
    """Число пиров на туннеле. Контроль: инструмент не должен его менять."""
    for имя in ("awg0", "wg0"):
        try:
            proc = subprocess.run(["awg", "show", имя, "peers"],
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                n = len([s for s in proc.stdout.splitlines() if s.strip()])
                return f"{имя}={n}"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return "нет туннеля"


def direct_api_works(timeout: float = 12.0) -> tuple[bool, str]:
    """Отвечает ли api.telegram.org при обычном обращении, без обходов."""
    url = f"https://{TELEGRAM_HOST}/bot{DEAD_TOKEN}/getMe"
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
            return _telegram_answered(resp.status, raw,
                                      f"HTTP {resp.status}", time.time() - t0)
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read()
        except Exception:
            pass
        return _telegram_answered(exc.code, raw, f"HTTP {exc.code}",
                                  time.time() - t0)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:60]}"


# ------------------------------------------------------------ generators

def днать(адрес: str) -> str:
    """Проверить, что адрес похож на IPv4, прежде чем писать его в правило.

    Без этой проверки значение из резолвера попало бы в команду iptables
    как есть. Строка, начинающаяся с «-», в iptables читается как флаг;
    строка с пробелом разорвала бы команду. Резолвер здесь — внешний
    источник, и доверять его выводу без сверки нельзя.
    """
    части = адрес.split(".")
    if len(части) != 4:
        raise ValueError(f"не похоже на IPv4: {адрес!r}")
    for часть in части:
        if not часть.isdigit() or not 0 <= int(часть) <= 255:
            raise ValueError(f"не похоже на IPv4: {адрес!r}")
    if any(c in адрес for c in " \t\n;|&$`\"'"):
        raise ValueError(f"недопустимый символ в адресе: {адрес!r}")
    return адрес


def сгенерировать_скрипт(цель: str, рабочий: str) -> str:
    """Текст bash-скрипта, который ставит правило при загрузке.

    Отдельная функция не для красоты: текст скрипта должен
    проверяться настоящим `bash -n` и настоящим запуском, а не
    «раз он получился из f-строки, то наверное нормально».
    Проверка не требует root и не трогает сеть.
    """
    цель = днать(цель)
    рабочий = днать(рабочий)
    аргументы = правило_для(цель, рабочий)
    дата = time.strftime('%Y-%m-%d')
    # Именно пробелы, а не список Python. Ниже об этом подробнее.
    аргументы_bash = " ".join(аргументы.split())
    return f"""#!/bin/bash
# Перенаправление трафика к Telegram API на рабочий адрес.
#
# Создано автоматически: tools/sora_telegram.py fix
# Дата: {дата}
#
# ЗАЧЕМ
#   DNS отдаёт {цель}, до него TCP/443 не проходит.
#   {рабочий} отвечает. /etc/hosts не помогает: система
#   отдаёт IPv6 раньше IPv4, и соединение уходит туда.
#   Поэтому работаем на уровне пакетов.
#
# ЧТО НЕ ДЕЛАЕТ
#   Не трогает маршруты, не трогает туннели awg0/wg0, не пишет
#   в /etc/hosts. Одно правило DNAT в OUTPUT таблицы nat.
#
# Если Telegram сменит адреса, правило перестанет помогать.
# Проверить: python3 tools/sora_telegram.py verify
set -e
RULE=({аргументы_bash})
if ! iptables -t nat -C OUTPUT "${{RULE[@]}}" 2>/dev/null; then
  iptables -t nat -A OUTPUT "${{RULE[@]}}"
  echo "правило добавлено"
else
  echo "правило уже есть"
fi
"""


def сгенерировать_unit() -> str:
    """Текст unit-файла systemd. Отдельная функция — тоже ради проверки."""
    return f"""[Unit]
Description=Обход фильтрации TCP/443 к Telegram API
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={SCRIPT_PATH}

[Install]
WantedBy=multi-user.target
"""


def правило_для(цель: str, рабочий: str) -> str:
    """Аргументы правила iptables одной строкой."""
    return (f"-p tcp -d {цель} --dport {TELEGRAM_PORT} "
            f"-j DNAT --to-destination {рабочий}:{TELEGRAM_PORT}")


# ------------------------------------------------------------ commands

def cmd_check(args) -> int:
    out("=" * 66)
    out("ДИАГНОСТИКА ДОСТУПА К TELEGRAM API")
    out("=" * 66)
    out(f"  хост: {platform.platform()}")
    out(f"  имя:  {TELEGRAM_HOST}")
    out("")

    out("--- 1. Что отдаёт DNS -------------------------------------")
    адреса = resolve(TELEGRAM_HOST)
    if not адреса:
        out("  DNS не ответил. Дальше идти некуда.")
        return 1
    for ip in адреса:
        вид = "IPv6" if ":" in ip else "IPv4"
        out(f"  {ip:<40} {вид}")
    ipv6_первым = bool(адреса) and ":" in адреса[0]
    if ipv6_первым:
        out("")
        out("  ВНИМАНИЕ: IPv6 возвращается раньше IPv4.")
        out("  Запись в /etc/hosts в такой ситуации НЕ ПОМОГАЕТ —")
        out("  соединение уходит на IPv6 раньше, чем файлы дойдут до дела.")
    out("")

    out("--- 2. Контроль: фильтр не про Telegram --------------------")
    for хост, порт in CONTROL_IPS:
        ok = tcp_open(хост, int(порт), timeout=8.0)
        out(f"  {хост + ':' + порт:<42} {'отвечает' if ok else 'НЕ отвечает'}")
    out("")

    out("--- 3. Адреса Telegram: порт и настоящий HTTPS --------------")
    рабочий = None
    for ip in KNOWN_IPS:
        порт_ok = tcp_open(ip, TELEGRAM_PORT, timeout=8.0)
        if not порт_ok:
            out(f"  {ip:<20} порт закрыт")
            continue
        ok, причина = probe_tls(ip, timeout=args.timeout)
        out(f"  {ip:<20} порт открыт, {причина}")
        if ok and рабочий is None:
            рабочий = ip
    out("")

    out("--- 4. Как обращается система сама -------------------------")
    ok, причина = direct_api_works(timeout=args.timeout)
    out(f"  {TELEGRAM_HOST}: {причина}")
    out("")

    out("--- 5. Уже установленные правила ---------------------------")
    правила = iptables_rules()
    if правила:
        for стр in правила:
            out(f"  {стр}")
    else:
        out("  перенаправлений нет")
    out("")
    out(f"  контроль туннеля: {awg_peers()}")
    out("")

    if ok:
        out("ИТОГ: API доступен, ничего чинить не нужно.")
        return 0
    if рабочий:
        out(f"ИТОГ: API недоступен из-за фильтрации, но адрес {рабочий} работает.")
        out(f"      Запустите:  sudo python3 tools/sora_telegram.py fix")
        return 2
    out("ИТОГ: ни один известный адрес не отвечает.")
    out("      Скорее всего, фильтр шире, чем предполагалось:")
    out("      проверьте провайдера или попробуйте другой сервер.")
    return 3


def cmd_fix(args) -> int:
    if not sys.platform.startswith("linux"):
        die("перенаправление настраивается только на Linux")
    if os.geteuid() != 0:
        die("нужны права root: iptables и systemd")

    out("=" * 66)
    out("ВКЛЮЧЕНИЕ ПЕРЕНАПРАВЛЕНИЯ")
    out("=" * 66)

    пиры_до = awg_peers()

    out("")
    out("--- 1. Ищем рабочий адрес ----------------------------------")
    заблокированный = None
    for ip in KNOWN_IPS:
        ok, причина = probe_tls(ip, timeout=args.timeout)
        out(f"  {ip:<20} {'ЖИВ  ' if ok else 'нет  '} {причина}")
        if ok and заблокированный is None:
            заблокированный = ip
    if not заблокированный:
        die("нет ни одного рабочего адреса, перенаправлять не на что")

    # Адрес назначения берём из DNS: именно он ломается.
    кандидаты = [ip for ip in resolve(TELEGRAM_HOST) if ":" not in ip]
    if not кандидаты:
        die("DNS не отдал ни одного IPv4 для api.telegram.org")
    цель = кандидаты[0]

    if цель == заблокированный:
        out("")
        out("  DNS отдаёт тот же адрес, который отвечает. Ничего менять не нужно.")
        return 0

    out("")
    out(f"--- 2. Перенаправляем {цель}:443 -> {заблокированный}:443 ---------")
    правило = правило_для(днать(цель), днать(заблокированный))
    аргументы = правило.split()
    уже_есть = subprocess.run(["iptables", "-t", "nat", "-C", "OUTPUT"] + аргументы,
                              capture_output=True, text=True).returncode == 0
    if уже_есть:
        out("  правило уже есть")
    else:
        proc = subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT"] + аргументы,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            die(f"iptables отклонил правило: {proc.stderr.strip()[:120]}")
        out("  правило добавлено")
    out(f"    iptables -t nat -A OUTPUT {правило}")
    out("")

    out("--- 3. Делаем правило переживающим перезагрузку --------------")
    Path(SCRIPT_PATH).write_text(сгенерировать_скрипт(цель, заблокированный),
                                 encoding="utf-8", newline="\n")
    os.chmod(SCRIPT_PATH, 0o755)
    out(f"  записан {SCRIPT_PATH}")

    Path(SERVICE_PATH).write_text(сгенерировать_unit(),
                                  encoding="utf-8", newline="\n")
    out(f"  записан {SERVICE_PATH}")

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", SERVICE_NAME],
                   capture_output=True, text=True)
    r = subprocess.run(["systemctl", "restart", SERVICE_NAME],
                       capture_output=True, text=True)

    # Служба поднята или нет — это проверяется, а не предполагается.
    #
    # Без этой проверки инструмент отчитывался об успехе при упавшей
    # службе, и это худший вид поломки: правило работает СЕЙЧАС, всё
    # выглядит исправным, а после перезагрузки доступ к Telegram
    # исчезает. Обнаружить это можно через месяц и по чужому жалобу.
    #
    # Именно так и случилось при первой сборке: systemd падал, потому
    # что в скрипт попал список Python, а код возврата был 0.
    жив = subprocess.run(["systemctl", "is-active", SERVICE_NAME],
                        capture_output=True, text=True).stdout.strip()
    состояние = subprocess.run(["systemctl", "is-enabled", SERVICE_NAME],
                              capture_output=True, text=True).stdout.strip()
    out(f"  автозапуск: {состояние}, служба: {жив}")
    служба_упала = r.returncode != 0 or жив != "active"
    if служба_упала:
        out("")
        out("  ВНИМАНИЕ: служба автозапуска НЕ поднялась.")
        out("  Правило работает сейчас, но после перезагрузки пропадёт,")
        out("  и доступ к Telegram пропадёт вместе с ним.")
        out("")
        out("  Что сказала служба:")
        for строка in (r.stderr or r.stdout or "").strip().splitlines()[:6]:
            out(f"    {строка}")
        out("")
        out("  Разбор вручную:")
        out(f"    bash -n {SCRIPT_PATH}")
        out(f"    {SCRIPT_PATH}")
        out(f"    journalctl -u {SERVICE_NAME} -n 20 --no-pager")
    out("")

    пиры_после = awg_peers()
    out("--- Контроль: туннель не задет -----------------------------")
    out(f"  до:    {пиры_до}")
    out(f"  после: {пиры_после}")
    if пиры_до != пиры_после:
        out("")
        out("  ВНИМАНИЕ: число пиров изменилось. Инструмент этого делать")
        out("  не должен был. Проверьте, что произошло, до того как")
        out("  отправлять ботов в работу.")
    else:
        out("  не изменилось")
    out("")

    код = cmd_verify(args)
    if служба_упала:
        out("")
        out("ИТОГ: сейчас работает, после перезагрузки — нет.")
        out("      Чинить надо до перезагрузки, а не после.")
        return 6
    return код


def cmd_verify(args) -> int:
    out("--- ПРОВЕРКА ----------------------------------------------")
    ok, причина = direct_api_works(timeout=args.timeout)
    out(f"  {TELEGRAM_HOST}: {причина}")
    правила = iptables_rules()
    for стр in правила:
        out(f"  правило: {стр}")

    # Перенаправление живо ровно настолько, насколько жив адрес
    # назначения в нём. Проверяем адрес напрямую.
    for стр in правила:
        части = стр.split("--to-destination")
        if len(части) < 2:
            continue
        цель = части[1].strip().split(":")[0]
        жив, почему = probe_tls(цель, timeout=args.timeout)
        out(f"  адрес в правиле {цель}: {'ЖИВ' if жив else 'МЁРТВ'} — {почему}")
        if not жив:
            out("")
            out("  ВНИМАНИЕ: перенаправление ведёт на мёртвый адрес.")
            out("  Telegram сменил адреса. Запустите fix заново.")
            return 4
    out(f"  контроль туннеля: {awg_peers()}")
    out("")
    out("ИТОГ: API доступен." if ok else "ИТОГ: API по-прежнему недоступен.")
    return 0 if ok else 5


def аргументы_удаления(строка: str) -> list[str] | None:
    """Аргументы для `iptables -D` по строке из `iptables -S`.

    Отдельная функция ради теста. Именно здесь в первой версии была
    ошибка: адрес брался из `--to-destination` (куда перенаправляем)
    и подставлялся в `-d` (откуда уходит трафик). Правило не
    совпадало, удаление не срабатывало, а цикл не останавливался.

    Здесь адрес не разбирается вообще. Берутся те же аргументы,
    которые напечатал iptables, и меняется только -A на -D.
    """
    части = строка.split()
    if len(части) < 3:
        return None
    if части[0] != "-A" or части[1] != "OUTPUT":
        return None
    return части[2:]


def удалить_правило(строка: str) -> bool:
    """Удалить правило ровно в том виде, в каком его показал iptables -S."""
    аргументы = аргументы_удаления(строка)
    if аргументы is None:
        return False
    proc = subprocess.run(["iptables", "-t", "nat", "-D", "OUTPUT"] + аргументы,
                          capture_output=True, text=True)
    return proc.returncode == 0


def cmd_revert(args) -> int:
    if os.geteuid() != 0:
        die("нужны права root")
    out("Снимаем перенаправление...")

    # Счётчик не «сколько раз попытались», а «сколько раз получилось».
    # Если за проход ничего не удалилось — выходим, а не повторяем.
    # Иначе ошибка в разборе правила превращается в бесконечный цикл.
    удалено = 0
    for _проход in range(20):
        правила = iptables_rules()
        if not правила:
            break
        за_проход = 0
        for стр in правила:
            if удалить_правило(стр):
                удалено += 1
                за_проход += 1
                out(f"  снято: {стр}")
            else:
                out(f"  НЕ СНЯТО: {стр}")
                out("  Правило осталось. Скорее всего, его формат")
                out("  не совпадает с ожидаемым — снять его надо вручную:")
                out(f"    iptables -t nat -D OUTPUT{' '.join(стр.split()[2:])}")
        if за_проход == 0:
            break

    subprocess.run(["systemctl", "disable", "--now", SERVICE_NAME],
                   capture_output=True)
    for путь in (SCRIPT_PATH, SERVICE_PATH):
        if Path(путь).exists():
            Path(путь).unlink()
            out(f"  удалён {путь}")
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    осталось = iptables_rules()
    out("")
    if осталось:
        out(f"ВНИМАНИЕ: осталось правил: {len(осталось)}")
        for стр in осталось:
            out(f"  {стр}")
        return 1
    out(f"Готово. Снято правил: {удалено}. Перенаправлений не осталось.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Диагностика и обход фильтрации до Telegram Bot API")
    ap.add_argument("команда",
                    choices=["check", "fix", "verify", "revert"],
                    help="что сделать")
    ap.add_argument("--timeout", type=float, default=12.0,
                    help="таймаут одной пробы, секунд (по умолчанию 12)")
    args = ap.parse_args()

    if args.команда == "check":
        return cmd_check(args)
    if args.команда == "fix":
        return cmd_fix(args)
    if args.команда == "verify":
        return cmd_verify(args)
    return cmd_revert(args)


if __name__ == "__main__":
    raise SystemExit(main())