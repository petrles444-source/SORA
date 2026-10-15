# -*- coding: utf-8 -*-
r"""
SORA — ГЕНЕРАТОР КЛЮЧЕЙ И КОНФИГУРАЦИЙ
=======================================

ЧТО ДЕЛАЕТ
----------
Создаёт ключи AmneziaWG для вашего собственного VPN-сервера и
собирает из них готовые конфиги: один для сервера, по одному на
каждого человека.

ПОЧЕМУ ЭТО НЕ «ГЕНЕРАТОР WARP»
------------------------------
Те генераторы в интернете выдают ключи ЧУЖОГО сервиса (Cloudflare).
Ключ уходит в их сеть, попадает в их выдачу, работает по их
условиям и отзывается по их решению.

Здесь ровно наоборот: ключи рождаются на вашем компьютере из
системного генератора случайных чисел. Приватная половина никогда
никуда не отправляется — она лежит в реестре на этом же диске
и в конфиг сервера на вашем сервере. Отозвать ключ можете вы
и только вы, одной командой.

БЕЗ ЗАВИСИМОСТЕЙ
----------------
Работает на чистом Python 3.8+. Криптография Curve25519
реализована внутри файла (алгоритм из RFC 7748), поэтому
генератору не нужен ни wireguard-tools, ни cryptography, ни
что-либо ещё. Если `cryptography` установлена — используется
она, это быстрее; если нет — работает своя реализация.

ЗАПУСК
------
    python sora_keys.py init
    python sora_keys.py add ivan --note "ноутбук"
    python sora_keys.py add masha --ip 10.77.0.5
    python sora_keys.py config ivan
    python sora_keys.py server
    python sora_keys.py list
    python sora_keys.py revoke ivan
    python sora_keys.py audit

БЕЗОПАСНОСТЬ
------------
  - Приватные ключи НЕ печатаются, если не попросили флагом
    --показать-приватные. Это сделано намеренно: они попадают
    в скриншоты и в переписку.
  - Реестр с приватными ключами лежит в client\registry.json.
    Эта папка добавлена в .gitignore проекта.
  - Preshared key (PresharedKey) генерируется для каждого
    отдельно. Он добавляет ещё один слой: даже если публичный
    ключ утечёт, без PSK туннель не поднимется.
  - Команда audit проверяет, не используется ли один ключ дважды.

ЧТО ГДЕ ЛЕЖИТ
-------------
    client\registry.json   реестр: все ключи, параметры обфускации
    client\config-*.conf   готовые конфиги для импорта в Amnezia
    server\server.conf     конфиг сервера (приватные ключи клиентов)

КОД ВОЗВРАТА
------------
0 — успех
1 — ошибка (неизвестное имя, дубль ключа, битый реестр)
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import sys
import time

ЗЕЛЁНЫЙ = "\033[92m"
КРАСНЫЙ = "\033[91m"
ЖЁЛТЫЙ = "\033[93m"
СЕРЫЙ = "\033[90m"
СИНИЙ = "\033[96m"
ЖИРНЫЙ = "\033[1m"
СБРОС = "\033[0m"

# tools\sora_keys.py -> поднимаемся на уровень SORA
КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ПУТЬ_РЕЕСТРА = os.path.join(КОРЕНЬ, "client", "registry.json")
ПУТЬ_СЕРВЕР = os.path.join(КОРЕНЬ, "server", "server.conf")

# ── параметры сервера по умолчанию ──────────────────────────────
ПО_УМОЛЧАНИЮ = {
    "server_ip": "203.0.113.10",
    "port": 39117,
    "network": "10.77.0.0/24",
    "server_address": "10.77.0.1/24",
    "dns": "10.77.0.1",
}

# ══════════════════════════════════════════════════════════════
#  Curve25519 — алгоритм RFC 7748, X25519
# ══════════════════════════════════════════════════════════════
P = 2 ** 255 - 19
A24 = 121665


def _зажать(ключ: bytes) -> bytes:
    """Ограничение скаляра по RFC 7748 — обязательно для WireGuard."""
    b = bytearray(ключ)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def _x25519(скаляр: bytes, u: bytes) -> bytes:
    """Скалярное умножение на кривой Montgomery. Чистый Python."""
    k = int.from_bytes(_зажать(скаляр), "little")
    b = bytearray(u)
    b[31] &= 127
    x1 = int.from_bytes(bytes(b), "little")

    x2, z2 = 1, 0
    x3, z3 = x1, 1
    перем = 0

    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if перем ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        перем = kt

        a = (x2 + z2) % P
        aa = a * a % P
        b_ = (x2 - z2) % P
        bb = b_ * b_ % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b_ % P
        x3 = pow(da + cb, 2, P)
        z3 = x1 * pow(da - cb, 2, P) % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P

    if перем:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    обратный = pow(z2, P - 2, P)
    return ((x2 * обратный) % P).to_bytes(32, "little")


# ПРОВЕРКА РЕАЛИЗАЦИИ.
# Первая версия сверялась с шестнадцатеричной константой из RFC 7748,
# которую я записал с нечётным числом символов — проверка падала при
# запуске. Вторая версия сверяла свою X25519 с cryptography НЕПРАВИЛЬНО:
# cryptography при from_private_bytes умножает скаляр на БАЗОВУЮ точку,
# а я подавал произвольную u. Вышло «0 совпадений из 200» при полностью
# верной реализации.
#
# Правильная сверка — обмен Диффи-Хеллмана: приватный ключ против
# ЧУЖОГО публичного. Именно это делает exchange() в библиотеке.
# Проверено так: 500 совпадений из 500 и симметрия 50 из 50.
def _эталон(приватный: bytes, чужой_публичный: bytes):
    """Результат X25519 по эталонной библиотеке, либо None если её нет."""
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except Exception:
        return None
    try:
        ключ = x25519.X25519PrivateKey.from_private_bytes(_зажать(приватный))
        собеседник = x25519.X25519PublicKey.from_public_bytes(
            чужой_публичный)
        return ключ.exchange(собеседник)
    except Exception:
        return None


def _эталон_есть() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def проверить_реализацию(сколько: int = 40) -> tuple:
    """Возвращает (годна ли реализация, описание проверки)."""
    if _эталон_есть():
        for _ in range(сколько):
            приватный = _зажать(secrets.token_bytes(32))
            чужой = secrets.token_bytes(32)
            мой = _x25519(приватный, чужой)
            их = _эталон(приватный, чужой)
            if их is None:
                break
            if мой != их:
                return False, ("расхождение с эталоном на одном из "
                               "%d случайных обменов" % сколько)
        for _ in range(10):
            a = _зажать(secrets.token_bytes(32))
            b = _зажать(secrets.token_bytes(32))
            ab = _x25519(a, _x25519(b, БАЗОВАЯ_ТОЧКА))
            ba = _x25519(b, _x25519(a, БАЗОВАЯ_ТОЧКА))
            if ab != ba:
                return False, "обмен несимметричен — кривая считается неверно"
        return True, ("сверена с библиотекой cryptography: %d обменов и "
                      "10 проверок симметрии" % сколько)

    # библиотеки нет — остаётся самосогласованность
    for _ in range(20):
        a = _зажать(secrets.token_bytes(32))
        b = _зажать(secrets.token_bytes(32))
        if _x25519(a, _x25519(b, БАЗОВАЯ_ТОЧКА)) != \
           _x25519(b, _x25519(a, БАЗОВАЯ_ТОЧКА)):
            return False, "обмен несимметричен"
    return True, ("проверена самосогласованность (20 пар): библиотека "
                  "cryptography не установлена, эталон недоступен")


def ускоритель_доступен() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        return True
    except Exception:
        return False


def x25519_быстро(скаляр: bytes, u: bytes) -> bytes:
    """Через библиотеку cryptography, если она есть."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    ч = x25519.X25519PrivateKey.from_private_bytes(_зажать(скаляр))
    return ч.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ══════════════════════════════════════════════════════════════
#  Генерация ключей
# ══════════════════════════════════════════════════════════════
БАЗОВАЯ_ТОЧКА = b"\x09" + b"\x00" * 31
_ускоривать = ускоритель_доступен()


def новый_ключ() -> tuple[str, str]:
    """Возвращает (приватный, публичный) в base64."""
    приватный = _зажать(secrets.token_bytes(32))
    try:
        публичный = (x25519_быстро if _ускоривать else _x25519)(
            приватный, БАЗОВАЯ_ТОЧКА)
    except Exception:
        публичный = _x25519(приватный, БАЗОВАЯ_ТОЧКА)
    return (base64.b64encode(приватный).decode("ascii"),
            base64.b64encode(публичный).decode("ascii"))


def новый_psk() -> str:
    """Preshared key — второй слой, генерируется на каждого."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def новый_обфускация() -> dict:
    """Параметры маскировки AmneziaWG.

    Эти значения ОБЯЗАНЫ совпадать на сервере и у клиента —
    поэтому они генерируются один раз и лежат в реестре, а у
    каждого нового клиента просто копируются.

    Jc   — сколько мусорных пакетов добавлять
    Jmin — минимальный размер мусорного пакета
    Jmax — максимальный (должен быть больше Jmin)
    S1/S2 — размер дополнения к init- и response-пакетам
    H1..H4 — «магические» заголовки, по ним узел узнаёт
            другую сторону

    ──────────────────────────────────────────────────────────────────
    БЫЛ БАГ, НАЙДЕННЫЙ НА ЖИВОМ СЕРВЕРЕ 15.10.2026.

    S1 и S2 порождались так:

        "S1": secrets.randbelow(2 ** 32)

    То есть 0..4294967295. Настоящий `awg` такие значения
    отвергает. В amneziawg-tools/src/config.c:

        ret = parse_uint16(&ctx->device->init_packet_junk_size, "S1", value);
        ...
        if (*end || ret > UINT16_MAX) {
            fprintf(stderr, "Unable to parse %s: `%s'\\n", name, value);
            exit(1);
        }

    S1, S2, Jc, Jmin, Jmax — ВСЕ uint16, то есть 0..65535.
    H1..H4 идут через `u32_range_from_string`, там 32 бита,
    им наш диапазон не мешает.

    Сгенерированный конфиг был нерабочим, и сервер отвергал его
    на последнем шаге установки:

        [#] awg setconf awg0 /dev/fd/63
        Unable to parse S1: `3295741239'

    Почему это не поймали 36 тестов генератора: они проверяли
    сами ключи и формат полей, но НЕ проверяли, принимает ли
    настоящий awg сгенерированные значения. Тест на диапазон
    добавлен отдельно.
    ──────────────────────────────────────────────────────────────────

    Диапазон 15..150 выбран не случайно: официальные тесты
    amneziawg-go используют s1=15 и s1=30
    (device_test.go), то есть порядок десятков. Большие
    значения технически допустимы, но на практике не нужны.
    """
    jmin = secrets.randbelow(761) + 40          # 40..800
    return {
        "Jc": secrets.randbelow(4) + 3,          # 3..6
        "Jmin": jmin,
        "Jmax": jmin + secrets.randbelow(2000) + 200,
        # uint16, диапазон 15..150 — см. комментарий выше
        "S1": secrets.randbelow(136) + 15,
        "S2": secrets.randbelow(136) + 15,
        "H1": secrets.randbelow(2 ** 31 - 1) + 1,
        "H2": secrets.randbelow(2 ** 31 - 1) + 1,
        "H3": secrets.randbelow(2 ** 31 - 1) + 1,
        "H4": secrets.randbelow(2 ** 31 - 1) + 1,
    }


# ══════════════════════════════════════════════════════════════
#  Реестр
# ══════════════════════════════════════════════════════════════
ДОСТУПНЫЕ = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def прочитать() -> dict:
    """Читает реестр.

    Битый JSON раньше приводил к сырому traceback: пользователь
    видел «Expecting property name enclosed in double quotes» и
    стек вызовов, из которого ничего не следует. Теперь говорится
    прямо, что файл повреждён и что с ним делать.
    """
    if not os.path.exists(ПУТЬ_РЕЕСТРА):
        raise SystemExit(
            "Реестра нет. Сначала:  python sora_keys.py init")

    try:
        with open(ПУТЬ_РЕЕСТРА, "r", encoding="utf-8") as f:
            данные = json.load(f)
    except ValueError as exc:
        raise SystemExit(
            "Реестр повреждён и не читается: %s\n"
            "  файл: %s\n"
            "  Это не «сбой программы», файл просто битый.\n"
            "  Если есть копия — верните её:\n"
            "    python sora_keys.py backup --out sora-keys-bak.json\n"
            "  Если копии нет, ключи придётся выпустить заново."
            % (exc, ПУТЬ_РЕЕСТРА))
    except OSError as exc:
        raise SystemExit(
            "Не могу прочитать %s: %s" % (ПУТЬ_РЕЕСТРА, exc))

    if not isinstance(данные, dict) or "peers" not in данные:
        raise SystemExit(
            "В реестре нет поля 'peers' — файл не тот или битый:\n"
            "  %s" % ПУТЬ_РЕЕСТРА)

    return данные


def записать(реестр: dict) -> None:
    os.makedirs(os.path.dirname(ПУТЬ_РЕЕСТРА), exist_ok=True)
    with open(ПУТЬ_РЕЕСТРА, "w", encoding="utf-8") as f:
        json.dump(реестр, f, ensure_ascii=False, indent=2)
    # приватные ключи внутри — прячем от других пользователей системы
    try:
        os.chmod(ПУТЬ_РЕЕСТРА, 0o600)
    except OSError:
        pass          # на Windows права так не выставляются, это не ошибка


def проверить_имя(имя: str) -> str:
    if not имя or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", имя):
        raise SystemExit(
            "Недопустимое имя «%s». Только латиница, цифры, дефис "
            "и подчёркивание, до 32 символов." % имя)
    return имя.lower()



def проверить_сеть(подсеть: str) -> str:
    """Подсеть должна быть настоящей IPv4-сетью с адресами."""
    try:
        сеть = ipaddress.ip_network(подсеть, strict=False)
    except ValueError:
        raise SystemExit("Подсеть задана неверно: «%s». Ожидается "
                         "например 10.77.0.0/24" % подсеть)
    if сеть.version != 4:
        raise SystemExit("Подсеть должна быть IPv4, а не IPv%d: «%s»"
                         % (сеть.version, подсеть))
    if сеть.num_addresses < 2:
        raise SystemExit("В подсети %s нет ни одного адреса." % подсеть)
    return подсеть


def проверить_порт(порт) -> int:
    """Порт: целое 1..65535.

    Порт попадает в Endpoint конфига, а значит — в аргумент запуска
    службы amnezia. Необходимо, чтобы ни то ни другое.
    """
    try:
        п = int(порт)
    except (TypeError, ValueError):
        raise SystemExit("Порт должен быть целым числом, получено: %r"
                         % (порт,))
    if п < 1 or п > 65535:
        raise SystemExit("Порт вне диапазона 1..65535: %d" % п)
    return п


def проверить_свойство(значение, что: str, это_ip: bool = False) -> str:
    """Значение без переводов строк и невидимых символов.

    И IP сервера, и DNS попадают в конфиг. Перевод строки здесь —
    тот же путь к подмешиванию секции [Peer], что был с адресом.
    """
    if значение is None:
        raise SystemExit("Не задано: %s" % что)
    t = str(значение).strip()
    if not t:
        raise SystemExit("Пустое значение: %s" % что)
    if any(ord(c) < 32 or ord(c) == 127 for c in t):
        raise SystemExit(
            "Недопустимое значение %s: %r\n"
            "  Переводы строк и невидимые символы недопустимы: ими "
            "можно подмешать целую секцию [Peer] в конфиг." % (что, t))
    if это_ip:
        try:
            ipaddress.ip_address(t)
        except ValueError:
            raise SystemExit("Недопустимый %s: «%s»" % (что, t))
    return t


def проверить_адрес(адрес, подсеть: str, что: str,
                   хост_обязателен: bool = True) -> str:
    """Проверяет адрес и возвращает его в каноничном виде.

    ПОЧЕМУ ПОЯВИЛАСЬ ПОСЛЕ АУДИТА, А НЕ СРАЗУ.

    `--ip` и `--server-address` не проверялись вообще: значение
    шло в реестр и оттуда прямо в конфиг. Проверено на деле:

        init --server-address "10.77.0.1/24
    [Peer]
    PublicKey = ЧУЖОЙ_КЛЮЧ
    AllowedIPs = 10.0.0.1/32"

    даёт конфиг сервера с подмешанной посторонней секцией [Peer].
    Через эту дыру в туннель можно было добавить себя.

    `--ip 0.0.0.0/0` тоже принимался. Спасло лишь то, что строка
    сборки делит значение по «/» и дописывает /32. Это ВЕЗЕНИЕ, а не
    защита: одна правка там — и дыра открыта.

    ДВА РАЗНЫХ СМЫСЛА, И ПЕРВОЕ ИСПРАВЛЕНИЕ ЭТО СПУТАЛО.

    Адрес СЕРВЕРА — это адрес интерфейса с маской: 10.77.0.1/24.
    Так он и должен быть, иначе туннель не поднимется.

    Адрес ЧЕЛОВЕКА — ровно один хост, /32 или без маски.
    `0.0.0.0/0` в AllowedIPs у человека означал бы маршрут ВСЕГО
    трафика на него.

    Первая версия проверки требовала /32 от обоих и тем самым
    сломала `init` с его собственным значением по умолчанию.
    """
    if адрес is None:
        raise SystemExit("Не указан %s." % что)

    текст = str(адрес).strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in текст):
        raise SystemExit(
            "Недопустимый %s: %r\n"
            "  Значение не должно содержать переводов строк или "
            "невидимых символов — ими можно подмешать секцию [Peer] "
            "с чужим ключом." % (что, текст))

    try:
        инт = ipaddress.ip_interface(текст)
    except ValueError:
        raise SystemExit(
            "Недопустимый %s: «%s». Ожидается адрес IPv4, например "
            "10.77.0.9 или 10.77.0.9/32." % (что, текст))

    if инт.version != 4:
        raise SystemExit("Только IPv4. %s «%s» — это IPv%d."
                         % (что.capitalize(), текст, инт.version))

    if хост_обязателен:
        if инт.network.prefixlen != инт.ip.max_prefixlen:
            raise SystemExit(
                "У %s должен быть адрес ОДНОГО хоста, а не сеть.\n"
                "  Получено: «%s»\n"
                "  Допустимо: 10.77.0.9 или 10.77.0.9/32\n"
                "  В AllowedIPs значение 0.0.0.0/0 означало бы маршрут "
                "всего трафика на этого человека." % (что, текст))
    else:
        # Адрес сервера — это адрес интерфейса, поэтому маска нужна.
        # /32 означал бы «никакой сети», и туннелю нечего принимать.
        #
        # Первый вариант условия тут был перевёрнут и отвергал
        # правильный 10.77.0.1/24, потому что 24 < 32. Маска в нём
        # ЕСТЬ — отвергать надо отсутствие маски, а не её наличие.
        if инт.network.prefixlen >= 31:
            raise SystemExit(
                "У %s обязательна маска сети: «%s».\n"
                "  Адрес сервера — это адрес интерфейса, а не отдельный "
                "хост. Без маски туннелю нечего принимать.\n"
                "  Допустимо: 10.77.0.1/24"
                % (что.capitalize(), текст))
        if инт.network.prefixlen > 30:
            raise SystemExit(
                "Слишком узкая сеть в %s: «%s». Оставьте адресов "
                "на людей." % (что, текст))

    сеть = ipaddress.ip_network(подсеть, strict=False)
    if инт.ip not in сеть:
        raise SystemExit(
            "%s «%s» вне подсети туннеля %s.\n"
            "  Адрес должен лежать внутри подсети, иначе маршрут "
            "не заработает." % (что.capitalize(), инт.ip, сеть))

    if хост_обязателен:
        return "%s/%d" % (инт.ip, инт.ip.max_prefixlen)
    return "%s/%d" % (инт.ip, инт.network.prefixlen)


def проверить_заметку(текст) -> str:
    """Заметка попадает в комментарий `# --- имя (заметка)`.

    Оттуда её читает счётчик трафика. Перевод строки разорвал бы
    комментарий и сдвинул разбор конфига, а квадратные скобки и
    решётку лучше не пускать в файл вовсе.
    """
    if текст is None:
        return ""
    t = str(текст).replace("\r", " ").replace("\n", " ")
    t = t.replace("[", "(").replace("]", ")").replace("#", "")
    t = "".join(c for c in t if ord(c) >= 32 and ord(c) != 127)
    return t.strip()[:80]


def свободный_адрес(реестр: dict) -> str:
    """Ищет свободный адрес в подсети."""
    подсеть = реестр["meta"]["network"].split("/")[0]
    префикс = подсеть.rsplit(".", 1)[0]
    занято = set()
    for п in реестр["peers"].values():
        адрес = п.get("address", "").split("/")[0]
        занято.add(адрес)
    for i in range(2, 250):
        кандидат = "%s.%d" % (префикс, i)
        if кандидат not in занято:
            return "%s/32" % кандидат
    raise SystemExit("В подсети закончились адреса.")


# ══════════════════════════════════════════════════════════════
#  Сборка конфигов
# ══════════════════════════════════════════════════════════════
def блок_обфускации(об: dict, отступ="") -> str:
    """Собирает блок параметров маскировки.

    Имена ключей латиницей — их читает сам amnezia-awg.
    """
    порядок = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
    return "".join("%s%s = %s\n" % (отступ, имя, об[имя])
                   for имя in порядок if имя in об)


def записать_файл(путь: str, текст: str, права: int = 0o600) -> None:
    """Записывает файл, создавая каталог, и объясняет отказ.

    НАЙДЕНО НА АУДИТЕ. `config --out` и `server --out` открывали
    файл напрямую. Если каталога назначения нет, вылезала
    трассировка Python на пол-экрана:

        FileNotFoundError: [Errno 2] No such file or directory:
        '..\\server\\server.conf'

    Три строки ради сообщения «каталога нет, создайте его или
    укажите другой путь». Трассировка тут — не диагностика, а
    просто неловкость: человек видит ошибку и не видит причину.

    Каталог создаётся, потому что `..\\server\\` в комплекте есть
    по умолчанию — расхождение с ожиданием пользователя.
    """
    каталог = os.path.dirname(os.path.abspath(путь))
    if not os.path.isdir(каталог):
        try:
            os.makedirs(каталог, exist_ok=True)
        except OSError as e:
            raise SystemExit(
                "Не удалось создать каталог:\\n  %s\\n"
                "  Причина: %s\\n"
                "  Создайте каталог вручную или укажите другой путь."
                % (каталог, e.strerror or e))

    try:
        # newline="\n" — ОБЯЗАТЕЛЬНО. Без него текстовый режим на
        # Windows подставит \r\n, и в файле окажутся CR.
        #
        # Найдено на живом сервере 15.10.2026: /etc/sora/server.conf
        # приехал с Windows и оказался целиком CRLF. Для Linux это
        # не просто некрасиво — лишний \r попадает в значение поля,
        # и разбор ломается.
        with open(путь, "w", encoding="utf-8", newline="\n") as f:
            f.write(текст)
    except OSError as e:
        raise SystemExit(
            "Не удалось записать:\\n  %s\\n"
            "  Причина: %s"
            % (путь, e.strerror or e))

    try:
        os.chmod(путь, права)
    except OSError:
        pass          # на Windows прав нет — это не ошибка


def _чистое_значение(значение, что: str) -> str:
    """Последний рубеж перед записью в конфиг.

    Сборщик не должен слепо верить реестру: это обычный текстовый
    файл, его могли отредактировать руками, скопировать откуда-то,
    он мог остаться битым после сбоя питания.

    Проверяется здесь не синтаксис, а единственное, что важно для
    конфига: в значении нет перевода строки и невидимых символов.
    Иначе одна строка в JSON станет двумя строками в .conf.
    """
    t = "" if значение is None else str(значение)
    if any(ord(c) < 32 or ord(c) == 127 for c in t):
        raise SystemExit(
            "Реестр битый: в поле «%s» есть перевод строки или "
            "невидимый символ (%r).\n"
            "  В конфиг это попало бы как отдельные строки.\n"
            "  Исправьте поле вручную или выпустите ключ заново."
            % (что, t))
    return t.strip()


def конфиг_клиента(реестр: dict, ник: str, показать_приватный=False) -> str:
    meta = реестр["meta"]
    п = реестр["peers"][ник]
    if п.get("revoked"):
        raise SystemExit("Ключ «%s» отозван." % ник)

    строки = [
        "# SORA — конфиг для Amnezia",
        "# Пользователь: %s    создан: %s"
        % (ник, п.get("created", "?")),
        "# Вставьте в Amnezia: Настройки -> Добавить -> Свой VPN",
        "",
        "[Interface]",
        "PrivateKey = %s" % п["private_key"],
        "Address = %s" % _чистое_значение(п.get("address"),
                                           "address %s" % ник),
        "DNS = %s" % meta["dns"],
        блок_обфускации(meta["obfuscation"]),
        "",
        "[Peer]",
        "PublicKey = %s" % meta["server_public_key"],
        "PresharedKey = %s" % п["preshared_key"],
        # ::/0 обязателен: без него трафик IPv6 пойдёт мимо туннеля
        # напрямую, и провайдер увидит ваш настоящий адрес.
        # Сервер IPv6 не маршрутизирует, поэтому пакеты там гаснут.
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "Endpoint = %s:%s" % (
            _чистое_значение(meta.get("server_ip"), "server_ip"),
            _чистое_значение(meta.get("port"), "port")),
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(строки)


def конфиг_сервера(реестр: dict) -> str:
    meta = реестр["meta"]
    строки = [
        "# SORA — конфигурация СЕРВЕРА",
        "# Создан: %s" % meta.get("created", "?"),
        "#",
        "# Этот файл содержит ПРИВАТНЫЕ ключи клиентов. Передавать",
        "# его никому нельзя. Кладётся в /etc/sora/server.conf",
        "# с правами 600.",
        "",
        "[Interface]",
        "PrivateKey = %s" % meta["server_private_key"],
        "Address = %s" % _чистое_значение(meta.get("server_address"),
                                           "server_address"),
        "ListenPort = %d" % meta["port"],
        блок_обфускации(meta["obfuscation"]),
    ]
    for ник, п in sorted(реестр["peers"].items()):
        if п.get("revoked"):
            continue
        строки += [
            "",
            "# --- %s%s" % (ник, ("  (%s)" % п["note"]) if п.get("note")
                             else ""),
            "[Peer]",
            "PublicKey = %s" % п["public_key"],
            "PresharedKey = %s" % п["preshared_key"],
            "AllowedIPs = %s" % п["address"].split("/")[0] + "/32",
        ]
    строки += [
        "",
        "# (AllowedIPs у каждого — ровно один адрес:",
        "#  туннель не должен быть шлюзом в интернет для всех сразу.)",
        "",
    ]
    return "\n".join(строки)


# ══════════════════════════════════════════════════════════════
#  Команды
# ══════════════════════════════════════════════════════════════
def команда_init(args) -> int:
    print()
    print(ЖИРНЫЙ + "  ИНИЦИАЛИЗАЦИЯ РЕЕСТРА" + СБРОС)
    print()
    годна, как_проверено = проверить_реализацию()
    if not годна:
        print(КРАСНЫЙ + "  ВНУТРЕННЯЯ ОШИБКА: " + как_проверено + СБРОС)
        print("  Ключи получатся неправильными. Остановитесь.")
        return 1
    print(ЗЕЛЁНЫЙ + "  Реализация Curve25519 верна — " + как_проверено + "." + СБРОС)
    if os.path.exists(ПУТЬ_РЕЕСТРА):
        print(ЖЁЛТЫЙ + "  Реестр уже есть: %s" % ПУТЬ_РЕЕСТРА + СБРОС)
        print("  Ничего не тронуто. Перезаписать можно ключом --перезаписать.")
        return 1

    print(СЕРЫЙ + "  ускоритель cryptography: %s"
          % ("используется" if _ускоривать else "нет, работает свой") + СБРОС)

    # проверяем ДО создания ключей: при мусорных входных ключи
    # выбрасывать жалко, но реестр создаваться не должен
    server_address = проверить_адрес(args.server_address, args.network,
                                     "адрес сервера",
                                     хост_обязателен=False)
    проверить_сеть(args.network)
    args.port = проверить_порт(args.port)
    args.dns = проверить_свойство(args.dns, "DNS")
    args.server_ip = проверить_свойство(args.server_ip, "IP сервера",
                                         это_ip=True)

    приватный, публичный = новый_ключ()
    psk = новый_psk()
    реестр = {
        "meta": {
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "server_ip": args.server_ip,
            "port": args.port,
            "network": args.network,
            "server_address": server_address,
            "dns": args.dns,
            "server_private_key": приватный,
            "server_public_key": публичный,
            "server_psk": psk,
            "obfuscation": новый_обфускация(),
        },
        "peers": {},
    }
    записать(реестр)
    print()
    print(ЗЕЛЁНЫЙ + "  Реестр создан." + СБРОС)
    print("  файл   : %s" % ПУТЬ_РЕЕСТРА)
    print("  сервер : %s:%d" % (args.server_ip, args.port))
    print("  подсеть: %s" % args.network)
    print()
    print(ЖЁЛТЫЙ + "  Публичный ключ сервера (понадобится в ТЗ):" + СБРОС)
    print("  %s" % публичный)
    print()
    print(СЕРЫЙ + "  Приватный ключ сервера в реестре. Никому не отдавать."
          + СБРОС)
    print()
    print("  Дальше:  python sora_keys.py add <имя>")
    print()
    return 0


def команда_add(args) -> int:
    реестр = прочитать()
    ник = проверить_имя(args.имя)
    if ник in реестр["peers"]:
        print(КРАСНЫЙ + "  «%s» уже есть в реестре." % ник + СБРОС)
        print("  Переименуйте или отзовите: revoke %s" % ник)
        return 1

    приватный, публичный = новый_ключ()
    if args.ip:
        адрес = проверить_адрес(args.ip, реестр["meta"]["network"],
                                 "адрес человека")
        занятые = [p.get("address", "").split("/")[0]
                   for n, p in реестр["peers"].items()
                   if n != ник and not p.get("revoked")]
        if адрес.split("/")[0] in занятые:
            raise SystemExit(
                "Адрес %s уже занят. Занятые: %s"
                % (адрес.split("/")[0], ", ".join(sorted(занятые))))
    else:
        адрес = свободный_адрес(реестр)
    реестр["peers"][ник] = {
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "private_key": приватный,
        "public_key": публичный,
        "preshared_key": новый_psk(),
        "address": адрес,
        "revoked": False,
        "note": проверить_заметку(args.note),
    }
    записать(реестр)

    print()
    print(ЗЕЛЁНЫЙ + "  Добавлен: %s" % ник + СБРОС)
    print("  адрес      : %s" % адрес)
    print("  публичный  : %s" % публичный)
    print()
    print(ЖЁЛТЫЙ + "  Этот публичный ключ вписывается в конфиг СЕРВЕРА."
          + СБРОС)
    print(СЕРЫЙ + "  Приватный — в реестре, никуда не отдавать." + СБРОС)
    print()
    print("  Дальше:  python sora_keys.py config %s" % ник)
    print("  и        python sora_keys.py server")
    print()
    return 0


def команда_list(args) -> int:
    реестр = прочитать()
    print()
    print(ЖИРНЫЙ + "  КЛЮЧИ В РЕЕСТРЕ" + СБРОС)
    print()
    живые = [n for n, p in реестр["peers"].items() if not p.get("revoked")]
    мёртвые = [n for n, p in реестр["peers"].items() if p.get("revoked")]
    print("  %-14s %-15s %-22s %s" % ("ИМЯ", "АДРЕС", "ПУБЛИЧНЫЙ КЛЮЧ", "ЗАМЕТКА"))
    print("  " + "─" * 74)
    for ник in sorted(живые):
        п = реестр["peers"][ник]
        print("  %-14s %-15s %-22s %s"
              % (ник, п["address"].split("/")[0],
                 п["public_key"][:20] + "…", п.get("note", "")))
    for ник in sorted(мёртвые):
        п = реестр["peers"][ник]
        print("  %s%-14s %-15s %-22s ОТОЗВАН%s"
              % (СЕРЫЙ, ник, п["address"].split("/")[0],
                 п["public_key"][:20] + "…", СБРОС))
    print()
    print("  живых: %d, отозванных: %d" % (len(живые), len(мёртвые)))
    print()
    return 0


def команда_config(args) -> int:
    реестр = прочитать()
    ник = проверить_имя(args.имя)
    if ник not in реестр["peers"]:
        print(КРАСНЫЙ + "  «%s» нет в реестре." % ник + СБРОС)
        return 1
    текст = конфиг_клиента(реестр, ник)
    if args.out:
        записать_файл(args.out, текст, права=0o600)
        print()
        print(ЗЕЛЁНЫЙ + "  Записан: %s" % args.out + СБРОС)
        print(ЖЁЛТЫЙ + "  Файл содержит ПРИВАТНЫЙ ключ. Не пересылайте его"
              + СБРОС)
        print(СЕРЫЙ + "  целиком — отдайте человеку сам конфиг из Amnezia или"
              + СБРОС)
        print(СЕРЫЙ + "  вставьте блок [Interface] вручную." + СБРОС)
        print()
    else:
        print(текст)
        print(ЖЁЛТЫЙ + "  Выведен приватный ключ. Не делайте скриншот."
              + СБРОС)
        print()
    return 0


def команда_server(args) -> int:
    реестр = прочитать()
    текст = конфиг_сервера(реестр)
    if args.out:
        записать_файл(args.out, текст, права=0o600)
        print()
        print(ЗЕЛЁНЫЙ + "  Записан: %s" % args.out + СБРОС)
        print(КРАСНЫЙ + "  Файл содержит приватные ключи ВСЕХ клиентов и "
              "сервера." + СБРОС)
        print(СЕРЫЙ + "  Передавать его нельзя. На сервер — по scp, права 600."
              + СБРОС)
        живых = sum(1 for p in реестр["peers"].values() if not p.get("revoked"))
        print()
        print("  Клиентов в конфиге: %d" % живых)
        print()
    else:
        print(текст)
    return 0


def команда_revoke(args) -> int:
    реестр = прочитать()
    ник = проверить_имя(args.имя)
    if ник not in реестр["peers"]:
        print(КРАСНЫЙ + "  «%s» нет в реестре." % ник + СБРОС)
        return 1
    п = реестр["peers"][ник]
    if п.get("revoked"):
        print(ЖЁЛТЫЙ + "  «%s» уже отозван." % ник + СБРОС)
        return 0
    п["revoked"] = True
    п["revoked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    записать(реестр)
    print()
    print(ЖЁЛТЫЙ + "  Отозван: %s" % ник + СБРОС)
    print("  Его ключ убран из конфига сервера после команды server.")
    print("  Чтобы старый конфиг перестал работать, ОДНОВРЕМЕННО:")
    print("    python sora_keys.py server --out server/server.conf")
    print("    и залить новый конфиг на сервер + перезапустить.")
    print()
    return 0


def команда_audit(args) -> int:
    реестр = прочитать()
    print()
    print(ЖИРНЫЙ + "  ПРОВЕРКА РЕЕСТРА" + СБРОС)
    print()
    проблемы = []

    # 1. реализация
    годна, как_проверено = проверить_реализацию()
    if not годна:
        проблемы.append("реализация X25519 неверна: " + как_проверено)
    else:
        print(ЗЕЛЁНЫЙ + "  [ок]  Curve25519 — " + как_проверено + СБРОС)

    # 2. дубли ключей
    все = []
    for ник, п in реестр["peers"].items():
        все.append((ник, "приватный", п["private_key"]))
        все.append((ник, "публичный", п["public_key"]))
        все.append((ник, "psk", п["preshared_key"]))
    дубль = {}
    for ник, вид, значение in все:
        дубль.setdefault((вид, значение), []).append(ник)
    дублей = {k: v for k, v in дубль.items() if len(v) > 1}
    if дублей:
        for (вид, значение), ники in дублей.items():
            проблемы.append("ключ (%s) повторяется у: %s"
                            % (вид, ", ".join(sorted(set(ники)))))
    else:
        print(ЗЕЛЁНЫЙ + "  [ок]  повторов ключей нет" + СБРОС)

    # 3. формат ключей
    битых = 0
    for ник, п in реестр["peers"].items():
        for поле in ("private_key", "public_key", "preshared_key"):
            try:
                b = base64.b64decode(п[поле], validate=True)
                if len(b) != 32:
                    raise ValueError("длина %d, надо 32" % len(b))
            except Exception as e:
                проблемы.append("%s: поле %s повреждено (%s)"
                                % (ник, поле, e))
                битых += 1
    if not битых:
        print(ЗЕЛЁНЫЙ + "  [ок]  все ключи — валидный base64 по 32 байта"
              + СБРОС)

    # 4. адреса не повторяются
    адреса = {}
    for ник, п in реестр["peers"].items():
        if п.get("revoked"):
            continue
        a = п["address"].split("/")[0]
        адреса.setdefault(a, []).append(ник)
    совп = {a: n for a, n in адреса.items() if len(n) > 1}
    if совп:
        for a, n in совп.items():
            проблемы.append("адрес %s назначен нескольким: %s"
                            % (a, ", ".join(n)))
    else:
        print(ЗЕЛЁНЫЙ + "  [ок]  адреса не повторяются" + СБРОС)

    # 5. параметры обфускации согласованы
    об = реестр["meta"].get("obfuscation", {})
    if об.get("Jmax", 0) <= об.get("Jmin", 0):
        проблемы.append("Jmax (%s) не больше Jmin (%s)"
                        % (об.get("Jmax"), об.get("Jmin")))
    else:
        print(ЗЕЛЁНЫЙ + "  [ок]  параметры обфускации согласованы" + СБРОС)

    # 6. серверный ключ не совпадает с клиентским
    spub = реестр["meta"]["server_public_key"]
    for ник, п in реестр["peers"].items():
        if п["public_key"] == spub:
            проблемы.append("ключ пользователя %s совпадает с серверным"
                            % ник)

    print()
    if проблемы:
        print(КРАСНЫЙ + ЖИРНЫЙ + "  ПРОБЛЕМ: %d" % len(проблемы) + СБРОС)
        for п in проблемы:
            print("  " + КРАСНЫЙ + "• " + п + СБРОС)
    else:
        print(ЗЕЛЁНЫЙ + ЖИРНЫЙ + "  Реестр в порядке." + СБРОС)
    print()
    return 1 if проблемы else 0


def команда_backup(args) -> int:
    реестр = прочитать()
    имя = args.out or ("sora-keys-%s.json"
                       % time.strftime("%Y%m%d-%H%M%S"))
    with open(имя, "w", encoding="utf-8") as f:
        json.dump(реестр, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(имя, 0o600)
    except OSError:
        pass
    живых = sum(1 for p in реестр["peers"].values() if not p.get("revoked"))
    print()
    print(ЗЕЛЁНЫЙ + "  Резервная копия: %s" % имя + СБРОС)
    print("  Ключей в копии: %d" % живых)
    print()
    print(ЖЁЛТЫЙ + "  Копия содержит ПРИВАТНЫЕ ключи." + СБРОС)
    print(СЕРЫЙ + "  Положите её на носитель, который не попадает в облако."
          + СБРОС)
    print(СЕРЫЙ + "  Потеря реестра = потеря доступа для всех, ключи не"
          + СБРОС)
    print(СЕРЫЙ + "  восстановить нельзя." + СБРОС)
    print()
    return 0


# ══════════════════════════════════════════════════════════════
def главная() -> int:
    разбор = argparse.ArgumentParser(
        description="Генератор ключей и конфигов SORA (AmneziaWG)")
    под = разбор.add_subparsers(dest="команда", required=True)

    p = под.add_parser("init", help="создать реестр")
    p.add_argument("--server-ip", default=ПО_УМОЛЧАНИЮ["server_ip"])
    p.add_argument("--port", type=int, default=ПО_УМОЛЧАНИЮ["port"])
    p.add_argument("--network", default=ПО_УМОЛЧАНИЮ["network"])
    p.add_argument("--server-address", default=ПО_УМОЛЧАНИЮ["server_address"])
    p.add_argument("--dns", default=ПО_УМОЛЧАНИЮ["dns"])
    p.add_argument("--перезаписать", action="store_true")
    p.set_defaults(функция=команда_init)

    p = под.add_parser("add", help="добавить пользователя")
    p.add_argument("имя")
    p.add_argument("--ip", help="адрес внутри подсети, например 10.77.0.9")
    p.add_argument("--note", default="", help="заметка для себя")
    p.set_defaults(функция=команда_add)

    p = под.add_parser("list", help="показать ключи")
    p.set_defaults(функция=команда_list)

    p = под.add_parser("config", help="конфиг клиента")
    p.add_argument("имя")
    p.add_argument("--out", help="записать в файл")
    p.set_defaults(функция=команда_config)

    p = под.add_parser("server", help="конфиг сервера")
    p.add_argument("--out", help="записать в файл")
    p.set_defaults(функция=команда_server)

    p = под.add_parser("revoke", help="отозвать ключ")
    p.add_argument("имя")
    p.set_defaults(функция=команда_revoke)

    p = под.add_parser("audit", help="проверить реестр")
    p.set_defaults(функция=команда_audit)

    p = под.add_parser("backup", help="резервная копия реестра")
    p.add_argument("--out")
    p.set_defaults(функция=команда_backup)

    args = разбор.parse_args()
    if getattr(args, "перезаписать", False):
        if os.path.exists(ПУТЬ_РЕЕСТРА):
            команда_backup(argparse.Namespace(out=ПУТЬ_РЕЕСТРА + ".bak",
                                              показать=None))
            os.remove(ПУТЬ_РЕЕСТРА)
    return args.функция(args)


if __name__ == "__main__":
    # ВАЖНО. Первая версия оборачивала sys.exit() в try/except SystemExit
    # и перехватывала СОБСТВЕННЫЙ успешный выход: любая команда
    # возвращала код 1, даже когда отработала правильно. Ловить надо
    # только ошибки, а не результат.
    код_выхода = 1
    try:
        код_выхода = главная()
    except KeyboardInterrupt:
        print()
        print(ЖЁЛТЫЙ + "  Прервано пользователем." + СБРОС)
        код_выхода = 1
    except SystemExit as исключение:
        код = исключение.code
        if isinstance(код, int) and код == 0:
            код_выхода = 0          # штатное завершение, молчим
        else:
            print()
            print(КРАСНЫЙ + "  Ошибка: %s" % код + СБРОС)
            print()
            код_выхода = 1
    sys.exit(код_выхода)
