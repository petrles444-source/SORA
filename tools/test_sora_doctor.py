# -*- coding: utf-8 -*-
r"""
НЕГАТИВНЫЕ ТЕСТЫ SORA DOCTOR
============================

ЗАЧЕМ ЭТОТ ФАЙЛ
----------------
Проверка, которая молчит на сломанных данных, не защищает ни от чего.
Она создаёт ощущение безопасности ровно тогда, когда безопасности нет.
Поэтому каждая проверка doctor'а здесь проверяется обратным порядком:
в реестр кладётся ЗАВЕДОМО СЛОМАННЫЕ данные, и смотрится, замечет ли
их doctor.

Сколько проверок не поймало свою поломку — столько в doctor дыр.

КАК УСТРОЕНО
------------
Тесты работают на ПОЛНОЙ КОПИИ папки SORA во временном каталоге.
Настоящие данные не трогаются физически: скопированный doctor
находит свою копию реестра по пути относительно себя.

Первый вариант тестов правил реестр на месте и при откате удалял
его вместо возврата — данные были потеряны. Отсюда и копия.

ЗАПУСК
------
    python test_sora_doctor.py
    python test_sora_doctor.py --подробно

КОД ВОЗВРАТА
------------
0 — все проверки видят свои поломки
1 — есть проверки, которые не срабатывают
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

КОРЕНЬ_ИСХ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def подготовить() -> str:
    """Копирует SORA во временный каталог и готовит ФИКСТУРНЫЕ данные.

    Почему фикстуры создаются ВСЕГДА, а не «если реестра нет».

    Первая версия копировала пакет как есть, а фикстуры создавала
    только когда registry.json отсутствует. На чистом комплекте из
    репозитория реестра нет — тесты работали. Но у разработчика, у
    которого реестр ЕСТЬ (то есть у того, кто пакетом и пользуется),
    в копию попадал его настоящий реестр, фикстуры не создавались,
    и тесты падали с KeyError: 'ivan' на первой же мутации.

    То есть тесты работали у того, кому они не нужны, и падали у того,
    кому нужны. Хуже: настоящий реестр с приватными ключами копировался
    во временный каталог при каждом прогоне.

    Теперь настоящий реестр на копии всегда удаляется, а фикстуры
    создаются всегда. Оригинал не затрагивается — работа идёт с копией.
    """
    каталог = tempfile.mkdtemp(prefix="sora_test_")
    копия = os.path.join(каталог, "SORA")
    shutil.copytree(
        КОРЕНЬ_ИСХ, копия,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))

    # Настоящий реестр и настоящие клиентские конфиги на копию
    # попадать не должны: это приватные ключи, и тесту они не нужны.
    реестр = os.path.join(копия, "client", "registry.json")
    if os.path.exists(реестр):
        os.remove(реестр)
    каталог_клиента = os.path.join(копия, "client")
    for имя in os.listdir(каталог_клиента):
        if имя.endswith(".conf"):
            os.remove(os.path.join(каталог_клиента, имя))

    # Конфиг сервера тоже свой: он генерируется из фикстурного реестра.
    сервер_конфиг = os.path.join(копия, "server", "server.conf")
    if os.path.exists(сервер_конфиг):
        os.remove(сервер_конфиг)

    gen = os.path.join(копия, "tools", "sora_keys.py")
    for args in (["init"], ["add", "ivan", "--note", "ноутбук"],
                 ["add", "masha", "--note", "телефон"],
                 ["add", "petr", "--note", "старый"],
                 ["revoke", "petr"],
                 ["server", "--out", сервер_конфиг]):
        subprocess.run([sys.executable, gen] + args, capture_output=True)
    for ник in ("ivan", "masha"):
        subprocess.run([sys.executable, gen, "config", ник, "--out",
                        os.path.join(каталог_клиента,
                                     "config-%s.conf" % ник)],
                       capture_output=True)

    # Если фикстуры не получились — это поломка, о ней надо сказать
    # явно, а не падать позже с KeyError без объяснения.
    if not os.path.exists(реестр):
        raise RuntimeError(
            "не удалось создать фикстурный реестр: %s" % gen)
    return копия


class Сценарий:
    """Один негативный тест: мутация реестра + ожидаемый код проверки."""

    def __init__(self, имя, код, мутация, подробно=""):
        self.имя = имя
        self.код = код
        self.мутация = мутация
        self.подробно = подробно


def чтение(реестр):
    with open(реестр, encoding="utf-8") as f:
        return json.load(f)


def запись(реестр, данные):
    with open(реестр, "w", encoding="utf-8") as f:
        json.dump(данные, f, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════
#  Мутации — каждая ломает ровно одну вещь
# ══════════════════════════════════════════════════════════════
def m_A2(r):
    """Ключ обрезан — не 32 байта."""
    r["peers"]["ivan"]["private_key"] = base64.b64encode(
        secrets.token_bytes(16)).decode()


def m_A3(r):
    """Приватный ключ не зажат: снимаем ограничение нижних бит."""
    p = r["peers"]["ivan"]
    b = bytearray(base64.b64decode(p["private_key"]))
    b[0] ^= 0x07
    p["private_key"] = base64.b64encode(bytes(b)).decode()


def m_A4(r):
    """Публичный ключ не выводится из своего приватного."""
    r["peers"]["masha"]["public_key"] = \
        base64.b64encode(secrets.token_bytes(32)).decode()


def m_A5(r):
    """Два человека с одним ключом."""
    a, b = r["peers"]["ivan"], r["peers"]["masha"]
    b["private_key"] = a["private_key"]
    b["public_key"] = a["public_key"]


def m_B2(r):
    """Один адрес выдан двоим."""
    r["peers"]["masha"]["address"] = r["peers"]["ivan"]["address"]


def m_B2_вне_сети(r):
    """Адрес вне подсети туннеля."""
    r["peers"]["masha"]["address"] = "192.168.55.7/32"


def m_B3(r):
    """Нет PresharedKey."""
    r["peers"]["ivan"]["preshared_key"] = ""


def m_B4(r):
    """Jmax меньше Jmin — параметры обфускации бессмысленны."""
    r["meta"]["obfuscation"]["Jmax"] = 10
    r["meta"]["obfuscation"]["Jmin"] = 500


def m_B6(r):
    """Ключ пользователя совпал с серверным."""
    r["peers"]["ivan"]["public_key"] = r["meta"]["server_public_key"]


# A2..B6 правятся в реестре, и конфиг затем пересобирается из него.
# C2 и C3 СПЕЦИАЛЬНЫ: они сверяют файл конфига с реестром. Если сломать
# реестр и потом пересобрать из него конфиг, они совпадут по построению
# и проверка ничего не заметит — а это ровно тот случай, когда тест
# притворяется, что работает. Эти двое правятся руками в server.conf,
# см. сценарий_C2 и сценарий_C3 ниже.


СЦЕНАРИИ = [
    Сценарий("A2  ключ обрезан, не 32 байта",            "A2", m_A2),
    Сценарий("A3  скаляр не зажат по RFC 7748",           "A3", m_A3),
    Сценарий("A4  публичный ключ чужой",                  "A4", m_A4),
    Сценарий("A5  ключ повторяется у двоих",              "A5", m_A5),
    Сценарий("B2  адрес выдан двоим",                     "B2", m_B2),
    Сценарий("B2  адрес вне подсети туннеля",             "B2", m_B2_вне_сети),
    Сценарий("B3  нет PresharedKey",                      "B3", m_B3),
    Сценарий("B4  Jmax не больше Jmin",                   "B4", m_B4),
    Сценарий("B6  ключ пользователя равен серверному",     "B6", m_B6),
]


# ══════════════════════════════════════════════════════════════
#  Прогон doctor на мутированной копии
# ══════════════════════════════════════════════════════════════
def собрать_конфиги(копия):
    """Генерирует заново серверный и клиентские конфиги из реестра."""
    gen = os.path.join(копия, "tools", "sora_keys.py")
    subprocess.run([sys.executable, gen, "server", "--out",
                    os.path.join(копия, "server", "server.conf")],
                   capture_output=True)
    for cfg in os.listdir(os.path.join(копия, "client")):
        if cfg.startswith("config-"):
            os.remove(os.path.join(копия, "client", cfg))
    for ник in ("ivan", "masha"):
        subprocess.run([sys.executable, gen, "config", ник, "--out",
                        os.path.join(копия, "client",
                                     "config-%s.conf" % ник)],
                       capture_output=True)


def прогон(копия):
    p = subprocess.run(
        [sys.executable, os.path.join(копия, "tools", "sora_doctor.py"),
         "--подробно"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.stdout


def замечен(вывод, код):
    """Код проверки упомянут как ПРОБЛЕМА, а не как ок/не проверено."""
    for стр in вывод.splitlines():
        if код in стр and "[!!]" in стр:
            return True
    return False


# ══════════════════════════════════════════════════════════════
#  Сценарии, работающие не с реестром, а с файлами
# ══════════════════════════════════════════════════════════════
def сценарий_F4(копия):
    """Приватный ключ утёк в текстовый отчёт."""
    реестр = os.path.join(копия, "client", "registry.json")
    r = чтение(реестр)
    путь = os.path.join(копия, "docs", "_проверка_утечки.md")
    os.makedirs(os.path.dirname(путь), exist_ok=True)
    with open(путь, "w", encoding="utf-8") as f:
        f.write("служебная записка\n\nключ: %s\n"
                % r["peers"]["ivan"]["private_key"])
    вывод = прогон(копия)
    os.remove(путь)
    return "F4", замечен(вывод, "F4")


def сценарий_F5(копия):
    """В конфиге Иванова приватный ключ Маши."""
    реестр = os.path.join(копия, "client", "registry.json")
    r = чтение(реестр)
    путь = os.path.join(копия, "client", "config-ivan.conf")
    t = open(путь, encoding="utf-8").read()
    t = t.replace(r["peers"]["ivan"]["private_key"],
                  r["peers"]["masha"]["private_key"])
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    вывод = прогон(копия)
    return "F5", замечен(вывод, "F5")


def сценарий_C6(копия):
    """Из клиентского конфига убрана защита от утечки IPv6."""
    путь = os.path.join(копия, "client", "config-ivan.conf")
    t = open(путь, encoding="utf-8").read()
    t = t.replace("AllowedIPs = 0.0.0.0/0, ::/0",
                  "AllowedIPs = 0.0.0.0/0")
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    вывод = прогон(копия)
    return "C6", замечен(вывод, "C6.ivan")


def сценарий_C7(копия):
    """В клиентском конфиге DNS наружу, а не в туннель."""
    путь = os.path.join(копия, "client", "config-ivan.conf")
    t = open(путь, encoding="utf-8").read()
    t = t.replace("DNS = 10.77.0.1", "DNS = 8.8.8.8")
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    вывод = прогон(копия)
    строки = [s for s in вывод.splitlines() if "C7.ivan" in s]
    помечено = any("[!!]" in s for s in строки)
    помечено = помечено or any("[..]" in s for s in строки)
    return "C7", помечено


def сценарий_C8(копия):
    """В клиентском конфиге неверный адрес сервера."""
    путь = os.path.join(копия, "client", "config-ivan.conf")
    t = open(путь, encoding="utf-8").read()
    ток = [s for s in t.splitlines() if s.startswith("Endpoint")]
    t = t.replace(ток[0], "Endpoint = 10.0.0.1:9999")
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    вывод = прогон(копия)
    return "C8", замечен(вывод, "C8.ivan")


def сценарий_C2(копия):
    """Приватный ключ сервера в файле разошёлся с реестром.

    Правка идёт по файлу server.conf, а не по реестру: если сломать
    реестр и пересобрать из него конфиг, расхождения не будет по
    построению, и проверка промолчит вхолостую.
    """
    путь = os.path.join(копия, "server", "server.conf")
    t = open(путь, encoding="utf-8").read()
    строка = next(s for s in t.splitlines()
                  if s.startswith("PrivateKey = "))
    подмена = base64.b64encode(secrets.token_bytes(32)).decode()
    t = t.replace(строка, "PrivateKey = " + подмена)
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    return "C2", замечен(прогон(копия), "C2")


def сценарий_C3(копия):
    """Параметр обфускации в файле разошёлся с реестром."""
    путь = os.path.join(копия, "server", "server.conf")
    t = open(путь, encoding="utf-8").read()
    строка = next(s for s in t.splitlines() if s.startswith("Jc = "))
    t = t.replace(строка, "Jc = 42")
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    return "C3", замечен(прогон(копия), "C3")


def сценарий_B5(копия):
    """Отозванный ключ попал в конфиг сервера."""
    реестр = os.path.join(копия, "client", "registry.json")
    r = чтение(реестр)
    r["peers"]["petr"]["revoked"] = True
    запись(реестр, r)
    собрать_конфиги(копия)      # server.conf соберётся БЕЗ petr
    # а теперь впишем его обратно руками — как если бы конфиг забыли
    # пересобрать после отзыва
    путь = os.path.join(копия, "server", "server.conf")
    t = open(путь, encoding="utf-8").read()
    t += ("\n# --- petr\n[Peer]\nPublicKey = %s\n"
          "PresharedKey = %s\nAllowedIPs = %s\n"
          % (r["peers"]["petr"]["public_key"],
             r["peers"]["petr"]["preshared_key"],
             r["peers"]["petr"]["address"].split("/")[0] + "/32"))
    with open(путь, "w", encoding="utf-8") as f:
        f.write(t)
    вывод = прогон(копия)
    return "B5", замечен(вывод, "B5")


def сценарий_F6(копия):
    """`--html` в каталог, которого нет, роняет трассировку.

    НАЙДЕНО НА АУДИТЕ. `в_html` открывала файл напрямую, не создавая
    каталог. На отсутствующем каталоге вылезала трассировка Python
    на пол-экрана:

        FileNotFoundError: [Errno 2] No such file or directory:
        '...\\нет\\такого\\отчёт.html'

    Особенно скверно здесь то, что отчёт заказывают именно тогда,
    когда что-то сломалось. Единственный инструмент диагностики не
    должен падать в момент обращения к нему.

    Ожидается F6: код не должно падать, отчёт должен записаться.
    """
    куда = os.path.join(копия, "нет", "такого", "отчёт.html")
    p = subprocess.run(
        [sys.executable, os.path.join(копия, "tools", "sora_doctor.py"),
         "--html", куда],
        capture_output=True, text=True, encoding="utf-8", errors="replace")

    if "Traceback" in (p.stdout + p.stderr):
        return "F6", False

    if not os.path.isfile(куда):
        return "F6", False

    try:
        with open(куда, encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return "F6", False

    начало = html.lstrip().lower()
    if not (начало.startswith("<!doctype") or начало.startswith("<html")):
        return "F6", False
    return "F6", True


ФАЙЛОВЫЕ = [
    ("B5  отозванный ключ в конфиге сервера", сценарий_B5),
    ("C2  ключ сервера в файле разошёлся",     сценарий_C2),
    ("C3  обфускация в файле разошлась",       сценарий_C3),
    ("C6  из конфига убрана защита IPv6",      сценарий_C6),
    ("C7  в конфиге DNS наружу",              сценарий_C7),
    ("C8  в конфиге неверный адрес сервера",   сценарий_C8),
    ("F4  приватный ключ утёк в отчёт",        сценарий_F4),
    ("F5  в конфиге чужой приватный ключ",     сценарий_F5),
    ("F6  --html роняет трассировку",         сценарий_F6),
]


# ══════════════════════════════════════════════════════════════
def main() -> int:
    подробно = "--подробно" in sys.argv

    print()
    print("═" * 74)
    print("  НЕГАТИВНЫЕ ТЕСТЫ DOCTOR")
    print("  данные копируются во временный каталог, оригинал не страдает")
    print("═" * 74)

    итоги = []

    # ── контрольная проверка: на ЧИСТЫХ данныхdoctor не должен врать ──
    контрольная = прогон(подготовить())
    ложные = [s for s in контрольная.splitlines()
              if "[!!]" in s and "F1" not in s and "F2" not in s]
    print()
    print("── КОНТРОЛЬ НА ЧИСТЫХ ДАННЫХ ──")
    print("  проверок: %s"
          % next((s.strip() for s in контрольная.splitlines()
                  if "проверок:" in s), "?"))
    if ложные:
        print("  doctor ругается без причины:")
        for s in ложные:
            print("    %s" % s.strip())
        итоги.append((False, "ЛОЖНЫЕ СРАБАТЫВАНИЯ на чистых данных",
                      "%d строк" % len(ложные)))
    else:
        print("  ложных срабатываний нет")
        итоги.append((True, "чистые данные проходят без ложных тревог", ""))

    # ── сценарии на реестре ──
    print()
    print("── ПОЛОМКИ В РЕЕСТРЕ ──")
    for сц in СЦЕНАРИИ:
        копия = подготовить()
        реестр = os.path.join(копия, "client", "registry.json")
        r = чтение(реестр)
        сц.мутация(r)
        запись(реестр, r)
        собрать_конфиги(копия)
        вывод = прогон(копия)
        поймал = замечен(вывод, сц.код)
        итоги.append((поймал, сц.имя,
                      "ожидалась %s, не поймана" % сц.код))
        print("  %s %-42s %s" % ("[ок]  " if поймал else "[!!]  ",
                                 сц.имя,
                                 "" if поймал else "— НЕ ПОЙМАНО"))
        shutil.rmtree(os.path.dirname(копия), ignore_errors=True)

    # ── сценарии на файлах ──
    print()
    print("── ПОЛОМКИ В ФАЙЛАХ ──")
    for имя, функция in ФАЙЛОВЫЕ:
        копия = подготовить()
        код, поймал = функция(копия)
        итоги.append((поймал, имя,
                      "ожидалась %s, не поймана" % код))
        print("  %s %-42s %s" % ("[ок]  " if поймал else "[!!]  ",
                                 имя,
                                 "" if поймал else "— НЕ ПОЙМАНО"))
        shutil.rmtree(os.path.dirname(копия), ignore_errors=True)

    # ── итог ──
    ок = sum(1 for г, _, _ in итоги if г)
    print()
    print("─" * 74)
    print("  результат: %d из %d" % (ок, len(итоги)))
    if подробно:
        for г, имя, деталь in итоги:
            if not г:
                print("    %s — %s" % (имя, деталь))
    if ок == len(итоги):
        print("  каждая проверка видит свою поломку и не ругается зря")
    else:
        print("  ЕСТЬ ДЫРЫ: проверки, которые не срабатывают")
    print("─" * 74)
    print()

    return 0 if ок == len(итоги) else 1


if __name__ == "__main__":
    sys.exit(main())
