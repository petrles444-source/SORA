#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
АНАЛИЗАТОР КЛЮЧЕЙ WARP — работает полностью офлайн.

ЗАЧЕМ ИМЕННО ТАК

Задача была «проверить, работают ли ключи». Проверить это можно
только одним способом — подключиться. Подключение к Cloudflare WARP
с одной машины десятками разных ключей выглядит для них как злоупотребление,
и часть ключей после этого перестаёт работать навсегда.

Поэтому этот инструмент НЕ УМЕЕТ НИЧЕГО ПОДКЛЮЧАТЬ. Ни одного
импорта сети в файле нет — это проверяемо. Он читает файлы и говорит,
что в них написано.

ЧТО ОН ДЕЛАЕТ

  1. Разбирает конфиги, собирает по ним таблицу.
  2. Ищет дубликаты: уникальных ключей обычно меньше, чем файлов.
  3. Проверяет форму ключей — зажаты ли биты по RFC 7748.
  4. Группирует по дате файла: ключи одного дня сгенерированы рядом.
  5. Считает эндпоинты и зоны.
  6. Показывает, какие ключи физически идентичны.

ЧЕГО ОН НЕ ДЕЛАЕТ И НЕ СМОЖЕТ

  Не проверяет живость ключа. Единственный источник правды здесь —
  рукопожатие с сервером, а оно требует настоящего клиента.
  Всё, что этот инструмент скажет про «работает» — это догадка.

ЗАПУСК

  python sora_keyscan.py                          Downloads
  python sora_keyscan.py ПАПКА --подробно
  python sora_keyscan.py ПАПКА --html отчёт.html

ПРИВАТНЫЕ КЛЮЧИ НЕ ПЕЧАТАЮТСЯ

В выводе — только первые 8 символов отпечатка ключа, и то по
желанию. Полное значение не выводится никуда: оно попало бы в
логи и скриншоты.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── разбор конфига ─────────────────────────────────────────────────

ПОЛЯ_IFACE = {
    "PrivateKey", "Address", "DNS", "MTU",
    "S1", "S2", "S3", "S4", "Jc", "Jmin", "Jmax",
    "H1", "H2", "H3", "H4",
    # I1 и I2 — обе законные. Проверено на 122 реальных файлах:
    # I1 есть во всех, I2 — только в версии 3. На это смотреть
    # не как на аномалию нельзя: в их генераторе есть переключатель
    # «Собственный I1», а второй блок приходит вместе с AWG 3.1.
    "I1", "I2", "I3", "I4",
    "PersistentKeepalive",
}
ПОЛЯ_PEER = {
    "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
    "Reserved",
}

ЗОНА = re.compile(
    r"^([a-z]{2})WARPv(\d)", re.IGNORECASE)

ИМЕНА_ЗОН = {
    "ee": "Эстония", "fi": "Финляндия", "nl": "Нидерланды",
    "pl": "Польша", "lv": "Латвия", "de": "Германия",
    "ru": "Россия", "us": "США", "fr": "Франция",
}


class Конфиг:
    """Один разобранный конфиг."""

    def __init__(self, путь: Path):
        self.путь = путь
        self.имя = путь.name
        self.размер = путь.stat().st_size
        self.изменён = datetime.fromtimestamp(путь.stat().st_mtime)
        self.поля: dict[str, str] = {}
        self.ошибки: list[str] = []
        self._разобрать()

    def _разобрать(self) -> None:
        try:
            текст = self.путь.read_text(encoding="utf-8", errors="ignore")
        except OSError as ошибка:
            self.ошибки.append(f"не читается: {ошибка}")
            return

        секция = ""
        for номер, строка in enumerate(текст.splitlines(), 1):
            строка = строка.strip()
            if not строка or строка.startswith("#"):
                continue
            if строка.startswith("[") and строка.endswith("]"):
                секция = строка[1:-1].strip()
                continue
            if "=" not in строка:
                self.ошибки.append(f"строка {номер}: нет знака =")
                continue
            имя, значение = строка.split("=", 1)
            ключ = имя.strip()
            self.поля[ключ] = значение.strip()
            if секция == "Interface" and ключ not in ПОЛЯ_IFACE:
                self.ошибки.append(f"поле в Interface: {ключ}")

    # ── свойства ──

    @property
    def приватный(self) -> str:
        return self.поля.get("PrivateKey", "")

    @property
    def эндпоинт(self) -> str:
        return self.поля.get("Endpoint", "")

    @property
    def адрес(self) -> str:
        return self.поля.get("Address", "")

    @property
    def ipv4(self) -> str:
        первая = self.адрес.split(",")[0].strip()
        return первая.split("/")[0]

    @property
    def зона(self) -> str:
        совпадение = ЗОНА.match(self.имя)
        if совпадение:
            код = совпадение.group(1).lower()
            имя = ИМЕНА_ЗОН.get(код, код.upper())
            версия = совпадение.group(2)
            LTE = " LTE" if "LTE" in self.имя else ""
            return f"{имя} v{версия}{LTE}"
        return "не определена"

    @property
    def отпечаток(self) -> str:
        """Первые 8 символов хеша от ключа. Сам ключ не показываем."""
        if not self.приватный:
            return "нет ключа"
        хеш = hashlib.sha256(self.приватный.encode()).hexdigest()
        return хеш[:8]

    @property
    def байты_ключа(self) -> bytes | None:
        try:
            return base64.b64decode(self.приватный)
        except Exception:
            return None

    @property
    def зажат(self) -> bool | None:
        """Проверка зажима битов по RFC 7748."""
        б = self.байты_ключа
        if б is None or len(б) != 32:
            return None
        return (б[0] & 248) == 248 and (б[31] & 127) == 64

    @property
    def длина_ключа(self) -> int:
        б = self.байты_ключа
        return len(б) if б is not None else 0

    def проверить(self) -> list[str]:
        """Проблемы конкретно в этом конфиге."""
        проблемы = list(self.ошибки)

        if not self.приватный:
            проблемы.append("нет PrivateKey")
        else:
            б = self.байты_ключа
            if б is None:
                проблемы.append("PrivateKey не декодируется в base64")
            elif len(б) != 32:
                проблемы.append(f"ключ {len(б)} Б, а должно быть 32")

        if not self.эндпоинт:
            проблемы.append("нет Endpoint")
        else:
            хост = self.эндпоинт.rsplit(":", 1)[0]
            порт = self.эндпоинт.rsplit(":", 1)[-1] if ":" in self.эндпоинт else ""
            if хост in ("", "engage.cloudflareclient.com"):
                проблемы.append("Endpoint — стандартный WARP, не их сеть")
            if порт and not порт.isdigit():
                проблемы.append(f"порт не число: {порт}")

        if not self.адрес:
            проблемы.append("нет Address")

        if not self.поля.get("AllowedIPs"):
            проблемы.append("нет AllowedIPs в Peer")

        return проблемы


def собрать(папка: Path) -> list[Конфиг]:
    файлы = []
    for образец in ("*.conf", "*.CONF"):
        файлы.extend(папка.glob(образец))
    return [Конфиг(f) for f in sorted(set(файлы))]


def отчёт(конфиги: list[Конфиг], подробно: bool) -> dict:
    всего = len(конфиги)

    # дубликаты по приватному ключу
    по_ключу = collections.defaultdict(list)
    for к in конфиги:
        по_ключу[к.приватный or f"<нет:{к.имя}>"].append(к)

    уникальных = len(по_ключу)
    дубли = {k: v for k, v in по_ключу.items() if len(v) > 1 and k}

    по_зонам = collections.Counter(к.зона for к in конфиги)
    по_эндпоинтам = collections.Counter(
        к.эндпоинт.rsplit(":", 1)[0] for к in конфиги if к.эндпоинт)

    по_дням = collections.Counter(
        к.изменён.strftime("%d.%m") for к in конфиги)

    зажатых = sum(1 for к in конфиги if к.зажат is True)
    незажатых = sum(1 for к in конфиги if к.зажат is False)
    битых = [к for к in конфиги if к.проверить()]

    return {
        "всего": всего,
        "уникальных": уникальных,
        "дубликатов": {v[0].отпечаток: [x.имя for x in v]
                       for v in дубли.values()},
        "по_зонам": dict(по_зонам),
        "по_эндпоинтам": dict(по_эндпоинтам),
        "по_дням": dict(sorted(по_дням.items(),
                              key=lambda п: п[0][3:] + п[0][:2])),
        "зажатых": зажатых,
        "незажатых": незажатых,
        "с_проблемами": [{"имя": к.имя, "проблемы": к.проверить()}
                         for к in битых],
        "конфиги": конфиги,
        "подробно": подробно,
    }


def напечатать(д: dict) -> None:
    print()
    print("═" * 70)
    print("  АНАЛИЗ КЛЮЧЕЙ WARP — ОФЛАЙН, БЕЗ ПОДКЛЮЧЕНИЙ")
    print("═" * 70)
    print()
    print("  ⚠ Этот инструмент НЕ проверяет живость ключа.")
    print("    Единственный источник правды — рукопожатие с сервером.")
    print("    Здесь только разбор того, что лежит в файлах.")
    print()

    print("  ── сколько ──")
    print(f"    файлов конфигов:      {д['всего']}")
    print(f"    уникальных ключей:    {д['уникальных']}")
    if д['всего'] != д['уникальных']:
        разница = д['всего'] - д['уникальных']
        print(f"    повторов:             {разница}")
    print()

    if д["дубликатов"]:
        print("  ── дубликаты (один ключ в нескольких файлах) ──")
        for отп, имена in sorted(д["дубликатов"].items(),
                                 key=lambda п: -len(п[1])):
            print(f"    ключ {отп}… встречается {len(имена)} раз:")
            for имя in имена[:6]:
                print(f"        {имя}")
            if len(имена) > 6:
                print(f"        …и ещё {len(имена) - 6}")
        print()

    print("  ── форма ключей ──")
    print(f"    зажаты по RFC 7748:   {д['зажатых']}")
    if д["незажатых"]:
        print(f"    НЕ зажаты:            {д['незажатых']}")
    print()

    print("  ── зоны ──")
    for зона, кол in sorted(д["по_зонам"].items(), key=lambda п: -п[1]):
        палка = "█" * min(кол, 40)
        print(f"    {зона:<22} {кол:>4}  {палка}")
    print()

    print("  ── серверы (хост) ──")
    for хост, кол in sorted(д["по_эндпоинтам"].items(),
                            key=lambda п: -п[1])[:15]:
        print(f"    {хост:<34} {кол:>4}")
    print()

    print("  ── по датам ──")
    for день, кол in д["по_дням"].items():
        палка = "█" * min(кол, 40)
        print(f"    {день:<10} {кол:>4}  {палка}")
    print()

    if д["с_проблемами"]:
        print("  ── с проблемами ──")
        for запись in д["с_проблемами"][:20]:
            print(f"    {запись['имя']}")
            for п in запись["проблемы"]:
                print(f"        {п}")
        if len(д["с_проблемами"]) > 20:
            print(f"    …и ещё {len(д['с_проблемами']) - 20}")
        print()

    if д["подробно"]:
        print("  ── по каждому файлу ──")
        print(f"    {'файл':<28} {'зона':<20} {'ключ':<10} {'адрес':<14}")
        for к in д["конфиги"]:
            print(f"    {к.имя[:27]:<28} {к.зона:<20} "
                  f"{к.отпечаток + '…':<10} {к.ipv4:<14}")
        print()


def в_html(д: dict) -> str:
    """Таблица для открытия в браузере."""
    строки = []
    for к in д["конфиги"]:
        проблемы = к.проверить()
        строки.append(
            "<tr class='{klass}'>"
            "<td>{имя}</td><td>{зона}</td><td>{отп}…</td>"
            "<td>{адрес}</td><td>{энд}</td><td>{размер}</td>"
            "<td>{зажат}</td><td>{проблемы}</td></tr>".format(
                klass="bad" if проблемы else "ok",
                имя=html.escape(к.имя),
                зона=html.escape(к.зона),
                отп=к.отпечаток,
                адрес=html.escape(к.ipv4),
                энд=html.escape(к.эндпоинт),
                размер=f"{к.размер:,}".replace(",", " "),
                зажат="да" if к.зажат else ("нет" if к.зажат is False else "?"),
                проблемы="; ".join(html.escape(p) for p in проблемы) or "—",
            ))

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Ключи WARP — анализ</title>
<style>
 body {{ font-family: system-ui, sans-serif; background:#111418; color:#dfe3e8;
        margin:0; padding:24px; }}
 h1 {{ font-size:20px; margin:0 0 4px; }}
 .пред {{ color:#8b949e; font-size:14px; margin-bottom:20px; }}
 .блок {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
         padding:16px; margin-bottom:16px; }}
 .цифра {{ font-size:28px; font-weight:600; color:#58a6ff; }}
 table {{ border-collapse:collapse; width:100%; font-size:13px;
          background:#161b22; }}
 th, td {{ border:1px solid #30363d; padding:6px 9px; text-align:left; }}
 th {{ background:#21262d; position:sticky; top:0; }}
 tr.bad td {{ background:#2d1618; }}
 .ок {{ color:#3fb950; }} .нет {{ color:#f85149; }}
</style></head><body>
<h1>Ключи WARP — разбор</h1>
<div class="пред">Офлайн-разбор. Живость ключа здесь не проверяется —
настоящую проверку даёт только рукопожатие с сервером.</div>

<div class="блок">
 <div>файлов: <span class="цифра">{д['всего']}</span></div>
 <div>уникальных ключей: <span class="цифра">{д['уникальных']}</span></div>
 <div>с проблемами: <span class="цифра">{len(д['с_проблемами'])}</span></div>
</div>

<table>
<tr><th>файл</th><th>зона</th><th>ключ</th><th>адрес</th>
<th>эндпоинт</th><th>размер</th><th>зажат</th><th>проблемы</th></tr>
{''.join(строки)}
</table>
</body></html>"""


def главный() -> int:
    разбор = argparse.ArgumentParser(
        description="Офлайн-разбор ключей WARP. Подключений не делает.")
    разбор.add_argument("папка", nargs="?", default="Downloads",
                        help="папка с конфигами")
    разбор.add_argument("--подробно", action="store_true",
                        help="таблица по каждому файлу")
    разбор.add_argument("--html", default=None,
                        help="сохранить отчёт в HTML")
    разбор.add_argument("--json", default=None,
                        help="сохранить данные в JSON")
    арг = разбор.parse_args()

    папка = Path(арг.папка)
    if not папка.is_dir():
        # подсказка: Downloads часто указывают полным путём
        для_проверки = Path.home() / "Downloads"
        if для_проверки.is_dir():
            папка = для_проверки
            print(f"  папка '{арг.папка}' не найдена, беру {папка}")
        else:
            print(f"  папка не найдена: {арг.папка}")
            return 1

    конфиги = собрать(папка)
    if not конфиги:
        print(f"  в {папке} нет файлов .conf")
        return 1

    д = отчёт(конфиги, арг.подробно)
    напечатать(д)

    if арг.json:
        данные = {k: v for k, v in д.items() if k != "конфиги"}
        данные["конфиги"] = [
            {"имя": к.имя, "зона": к.зона, "отпечаток": к.отпечаток,
             "ipv4": к.ipv4, "эндпоинт": к.эндпоинт,
             "зажат": к.зажат, "проблемы": к.проверить(),
             "изменён": к.изменён.isoformat()}
            for к in конфиги]
        Path(арг.json).write_text(
            json.dumps(данные, ensure_ascii=False, indent=2),
            encoding="utf-8", newline="\n")
        print(f"  JSON:  {арг.json}")

    if арг.html:
        Path(арг.html).write_text(в_html(д), encoding="utf-8",
                                  newline="\n")
        print(f"  HTML:  {арг.html}")

    return 0


if __name__ == "__main__":
    sys.exit(главный())
