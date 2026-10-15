#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Папка для секретов SORA. Создаёт правильную структуру и .gitignore.

ЗАЧЕМ ОТДЕЛЬНЫЙ ИНСТРУМЕНТ, А НЕ «ПРОСТО СОЗДАТЬ ПАПКУ»

Правильное хранение ключей выглядит просто, пока не начнёшь:
файл создаётся, .gitignore правится, потом что-то переименовывается —
и правило перестаёт работать. Ключ уезжает в историю git, а git её
не отдаёт никогда.

Поэтому здесь три вещи, которые обычно забывают:

  1. secrets.local.json — запрещён в .gitignore ДВАЖДЫ: по имени
     и по содержанию. Переименуют файл — правило по содержанию всё
     равно его поймает.
  2. example-файл рядом — чтобы было видно, какие поля вообще
     нужны, не показывая значения.
  3. Проверка перед каждым коммитом — ищем настоящие значения ключей
     в индексе git, а не похожие на них строки.

ЗАПУСК

  python sora_secrets.py                     создать если нет
  python sora_secrets.py --проверить         проверить папку
  python sora_secrets.py --путь ПАПКА       другая папка
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

СЕКРЕТЫ = "secrets.local.json"
ПРИМЕР = "secrets.local.example.json"
РЕЗЕРВ = "secrets.local.backup.json"

# Поля реестра SORA. Значения в example — заглушки, не ключи.
# Имя пользователя в примере — обобщённое, не реальное: в
# публичной сборке настоящие имена не нужны и только мешают.
ПОЛЯ_ПРИМЕРА = {
    "server_private_key": "<Curve25519, 32 байта в base64>",
    "server_public_key": "<открытый, можно публиковать>",
    "server_psk": "<PresharedKey, 32 байта в base64>",
    "peer_alice_private_key": "<закрытый ключ alice>",
    "peer_alice_public_key": "<открытый ключ alice>",
    "peer_alice_psk": "<PresharedKey для alice>",
}

ЧТО_ЗАКРЫТО = [
    "server_private_key",
    "server_psk",
    "private_key",
    "preshared_key",
]

GITIGNORE = """# ─────────────────────────────────────────────────────────────────
#  СЕКРЕТЫ. НИКОГДА НЕ КОММИТИТЬ.
#
#  Git хранит историю навсегда. Удалил файл — не помогло: старая
#  версия осталась у всех, кто успел клонировать. Ключ придётся
#  считать скомпрометированным и перевыпускать.
#
#  Закрытый ключ = то, что позволяет выдать себя за кого-то.
#  Открытый ключ = публичная часть, её прятать незачем.
# ─────────────────────────────────────────────────────────────────

# По имени — на случай переименования
secrets.local.json
secrets.local.backup.json
secrets*.json
*.secrets
*.secret

# Исключение: файл-пример коммитить МОЖНО и нужно. В нём вместо
# ключей подсказки вида «<Curve25519, 32 байта в base64>», и он
# объясняет человеку, что вообще сюда класть. Без него в
# репозитории не будет документации о формате.
# Правило ниже действует позже, поэтому побеждает secrets*.json.
!secrets.local.example.json

# По содержанию — ловит файл под любым именем
*.private
*.privkey
*.psk

# Ключи и сертификаты
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
id_ecdsa

# Окружение и бэкапы
.env
.env.*
*.bak
*.backup
*.old
*.zip
*.enc

# Базы и логи, где ключ может всплыть
*.db
*.sqlite
*.sqlite3
*.log
"""


def создать(папка: Path) -> bool:
    """Создать папку, example-файл и .gitignore. Не трогает существующее."""
    папка.mkdir(parents=True, exist_ok=True)
    создано = []

    # example
    пример = папка / ПРИМЕР
    if not пример.exists():
        пример.write_text(
            json.dumps(ПОЛЯ_ПРИМЕРА, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        создано.append(ПРИМЕР)

    # настоящий — только если его нет
    секрет = папка / СЕКРЕТЫ
    if not секрет.exists():
        секрет.write_text(
            json.dumps(ПОЛЯ_ПРИМЕРА, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        создано.append(СЕКРЕТЫ)

    # .gitignore
    игнор = папка / ".gitignore"
    if not игнор.exists():
        игнор.write_text(GITIGNORE, encoding="utf-8", newline="\n")
        создано.append(".gitignore")

    # инструкция
    инструкция = папка / "README.md"
    if not инструкция.exists():
        инструкция.write_text(ТЕКСТ_README, encoding="utf-8", newline="\n")
        создано.append("README.md")

    return создано


ТЕКСТ_README = """# Секреты SORA

Здесь закрытые ключи VPN. Папка не должна попадать в git.

## Что секретно, а что нет

| | |
|---|---|
| `private_key`, `server_private_key` | **секрет**. Кто знает — тот выдаёт себя за этого человека |
| `server_psk`, `preshared_key` | **секрет**. Часть протокола |
| `public_key` | **не секрет**. Он и так в конфиге у каждого клиента |

Открытые ключи можно хранить в открытом виде и распечатывать.
Закрытые — шифровать.

## Как шифровать

```
python SORA/tools/sora_crypt.py secrets.local.json
```

Получится `secrets.local.json.enc`. Исходник не удаляется —
удалите сами, когда убедитесь, что копия есть.

Пароль нигде не хранится. Забыли — ключей больше нет.

## Куда класть зашифрованное

Яндекс.Диск, Google Drive, почта самому себе, флешка.
**В двух местах сразу.** Яндекс и Google — разные компании,
значит их одновременная недоступность невозможна.

## Что делать при утечке

1. Отозвать старый ключ.
2. Выпустить новый.
3. Раздать новый всем, кому был выдан старый.
4. Не полагаться на «удалил из git».

## Проверка перед коммитом

```
python SORA/tools/publish_check.py client/registry.json .
```

Ищет настоящие значения ключей, а не похожие строки.
"""


def проверить(папка: Path) -> int:
    """Проверить, что секреты не попадают в git."""
    print()
    print("═" * 62)
    print("  ПРОВЕРКА СЕКРЕТОВ")
    print("═" * 62)
    print(f"  папка: {папка}")
    print()

    секрет = папка / СЕКРЕТЫ
    if not секрет.exists():
        print("  [?] файла секретов нет — проверять нечего")
        return 0

    try:
        данные = json.loads(секрет.read_text(encoding="utf-8"))
    except json.JSONDecodeError as ошибка:
        print(f"  [!!] файл не читается как JSON: {ошибка}")
        return 1

    живые = {k: v for k, v in данные.items()
             if isinstance(v, str) and v and not v.startswith("<")}

    print(f"  полей с настоящими значениями: {len(живые)}")
    for имя in sorted(живые):
        закрытый = any(ч in имя for ч in ЧТО_ЗАКРЫТО)
        метка = "СЕКРЕТ" if закрытый else "открытый"
        print(f"    {имя:<32} {метка}")
    print()

    # проверка через git
    корень = папка.parent
    if (корень / ".git").exists():
        print("  ── проверка git ──")
        try:
            игнор = (корень / ".gitignore").read_text(encoding="utf-8")
        except OSError:
            игнор = ""
        локальный = (папка / ".gitignore").exists()

        if not игнор and not локальный:
            print("    [!!] НЕТ .gitignore — секреты уедут в коммит")
            return 1

        rel = секрет.relative_to(корень).as_posix()
        итог = subprocess.run(
            ["git", "check-ignore", "-v", rel],
            cwd=str(корень), capture_output=True, text=True)
        if итог.returncode == 0:
            print(f"    [ok] {rel} игнорируется")
            print(f"         {итог.stdout.strip()}")
        else:
            print(f"    [!!] {rel} НЕ игнорируется — уедет в коммит")
            return 1
    else:
        print("  git не найден, проверка пропущена")
    print()

    # проверка содержимого: не лежит ли секрет где-то ещё
    print("  ── где ещё встречаются значения ──")
    найдено = []
    for путь in корень.rglob("*"):
        if not путь.is_file() or ".git" in путь.parts:
            continue
        if путь.suffix.lower() in (".zip", ".exe", ".dll", ".pyc",
                                   ".png", ".jpg", ".sqlite", ".db"):
            continue
        try:
            текст = путь.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for имя, значение in живые.items():
            if значение in текст and путь.resolve() != секрет.resolve():
                найдено.append((путь.relative_to(корень), имя))

    if найдено:
        for файл, имя in sorted({(str(f), i) for f, i in найдено}):
            print(f"    [!!] {имя} встречается в {файл}")
        return 1

    print("    больше нигде не встречаются")
    print()
    print("  [ok] Всё в порядке.")
    return 0


def главный() -> int:
    разбор = argparse.ArgumentParser(
        description="Папка секретов SORA: создать и проверить")
    разбор.add_argument("--путь", default=None,
                        help="куда создавать (по умолчанию рядом с tools)")
    разбор.add_argument("--проверить", action="store_true",
                        help="только проверить, ничего не создавать")
    арг = разбор.parse_args()

    папка = Path(арг.путь) if арг.путь else \
        (Path(__file__).resolve().parent.parent / "client" / "secrets")

    if арг.проверить:
        return проверить(папка)

    print()
    print("═" * 62)
    print("  ПАПКА СЕКРЕТОВ SORA")
    print("═" * 62)
    print()
    print(f"  папка: {папка}")
    print()

    создано = создать(папка)
    if создано:
        for имя in создано:
            print(f"  создан: {имя}")
    else:
        print("  всё уже было на месте, ничего не тронуто")
    print()

    код = проверить(папка)
    return код


if __name__ == "__main__":
    sys.exit(главный())
