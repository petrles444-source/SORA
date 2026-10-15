# -*- coding: utf-8 -*-
r"""
ТЕСТЫ ПРИМЕНЕНИЯ БЛОКИРОВОК
============================

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ
--------------------
`sora_traffic.py apply` правит файл, который прямо сейчас читает
работающий VPN. Ошибка здесь означает не «не посчитался трафик», а
«у человека отвалился интернет» или «сервер не грузится».

Поэтому проверяется не только успешный случай, но и отказы: что
происходит, когда подсовывать плохое.

ЧТО ПРОВЕРЯЕТСЯ
---------------
    1. Заблокированный убирается из конфига
    2. Остальные остаются нетронутыми — важно: убираем ОДНОГО
    3. Секция вырезается целиком: и комментарий, и поля
       (полувырезанная секция без PublicKey не запустится вообще)
    4. Пустой конфиг, битый конфиг — отказ без порчи
    5. Нечего убирать — файл не трогаем
    6. Возврат человека из резервной копии

ПОЧЕМУ НЕ НАСТОЯЩИЙ СЕРВЕР
--------------------------
Проверка идёт по копии во временном каталоге. Настоящий systemd и
iptables подменяются: тест проверяет логику правки конфига, а не
поведение системы — его проверяет приёмка на сервере.

ЗАПУСК
------
    python test_sora_apply.py

КОД ВОЗВРАТА
------------
0 — все проверки пройдены
1 — есть расхождения
"""
from __future__ import annotations

import importlib.util
import io
import os
import shutil
import sys
import tempfile

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
МОДУЛЬ = os.path.join(КОРЕНЬ, "tools", "sora_traffic.py")

ИТОГИ = []


def записать(имя, годно, деталь=""):
    ИТОГИ.append((годно, имя, деталь))
    print("  %s %s" % ("[ок]" if годно else "[!!]", имя))
    if not годно and деталь:
        print("         %s" % деталь)


КОНФИГ = """# SORA — конфигурация СЕРВЕРА

[Interface]
PrivateKey = Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==
Address = 10.77.0.1/24
ListenPort = 39117
Jc = 4

# --- ivan  (ноутбук)
[Peer]
PublicKey = aXZhbmtleXB1YmxpY2tleXB1YmxpY2tleXB1Ynk9
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM9
AllowedIPs = 10.77.0.2/32

# --- masha  (телефон)
[Peer]
PublicKey = bWFzaGFwdWJrZXltYXNoYXB1YmxpY2tleXB1YmxpY2s9
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM9
AllowedIPs = 10.77.0.3/32

# --- petr  (телефон старый)
[Peer]
PublicKey = cGV0cmtleXBldHJrZXlwZXRya2V5cGV0cmtleXBldHJrZXk9
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM9
AllowedIPs = 10.77.0.4/32
"""


def окружение():
    база = tempfile.mkdtemp(prefix="sora_apply_t_")
    etc = os.path.join(база, "etc")
    var = os.path.join(база, "var")
    os.makedirs(etc)
    os.makedirs(var)

    конф = os.path.join(etc, "server.conf")
    with open(конф, "w", encoding="utf-8") as f:
        f.write(КОНФИГ)

    spec = importlib.util.spec_from_file_location("sora_traffic_a", МОДУЛЬ)
    st = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(st)
    st.КАТ_СЕРВЕРА = etc
    st.ПУТЬ_КОНФ = конф
    st.ПУТЬ_ЛИМИТЫ = os.path.join(etc, "quotas.json")
    st.ПУТЬ_БЛОК = os.path.join(etc, "blocked.json")
    st.КАТ_ДАННЫХ = var
    st.ПУТЬ_СОСТОЯНИЕ = os.path.join(var, "traffic.json")
    st.ПУТЬ_CSV = os.path.join(var, "traffic.csv")
    st.ПУТЬ_ИСТОРИЯ = os.path.join(var, "history")

    # systemd на машине тестов нет — подменяем на успешный вызов
    st.subprocess = _ПодменаВозврата
    return st, конф, база


class _ПодменаВозврата:
    """Заглушка subprocess.run — systemd не нужен для проверки правок."""

    class P:
        returncode = 0
        stdout = ""
        stderr = ""

    @staticmethod
    def run(*a, **kw):
        return _ПодменаВозврата.P()


def читать_людей(st):
    with open(st.ПУТЬ_КОНФ, encoding="utf-8") as f:
        return st.разобрать_конфиг(f.read())


# ══════════════════════════════════════════════════════════════
def тест_вырезается_целиком():
    st, конф, база = окружение()
    st.записать_json(st.ПУТЬ_БЛОК, ["masha"])
    n, сообщение = st.применить_блокировки(тихо=True)

    люди = читать_людей(st)
    if n != 1:
        записать("вырезается целиком: ровно один человек", False,
                 "убрано %d" % n)
    else:
        записать("вырезается целиком: ровно один человек", True)

    if "masha" not in люди:
        записать("вырезается целиком: заблокированный убран", True)
    else:
        записать("вырезается целиком: заблокированный убран", False,
                 "masha осталась в конфиге")

    if set(люди) == {"ivan", "petr"}:
        записать("вырезается целиком: остальные целы", True)
    else:
        записать("вырезается целиком: остальные целы", False,
                 "остались %s" % sorted(люди))

    # Проверяем именно целокупность секции: у masha не должно
    # остаться ни строчки — ни комментария, ни AllowedIPs.
    текст = io.open(конф, encoding="utf-8").read()
    хвосты = [s for s in текст.splitlines()
              if "10.77.0.3" in s or "masha" in s]
    if хвосты:
        записать("вырезается целиком: не осталось огрызков", False,
                 "остались строки: %s" % хвосты)
    else:
        записать("вырезается целиком: не осталось огрызков", True)

    if os.path.exists(конф + ".bak"):
        записать("вырезается целиком: есть резервная копия", True)
    else:
        записать("вырезается целиком: есть резервная копия", False)

    shutil.rmtree(база, ignore_errors=True)


def тест_двое_сразу():
    st, конф, база = окружение()
    st.записать_json(st.ПУТЬ_БЛОК, ["masha", "petr"])
    n, _ = st.применить_блокировки(тихо=True)
    люди = читать_людей(st)

    if n == 2 and set(люди) == {"ivan"}:
        записать("двое сразу: оба убраны, один остался", True)
    else:
        записать("двое сразу: оба убраны, один остался", False,
                 "убрано %d, остались %s" % (n, sorted(люди)))
    shutil.rmtree(база, ignore_errors=True)


def тест_нечего_убирать():
    st, конф, база = окружение()
    до = io.open(конф, encoding="utf-8").read()
    n, _ = st.применить_блокировки(тихо=True)          # блок пуст
    после = io.open(конф, encoding="utf-8").read()

    if n == 0 and до == после:
        записать("нечего убирать: файл не тронут", True)
    else:
        записать("нечего убирать: файл не тронут", False,
                 "убрано %d, файл изменился: %s" % (n, до != после))
    shutil.rmtree(база, ignore_errors=True)


def те_чего_нет_в_конфиге():
    st, конф, база = окружение()
    до = io.open(конф, encoding="utf-8").read()
    st.записать_json(st.ПУТЬ_БЛОК, ["kostya"])         # такого нет
    n, _ = st.применить_блокировки(тихо=True)
    после = io.open(конф, encoding="utf-8").read()

    if n == 0 and до == после:
        записать("несуществующий в блоке: файл не тронут", True)
    else:
        записать("несуществующий в блоке: файл не тронут", False,
                 "убрано %d, файл изменился: %s" % (n, до != после))
    shutil.rmtree(база, ignore_errors=True)


def тест_битый_конфиг():
    st, конф, база = окружение()
    # подсовываем мусор: разбор должен спокойно пережить его
    мусор = "[Peer]\nPublicKey = \nAllowedIPs = не-adres\n"
    with open(конф, "w", encoding="utf-8") as f:
        f.write(мусор)
    st.записать_json(st.ПУТЬ_БЛОК, ["kto-to"])
    try:
        n, _ = st.применить_блокировки(тихо=True)
        текст = io.open(конф, encoding="utf-8").read()
        if текст == мусор or n == 0:
            записать("битый конфиг: не падаем и не портим", True)
        else:
            записать("битый конфиг: не падаем и не портим", False,
                     "конфиг изменён неожиданно")
    except Exception as e:
        записать("битый конфиг: не падаем и не портим", False,
                 "исключение: %s" % e)
    shutil.rmtree(база, ignore_errors=True)


def тест_пустой_конфиг():
    st, конф, база = окружение()
    open(конф, "w", encoding="utf-8").close()
    st.записать_json(st.ПУТЬ_БЛОК, ["ivan"])
    try:
        st.применить_блокировки(тихо=True)
        текст = io.open(конф, encoding="utf-8").read()
        if текст.strip() == "":
            записать("пустой конфиг: не падаем", True)
        else:
            записать("пустой конфиг: не падаем", False,
                     "в пустой файл что-то вписали")
    except Exception as e:
        записать("пустой конфиг: не падаем", False, "исключение: %s" % e)
    shutil.rmtree(база, ignore_errors=True)


def тест_возврат():
    st, конф, база = окружение()
    st.записать_json(st.ПУТЬ_БЛОК, ["masha"])
    st.применить_блокировки(тихо=True)
    if "masha" in читать_людей(st):
        записать("возврат: сначала убрали", False)
        shutil.rmtree(база, ignore_errors=True)
        return
    записать("возврат: сначала убрали", True)

    # Возвращаем НАСТОЯЩЕЙ функцией, а не собранной вручную операцией.
    # Первая версия теста вызывала _пересобрать на копии — то есть
    # делала ровно то неверное действие, из-за которого человек и
    # не возвращался. Тест повторял ошибку, а не проверял её.
    st.вернуть_блокировку("masha")

    люди = читать_людей(st)
    if set(люди) == {"ivan", "masha", "petr"}:
        записать("возврат: все трое на месте", True)
    else:
        записать("возврат: все трое на месте", False,
                 "после возврата: %s" % sorted(люди))

    блок = st.прочитать_json(st.ПУТЬ_БЛОК, [])
    if "masha" not in блок:
        записать("возврат: снят из списка заблокированных", True)
    else:
        записать("возврат: снят из списка заблокированных", False,
                 "в blocked.json всё ещё: %s" % блок)
    shutil.rmtree(база, ignore_errors=True)


# ══════════════════════════════════════════════════════════════
def main():
    print()
    print("═" * 70)
    print("  ТЕСТЫ ПРИМЕНЕНИЯ БЛОКИРОВОК")
    print("  здесь правится живой конфиг VPN — цена ошибки высока")
    print("═" * 70)
    print()

    тест_вырезается_целиком()
    тест_двое_сразу()
    тест_нечего_убирать()
    те_чего_нет_в_конфиге()
    тест_битый_конфиг()
    тест_пустой_конфиг()
    тест_возврат()

    ок = sum(1 for г, _, _ in ИТОГИ if г)
    print()
    print("─" * 70)
    print("  результат: %d из %d" % (ок, len(ИТОГИ)))
    if ок == len(ИТОГИ):
        print("  конфиг правится аккуратно: убирает нужное, не трогает лишнее")
    else:
        for г, имя, деталь in ИТОГИ:
            if not г:
                print("    %s — %s" % (имя, деталь))
    print("─" * 70)
    print()

    return 0 if ок == len(ИТОГИ) else 1


if __name__ == "__main__":
    sys.exit(main())
