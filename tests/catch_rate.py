#!/usr/bin/env python3
"""catch_rate.py — замер доли, которую фильтр входа guard ловит на корпусе.

Назначение: превратить «xfail по обфускации» в число для отчёта —
«поймано N из M (XX%)», как в строках A-09 / C-15 чек-листа L1.

Как это работает:
  - корпус — текстовый файл, по одному payload на строку (строки с # и пустые
    игнорируются). Каждый payload — это то, что фильтр ДОЛЖЕН заблокировать
    (вариант секрета / инъекции).
  - скрипт прогоняет каждый payload через `guard submit` и смотрит код возврата:
    1 = заблокирован (поймано), 0 = пропущен (промах).
  - в отчёте печатаются ТОЛЬКО номера непойманных строк, не их текст —
    чтобы отчёт не превращался в готовый список обходов.

Корпус наполняешь сам: из своего набора A-09 / C-15 или из вывода пробы
Garak `encoding` (`garak --probes encoding ...`). Скрипт payload'ы не придумывает.

Запуск:
  python3 tools/catch_rate.py --policy examples/policy.json \
      --corpus tests/corpus/secrets.txt [--min-rate 0.8]

Код возврата: 0, если доля >= --min-rate (по умолчанию проверки нет), иначе 2 —
удобно для CI как порог качества фильтра.
"""

import argparse
import pathlib
import subprocess
import sys


def load_corpus(path: pathlib.Path):
    items = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        items.append((i, line))
    return items


def is_blocked(guard: str, policy: str, cwd: str, payload: str) -> bool:
    r = subprocess.run(
        [guard, "submit", "--policy", policy, "--prompt", payload],
        cwd=cwd, capture_output=True, text=True,
    )
    return r.returncode == 1  # 1 = refused by the input filter


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--guard", default="./guard")
    ap.add_argument("--cwd", default=".")
    ap.add_argument("--min-rate", type=float, default=None,
                    help="порог доли пойманного для ненулевого кода возврата")
    args = ap.parse_args()

    corpus_path = pathlib.Path(args.corpus)
    if not corpus_path.exists():
        print(f"корпус не найден: {corpus_path}", file=sys.stderr)
        return 2

    items = load_corpus(corpus_path)
    if not items:
        print("корпус пуст — заполни его payload'ами (по одному на строку)", file=sys.stderr)
        return 2

    caught, missed_lines = 0, []
    for lineno, payload in items:
        if is_blocked(args.guard, args.policy, args.cwd, payload):
            caught += 1
        else:
            missed_lines.append(lineno)

    total = len(items)
    rate = caught / total
    print(f"корпус:        {corpus_path}")
    print(f"поймано:       {caught} из {total} ({rate:.0%})")
    if missed_lines:
        # только номера строк, не текст payload'ов
        nums = ", ".join(str(n) for n in missed_lines)
        print(f"пропущено на строках: {nums}")
        print("(посмотри эти строки в корпусе локально — в отчёт текст не выводится)")
    else:
        print("пропусков нет")

    if args.min_rate is not None and rate < args.min_rate:
        print(f"ниже порога {args.min_rate:.0%}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
