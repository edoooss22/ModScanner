"""
Сборка встроенной таблицы имён игры для ModScanner (разовый шаг, результат лежит в Resources/names.tsv.gz).

Источники (кеш Fabric Loom и таблица Yarn из прежнего проекта):
  * layered-маппинги Loom 1.21.10 / 1.21.11: official -> intermediary -> named (имена Mojang);
  * yarn-1.21.tsv.gz: intermediary -> Yarn для 1.21 ... 1.21.11;
  * minecraft-merged.jar 26.2 (игра без обфускации) и 1.21.11 (обфусцированная, переводится в имена
    Mojang через layered-маппинги) — для иерархии классов.

Формат строк результата (TSV):
  C  intermediaryClass  mojangClass  yarnClass
  M  intermediaryMember mojangOwner  mojangName  yarnOwner  yarnName
  H  mojangClass        super        iface1,iface2,...
"""
import gzip
import os
import struct
import sys
import zipfile

LOOM = os.path.expanduser("~/.gradle/caches/fabric-loom")
LAYERED = [
    f"{LOOM}/1.21.10/loom.mappings.1_21_10.layered+hash.2198-v2/mappings.tiny",
    f"{LOOM}/1.21.11/loom.mappings.1_21_11.layered+hash.2198-v2/mappings.tiny",
]
YARN = sys.argv[1] if len(sys.argv) > 1 else r"C:\Salam\Aizen_Solo\Minecraft\McScanner\ModScanner\src\ModScanner\Resources\yarn-1.21.tsv.gz"
JAR_UNOBF = [f"{LOOM}/26.2/minecraft-merged.jar"]
JAR_OBF_1_21_11 = f"{LOOM}/1.21.11/minecraft-merged.jar"
OUT = os.path.join(os.path.dirname(__file__), "..", "src", "ModScanner", "Resources", "names.tsv.gz")

cls_moj = {}      # intermediary class -> mojang
cls_yarn = {}     # intermediary class -> yarn
mem_moj = {}      # intermediary member -> (mojang owner, mojang name)
mem_yarn = {}     # intermediary member -> (yarn owner (intermediary), yarn name)
obf2moj = {}      # official (1.21.11) -> mojang, для иерархии

for path in LAYERED:
    is_last = path.endswith("1_21_11.layered+hash.2198-v2/mappings.tiny")
    cur_int = cur_moj = None
    with open(path, encoding="utf-8") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if p[0] == "c":
                off, inter, moj = p[1], p[2], p[3]
                cur_int, cur_moj = inter, moj
                cls_moj[inter] = moj
                if is_last:
                    obf2moj[off] = moj
            elif len(p) >= 6 and p[0] == "" and p[1] in ("m", "f"):
                inter, moj = p[4], p[5]
                if inter.startswith(("method_", "field_", "comp_")):
                    mem_moj[inter] = (cur_moj, moj)

with gzip.open(YARN, "rt", encoding="utf-8") as f:
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) == 2:
            cls_yarn[p[0]] = p[1]
        elif len(p) == 3 and p[0].startswith(("method_", "field_", "comp_")):
            mem_yarn[p[0]] = (p[2], p[1])


def read_hierarchy(data):
    """Имя класса, суперкласс и интерфейсы из байтов .class (минимальный разбор пула констант)."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        return None
    n = struct.unpack(">H", data[8:10])[0]
    pos = 10
    utf8 = {}
    classes = {}
    i = 1
    while i < n:
        tag = data[pos]
        pos += 1
        if tag == 1:
            ln = struct.unpack(">H", data[pos:pos + 2])[0]
            utf8[i] = data[pos + 2:pos + 2 + ln].decode("utf-8", "replace")
            pos += 2 + ln
        elif tag in (3, 4):
            pos += 4
        elif tag in (5, 6):
            pos += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            if tag == 7:
                classes[i] = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            pos += 4
        elif tag == 15:
            pos += 3
        else:
            return None
        i += 1
    pos += 2
    this_i, super_i = struct.unpack(">HH", data[pos:pos + 4])
    pos += 4
    ic = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    ifs = [struct.unpack(">H", data[pos + 2 * k:pos + 2 * k + 2])[0] for k in range(ic)]
    name = lambda ci: utf8.get(classes.get(ci, 0), "")
    return name(this_i), (name(super_i) if super_i else ""), [name(x) for x in ifs]


hier = {}


def add_jar(path, rename=None):
    with zipfile.ZipFile(path) as z:
        for e in z.namelist():
            if not e.endswith(".class"):
                continue
            h = read_hierarchy(z.read(e))
            if not h:
                continue
            c, s, ifs = h
            if rename:
                c = rename(c)
                s = rename(s) if s else s
                ifs = [rename(x) for x in ifs]
            if not c.startswith(("net/minecraft/", "com/mojang/")):
                continue
            hier[c] = (s, ifs)


def rename_obf(n):
    if n in obf2moj:
        return obf2moj[n]
    if "$" in n:
        outer, inner = n.split("$", 1)
        if outer in obf2moj:
            return obf2moj[outer] + "$" + inner
    return n


if os.path.exists(JAR_OBF_1_21_11):
    add_jar(JAR_OBF_1_21_11, rename_obf)
for j in JAR_UNOBF:
    if os.path.exists(j):
        add_jar(j)

rows = []
for inter in sorted(set(cls_moj) | set(cls_yarn)):
    rows.append(f"C\t{inter}\t{cls_moj.get(inter, '')}\t{cls_yarn.get(inter, '')}")
for inter in sorted(set(mem_moj) | set(mem_yarn)):
    mo, mn = mem_moj.get(inter, ("", ""))
    yo, yn = mem_yarn.get(inter, ("", ""))
    yo_named = cls_yarn.get(yo, yo) if yo else ""
    rows.append(f"M\t{inter}\t{mo}\t{mn}\t{yo_named}\t{yn}")
for c in sorted(hier):
    s, ifs = hier[c]
    keep = lambda x: x.startswith(("net/minecraft/", "com/mojang/"))
    s = s if keep(s) else ""
    ifs = [x for x in ifs if keep(x)]
    if s or ifs:
        rows.append(f"H\t{c}\t{s}\t{','.join(ifs)}")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as f:
    f.write("\n".join(rows) + "\n")
print(f"classes={len(set(cls_moj) | set(cls_yarn))} members={len(set(mem_moj) | set(mem_yarn))} hierarchy={len(hier)} -> {os.path.abspath(OUT)} ({os.path.getsize(OUT)} bytes)")
