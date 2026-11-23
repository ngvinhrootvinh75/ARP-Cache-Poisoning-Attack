import re

MAU_EMAIL = rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
MAU_SDT = rb"(?<![0-9])(?:\+84|0)(?:[0-9][ .-]?){8,9}[0-9](?![0-9])"


def _che_khop(match):
    return b"X" * len(match.group())


def che_thong_tin(du_lieu):
    du_lieu = re.sub(MAU_EMAIL, _che_khop, du_lieu)
    du_lieu = re.sub(MAU_SDT, _che_khop, du_lieu)
    return du_lieu


def build_name_pattern(names):
    names = sorted(set(names), key=len, reverse=True)
    alts = b"|".join(re.escape(n.encode("utf-8")) for n in names)
    return re.compile(b"(?<![A-Za-z])(?:" + alts + b")(?![A-Za-z])")


def thay_ten(du_lieu, pattern):
    return pattern.sub(lambda m: b"A" * len(m.group()), du_lieu)

