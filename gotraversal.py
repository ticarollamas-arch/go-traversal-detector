#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detector de Path Traversal em Go — análise estática honesta.

Procura chamadas a filepath.Join / os.Open / os.ReadFile e verifica se, na MESMA
função, existe uma barreira de contenção (HasPrefix, filepath.Rel, filepath.Clean
com checagem, os.Root, EvalSymlinks + verificação). Se não houver, marca como
CANDIDATO A REVISÃO — nunca como "vulnerável comprovado".

A ferramenta NÃO executa nada, NÃO prova exploração e NÃO gera PoC. Ela aponta
onde um humano precisa olhar. Essa honestidade é intencional.

Uso:
    python3 gotraversal.py <arquivo.go | pasta>
    python3 gotraversal.py --test
"""

import os
import re
import sys
from pathlib import Path

# Sinks: onde um caminho é usado para acessar o sistema de arquivos.
SINKS = re.compile(
    r"\b(filepath\.Join|path\.Join|os\.Open(?:File)?|os\.ReadFile|ioutil\.ReadFile|"
    r"os\.Create|os\.Stat|os\.MkdirAll|os\.Mkdir)\s*\(",
)

# Fontes: valor que veio de fora e não deveria ser confiado.
SOURCE_HINTS = re.compile(
    r"\b(subdir|subpath|subPath|userPath|relPath|input|param|query|"
    r"r\.URL|r\.Form|req\.|request\.|filename|fileName|userInput|"
    r"c\.Param|ctx\.Param|vars\[)",
    re.IGNORECASE,
)

# Barreiras de contenção reconhecidas: se alguma aparecer na mesma função, o
# achado é rebaixado — o código provavelmente se protege.
GUARDS = re.compile(
    r"(strings\.HasPrefix\s*\([^)]*\b(?:base|root|realBase|realRoot|dir)\b|"
    r"filepath\.Rel\s*\(|"
    r"os\.Root\b|os\.OpenInRoot|"
    r"securejoin|SecureJoin|"
    r"filepath\.IsLocal\s*\(|"
    r"strings\.Contains\s*\([^)]*\"\.\.\"|"
    r"doSafeMakeDir|doSafeOpen)",  # helpers internos que já contêm a checagem
)

GO_KEYWORDS_FUNC = re.compile(r"^\s*func\b")


def find_functions(lines):
    """Divide o arquivo em (nome, inicio, fim, corpo) por função, via contagem de chaves."""
    funcs = []
    i = 0
    n = len(lines)
    while i < n:
        if GO_KEYWORDS_FUNC.match(lines[i]):
            start = i
            # nome aproximado da função
            m = re.search(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)", lines[i])
            name = m.group(1) if m else "?"
            depth = lines[i].count("{") - lines[i].count("}")
            i += 1
            while i < n and depth > 0:
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            funcs.append((name, start, i, lines[start:i]))
        else:
            i += 1
    return funcs


def analyze_file(path: Path, base: Path):
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    try:
        rel = str(path.relative_to(base))
    except ValueError:
        rel = str(path)

    findings = []
    for name, start, end, body in find_functions(lines):
        body_text = "\n".join(body)
        has_guard = bool(GUARDS.search(body_text))
        for off, line in enumerate(body):
            if not SINKS.search(line):
                continue
            # o sink recebe algo que parece entrada não confiável?
            tainted = bool(SOURCE_HINTS.search(line)) or bool(SOURCE_HINTS.search(body_text))
            if not tainted:
                continue
            lineno = start + off + 1
            if has_guard:
                conf = "provavelmente-seguro"
                nota = "há barreira de contenção nesta função — revise se cobre este caminho."
            else:
                conf = "revisar"
                nota = "nenhuma barreira de contenção visível nesta função."
            findings.append((rel, lineno, name, line.strip()[:100], conf, nota))
    return findings


def scan(target: str):
    base = Path(target)
    if not base.exists():
        print(f"ERRO: não existe: {target}")
        return 2
    files = [base] if base.is_file() else [
        p for p in base.rglob("*.go")
        if "vendor" not in p.parts and not p.name.endswith("_test.go")
    ]
    all_find = []
    for f in files:
        all_find.extend(analyze_file(f, base if base.is_dir() else base.parent))

    print("=" * 70)
    print("DETECTOR DE PATH TRAVERSAL EM GO — análise estática")
    print("=" * 70)
    if not all_find:
        print("Nenhum candidato encontrado.")
    # revisar primeiro, seguros depois
    order = {"revisar": 0, "provavelmente-seguro": 1}
    for rel, ln, fn, code, conf, nota in sorted(all_find, key=lambda x: order[x[4]]):
        marca = "!!" if conf == "revisar" else "ok"
        print(f"\n[{marca}] {conf.upper()}  {rel}:{ln}  (func {fn})")
        print(f"     {code}")
        print(f"     -> {nota}")

    n_rev = sum(1 for x in all_find if x[4] == "revisar")
    print("\n" + "=" * 70)
    print(f"arquivos: {len(files)}   candidatos: {len(all_find)}   a revisar: {n_rev}")
    print("=" * 70)
    print(
        "\nEstes são CANDIDATOS de análise estática, não vulnerabilidades comprovadas.\n"
        "Um achado 'a revisar' significa: nenhuma barreira óbvia nesta função — vá LER\n"
        "o código e as funções que ela chama antes de concluir qualquer coisa. A ausência\n"
        "de barreira aqui pode significar que a checagem está numa função auxiliar."
    )
    return 1 if n_rev else 0


def autoteste():
    print("Autoteste do detector...\n")
    vulneravel = """package x
func (s *svc) leia(subdir string, base string) error {
    full := filepath.Join(base, subdir)
    return os.ReadFile(full)
}
"""
    protegido = """package x
func (s *svc) leiaSeguro(subdir string, base string) error {
    full := filepath.Join(base, subdir)
    if !strings.HasPrefix(full, base) {
        return fmt.Errorf("escape")
    }
    return os.ReadFile(full)
}
"""
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        pv = Path(d) / "vuln.go"; pv.write_text(vulneravel)
        pp = Path(d) / "safe.go"; pp.write_text(protegido)
        fv = analyze_file(pv, Path(d))
        fp = analyze_file(pp, Path(d))
        got_v = any(c == "revisar" for *_, c, _ in fv)
        got_s = any(c == "provavelmente-seguro" for *_, c, _ in fp)
        print(f"  código sem barreira marcado 'revisar':        {'OK' if got_v else 'FALHOU'}")
        print(f"  código com HasPrefix marcado 'provavelmente': {'OK' if got_s else 'FALHOU'}")
        ok = got_v and got_s
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--test" in argv:
        return autoteste()
    if not argv:
        print(__doc__)
        return 0
    return scan(argv[0])


if __name__ == "__main__":
    sys.exit(main())
