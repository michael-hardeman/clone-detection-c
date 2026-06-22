#!/usr/bin/env python3
"""Extract inlined switch-case arms of a function into standalone functions.
Tree-sitter driven (precise byte ranges; safe against brace-in-string).
Usage: extract_arms.py FILE FUNC CASE=NewName [CASE=NewName ...] [--apply]
"""
import sys, tree_sitter_c
from tree_sitter import Language, Parser

path, func = sys.argv[1], sys.argv[2]
apply = "--apply" in sys.argv
mapping = {}
for a in sys.argv[3:]:
    if "=" in a:
        k, v = a.split("=", 1); mapping[k] = v

src = open(path, "rb").read()
parser = Parser(Language(tree_sitter_c.language()))
tree = parser.parse(src)

def walk(n):
    yield n
    for c in n.children: yield from walk(c)

fn = None
for n in walk(tree.root_node):
    if n.type == "function_definition":
        x = n.child_by_field_name("declarator")
        while x is not None and x.type != "identifier":
            x = x.child_by_field_name("declarator")
        if x is not None and x.text.decode() == func:
            fn = n; break
assert fn, f"function {func} not found"

sw = next(n for n in walk(fn) if n.type == "switch_statement")
body = sw.child_by_field_name("body")

edits = []          # (start, end, text)
new_funcs = []      # text blocks
for case in body.children:
    if case.type != "case_statement":
        continue
    val = case.child_by_field_name("value")
    if val is None:  # default:
        continue
    name = mapping.get(val.text.decode())
    if not name:
        continue
    kids = list(case.children)
    ci = next(i for i, k in enumerate(kids) if k.type == ":")
    bodyk = kids[ci + 1:]
    while bodyk and bodyk[-1].type == "break_statement":
        bodyk.pop()
    assert bodyk, f"{name}: empty body"
    if len(bodyk) == 1 and bodyk[0].type == "compound_statement":
        b0 = bodyk[0]
        body_text = src[b0.start_byte + 1:b0.end_byte - 1].decode()
    else:
        body_text = src[bodyk[0].start_byte:bodyk[-1].end_byte].decode()
    new_funcs.append(f"void {name} (Syntax_Node *node) {{\n{body_text}\n}}\n\n")
    repl = f"case {val.text.decode()}:\n      {name} (node);\n      break;".encode()
    edits.append((case.start_byte, case.end_byte, repl))
    print(f"  {name}: arm bytes {case.start_byte}-{case.end_byte}, "
          f"body lines={body_text.count(chr(10))+1}")

# insert extracted functions immediately before the host function
ins = "".join(new_funcs).encode()
edits.append((fn.start_byte, fn.start_byte, ins))

print(f"new functions: {[m for m in mapping.values()]}")
print(f"host {func} start byte {fn.start_byte}")

if apply:
    for s, e, txt in sorted(edits, key=lambda z: z[0], reverse=True):
        src = src[:s] + txt + src[e:]
    open(path, "wb").write(src)
    print("APPLIED")
else:
    print("DRY RUN (pass --apply to write)")
