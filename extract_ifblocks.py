#!/usr/bin/env python3
"""Extract two type-guarded if-blocks of Generate_Aggregate into standalone
functions. Tree-sitter driven. Each target if-block must end in return."""
import sys, tree_sitter_c
from tree_sitter import Language, Parser
apply = "--apply" in sys.argv
src = open("ada83.c","rb").read()
parser = Parser(Language(tree_sitter_c.language()))
tree = parser.parse(src)
def walk(n):
    yield n
    for c in n.children: yield from walk(c)
fn = None
for n in walk(tree.root_node):
    if n.type=="function_definition":
        x=n.child_by_field_name("declarator")
        while x is not None and x.type!="identifier": x=x.child_by_field_name("declarator")
        if x is not None and x.text.decode()=="Generate_Aggregate": fn=n; break
body = fn.child_by_field_name("body")
targets = {"Type_Is_Array_Like":"Generate_Array_Aggregate",
           "Type_Is_Record":"Generate_Record_Aggregate"}
edits=[]; new_funcs=[]
for c in body.children:
    if c.type!="if_statement": continue
    cond = c.child_by_field_name("condition")
    cons = c.child_by_field_name("consequence")
    cond_txt = src[cond.start_byte:cond.end_byte].decode()
    name=None
    for marker,fname in targets.items():
        if marker in cond_txt: name=fname; break
    if not name: continue
    assert cons.type=="compound_statement", cons.type
    inner = src[cons.start_byte+1:cons.end_byte-1].decode()
    new_funcs.append(f"uint32_t {name} (Syntax_Node *node, Type_Info *agg_type) {{\n{inner}\n}}\n\n")
    repl = f"if {cond_txt}\n    return {name} (node, agg_type);".encode()
    edits.append((c.start_byte, c.end_byte, repl))
    print(f"  {name}: if-block {c.start_point[0]+1}-{c.end_point[0]+1}, body {inner.count(chr(10))+1} lines")
edits.append((fn.start_byte, fn.start_byte, "".join(new_funcs).encode()))
print("new functions:", [t for t in targets.values()])
if apply:
    for s,e,txt in sorted(edits, key=lambda z:z[0], reverse=True):
        src=src[:s]+txt+src[e:]
    open("ada83.c","wb").write(src); print("APPLIED")
else: print("DRY RUN")
