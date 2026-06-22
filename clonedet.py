#!/usr/bin/env python3
"""
clonedet — AST clone detector for C, tuned to surface "extract to a common
subprogram" candidates rather than raw textual similarity.

Pipeline (see docs/code-quality.md for the rationale):

  1. Parse each file with tree-sitter-c (error-tolerant; GNU extensions are fine)
     and collect a translation-unit symbol table (functions, file-scope globals,
     enum constants, macros) so external references can be told from locals.
  2. Bottom-up *normalized Merkle hash* of every subtree. Leaves that are
     parameter-like (identifiers, literals) collapse to a class token, so two
     subtrees that differ only in variable names / constants get the SAME hash
     (Type-1 and Type-2 clones). Operators, keywords, and *type* names are kept
     verbatim — `<` vs `<=` and `i32` vs `i64` are real differences, never fused.
  3. Bucket subtrees by hash. A bucket with >= MIN_INSTANCES members is a class.
  4. Free-variable + anti-unification analysis per class. Lexical scope analysis
     classifies every leaf as LOCAL (declared inside the candidate), a GLOBAL /
     macro / callee, or a FREE variable (read or written from outside). The
     accurate parameter list is:
       * every FREE variable  (an external input; by-reference if it is written
         inside the candidate — a true in/out parameter), UNION
       * every literal / macro / callee slot whose value VARIES across the clone
         instances (consistent renames collapse to one parameter).
     Internal renaming of locals no longer inflates the count.
  5. Rank by estimated lines saved = (instances-1)*lines - instances. Flag
     classes that are harder to lift (non-local control flow, in/out parameters,
     divergent struct-member access).
  6. Suppress non-maximal classes (a sub-clone fully contained inside an
     already-reported larger clone of the same multiplicity).

Output is a ranked worklist of clone classes. It does NOT edit code.

Usage:
  clonedet.py [options] FILE [FILE ...]

  --min-nodes N      min subtree size in AST nodes to be a candidate (default 40)
  --min-instances N  min members for a clone class (default 2)
  --min-lines N      min line span of the template (default 3)
  --min-saved N      only report classes with est. lines saved >= N (default 8)
  --top N            show at most N classes (default 40)
  --normalize-types  also collapse type names (find type-parameterizable clones)
  --no-suppress      do not suppress nested/contained clone classes
  --json             emit JSON instead of the human report
"""

import argparse
import hashlib
import json
import sys

import tree_sitter_c
from tree_sitter import Language, Parser

# Leaf node types treated as parameter slots: differences here become helper
# parameters, so they are normalized away for the structural hash.
PARAM_LEAVES = {
    "identifier": "#ID",
    "field_identifier": "#FLD",
    "number_literal": "#NUM",
    "string_literal": "#STR",
    "char_literal": "#CHR",
}
LITERAL_LEAVES = {"number_literal", "string_literal", "char_literal"}

# Named leaf types whose TEXT is structurally significant and must NOT be
# normalized (a clone that differs only in a type is not the same clone).
KEEP_TEXT = {"primitive_type", "type_identifier", "sized_type_specifier"}

# Presence of these in a template means extraction is not pure code-motion:
# the construct transfers control out of the candidate region.
CONTROL_ESCAPE = {
    "return_statement",
    "goto_statement",
    "break_statement",
    "continue_statement",
}

DECLARATOR_WRAPPERS = {
    "init_declarator",
    "pointer_declarator",
    "array_declarator",
    "function_declarator",
    "parenthesized_declarator",
}

# <iso646.h> operator spellings; also what tree-sitter error-recovery sometimes
# leaves as stray identifiers. Never real value parameters.
OPERATOR_WORDS = {
    "and", "or", "not", "xor", "bitand", "bitor", "compl",
    "and_eq", "or_eq", "xor_eq", "not_eq",
}

# Record layout stored per AST node, indexed by (file_idx, node.id):
DIGEST, SIZE, FILE, SB, EB, SR, ER, TYPE, NODE = range(9)


def iter_children(node):
    """Children with comments dropped, so formatting never affects a hash."""
    return [c for c in node.children if c.type != "comment"]


def node_text(node):
    return node.text.decode("utf-8", "replace")


def is_macro_caps(name):
    return name.isupper() and any(c.isalpha() for c in name)


def distinct(values, limit=3):
    out = []
    for v in values:
        if v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# Declarator / global-symbol collection
# --------------------------------------------------------------------------

def declarator_name(d):
    """Innermost declared identifier, following only `declarator` edges so that
    array sizes and initializers (which are uses, not declarations) are skipped."""
    while d is not None:
        if d.type == "identifier":
            return node_text(d)
        if d.type in DECLARATOR_WRAPPERS:
            d = d.child_by_field_name("declarator")
            continue
        nxt = d.child_by_field_name("declarator")
        if nxt is None:
            return None
        d = nxt
    return None


def declaration_declared_names(decl):
    """All names a `declaration` introduces (handles `int a, *b, c[3];`)."""
    names = []
    for ch in decl.children:
        if ch.type == "init_declarator" or ch.type in DECLARATOR_WRAPPERS \
                or ch.type == "identifier":
            nm = declarator_name(ch)
            if nm:
                names.append(nm)
    return names


def collect_globals(root, out):
    """File-scope names: functions, top-level objects, enum constants, macros.

    Enum constants and macros are collected at any depth (they are visible
    globally); functions and object declarations only at translation-unit top."""
    stack = [(root, 0)]
    while stack:
        n, depth = stack.pop()
        t = n.type
        if t == "enumerator":
            nm = n.child_by_field_name("name")
            if nm:
                out.add(node_text(nm))
        elif t in ("preproc_def", "preproc_function_def"):
            nm = n.child_by_field_name("name")
            if nm:
                out.add(node_text(nm))
        elif depth == 1 and t == "function_definition":
            nm = declarator_name(n.child_by_field_name("declarator"))
            if nm:
                out.add(nm)
        elif depth == 1 and t == "declaration":
            out.update(declaration_declared_names(n))
        for c in n.children:
            stack.append((c, depth + 1))


# --------------------------------------------------------------------------
# Structural hash
# --------------------------------------------------------------------------

def leaf_label(node, normalize_types):
    t = node.type
    if t in PARAM_LEAVES:
        return PARAM_LEAVES[t]
    if t in KEEP_TEXT:
        return "#TY" if normalize_types else "T:" + node_text(node)
    # Anonymous tokens (operators, keywords, punctuation) report their own text
    # as `.type`, which is exactly the structural label we want.
    return t


def compute_subtree_table(root, file_idx, normalize_types, table):
    """Post-order (iterative) fill of table[(file_idx, node.id)] = record.

    Iterative to survive the deep expression chains in generated C."""
    stack = [(root, False)]
    while stack:
        node, processed = stack.pop()
        if node.type == "comment":
            continue
        if not processed:
            stack.append((node, True))
            for ch in iter_children(node):
                stack.append((ch, False))
            continue

        kids = iter_children(node)
        h = hashlib.blake2b(digest_size=12)
        if kids:
            h.update(node.type.encode())
            size = 1
            for ch in kids:
                crec = table[(file_idx, ch.id)]
                h.update(crec[DIGEST])
                size += crec[SIZE]
        else:
            h.update(leaf_label(node, normalize_types).encode())
            size = 1
        sr, _ = node.start_point
        er, _ = node.end_point
        table[(file_idx, node.id)] = (
            h.digest(), size, file_idx, node.start_byte, node.end_byte,
            sr, er, node.type, node,
        )


# --------------------------------------------------------------------------
# Scope analysis over a candidate subtree
# --------------------------------------------------------------------------

def lvalue_base_id(node):
    """node.id of the identifier an lvalue ultimately writes through."""
    x = node
    while x is not None:
        t = x.type
        if t == "identifier":
            return x.id
        if t in ("subscript_expression", "field_expression", "pointer_expression"):
            x = x.child_by_field_name("argument")
            continue
        if t == "parenthesized_expression":
            named = [c for c in x.children if c.is_named]
            x = named[0] if named else None
            continue
        return None
    return None


def scope_sets(node):
    """One walk over the candidate: (local_names, callee_ids, write_ids)."""
    local_names = set()
    callee_ids = set()
    write_ids = set()
    stack = [node]
    while stack:
        x = stack.pop()
        t = x.type
        if t == "comment":
            continue
        if t == "declaration":
            local_names.update(declaration_declared_names(x))
        elif t == "parameter_declaration":
            nm = declarator_name(x.child_by_field_name("declarator"))
            if nm:
                local_names.add(nm)
        elif t == "call_expression":
            fn = x.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                callee_ids.add(fn.id)
        elif t == "identifier":
            # Fallback for error-recovered regions where call_expression did not
            # form: an identifier directly followed by an argument list is a callee.
            sib = x.next_named_sibling
            if sib is not None and sib.type == "argument_list":
                callee_ids.add(x.id)
        elif t == "assignment_expression":
            bid = lvalue_base_id(x.child_by_field_name("left"))
            if bid is not None:
                write_ids.add(bid)
        elif t == "update_expression":
            bid = lvalue_base_id(x.child_by_field_name("argument"))
            if bid is not None:
                write_ids.add(bid)
        stack.extend(iter_children(x))
    return local_names, callee_ids, write_ids


def template_slots(node, globals_, local_names, callee_ids, write_ids):
    """Pre-order (matching param_fill) classification of every parameter leaf.

    Returns (slots, free_writes) where slots[i] = (text, kind, direction):
      kind in {FREE, LOCAL, GLOBAL, CALLEE, LIT, FIELD}
    free_writes is the set of FREE variable names written inside the candidate."""
    slots = []
    free_writes = set()
    stack = [node]
    while stack:
        x = stack.pop()
        if x.type == "comment":
            continue
        kids = iter_children(x)
        if not kids:
            t = x.type
            if t == "field_identifier":
                slots.append((node_text(x), "FIELD", "in"))
            elif t in LITERAL_LEAVES:
                slots.append((node_text(x), "LIT", "in"))
            elif t == "identifier":
                txt = node_text(x)
                if x.id in callee_ids:
                    slots.append((txt, "CALLEE", "in"))
                elif txt in local_names:
                    slots.append((txt, "LOCAL", "in"))
                elif txt in globals_ or txt in OPERATOR_WORDS or is_macro_caps(txt):
                    slots.append((txt, "GLOBAL", "in"))
                elif x.id in write_ids:
                    slots.append((txt, "FREE", "inout"))
                    free_writes.add(txt)
                else:
                    slots.append((txt, "FREE", "in"))
        for c in reversed(kids):
            stack.append(c)
    return slots, free_writes


def param_fill(node):
    """Pre-order parameter-leaf texts under `node` — same order as template_slots,
    so column i aligns across all members of a clone class."""
    out = []
    stack = [node]
    while stack:
        x = stack.pop()
        if x.type == "comment":
            continue
        kids = iter_children(x)
        if not kids and x.type in PARAM_LEAVES:
            out.append(node_text(x))
        for c in reversed(kids):
            stack.append(c)
    return out


def template_has_escape(node):
    stack = [node]
    while stack:
        x = stack.pop()
        if x.type in CONTROL_ESCAPE:
            return True
        stack.extend(iter_children(x))
    return False


# --------------------------------------------------------------------------
# Parameter assembly (free vars UNION varying literals/macros/callees)
# --------------------------------------------------------------------------

KIND_LABEL = {"LIT": "lit", "GLOBAL": "macro", "CALLEE": "fn-ptr"}


def assemble_params(matrix, slots, free_writes):
    ncols = len(slots)
    colvals = [[row[c] for row in matrix] for c in range(ncols)]
    varies = [len(set(col)) > 1 for col in colvals]

    params = []   # (label, direction, examples)
    notes = []

    # FREE variables: always parameters, grouped by name (same var = one param).
    free_index = {}
    for c in range(ncols):
        txt, kind, _ = slots[c]
        if kind == "FREE":
            if txt not in free_index:
                direction = "in/out" if txt in free_writes else "in"
                free_index[txt] = len(params)
                params.append(("var", direction, distinct(colvals[c])))
        elif kind == "FIELD" and varies[c]:
            note = "accesses differing members: {" + ", ".join(distinct(colvals[c])) + "}"
            if note not in notes:
                notes.append(note)

    # Varying literal / macro / callee slots: parameters too. Merge columns that
    # co-vary identically across instances (a consistent rename) into one.
    nf_cols = [c for c in range(ncols)
               if slots[c][1] in ("LIT", "GLOBAL", "CALLEE") and varies[c]]
    parent = {c: c for c in nf_cols}

    def find(c):
        while parent[c] != c:
            parent[c] = parent[parent[c]]
            c = parent[c]
        return c

    for i in range(len(nf_cols)):
        for j in range(i + 1, len(nf_cols)):
            a, b = nf_cols[i], nf_cols[j]
            if colvals[a] == colvals[b]:
                parent[find(a)] = find(b)

    groups = {}
    for c in nf_cols:
        groups.setdefault(find(c), c)
    for rep in groups.values():
        label = KIND_LABEL[slots[rep][1]]
        params.append((label, "in", distinct(colvals[rep])))

    return params, notes


# --------------------------------------------------------------------------
# Clone class assembly + ranking
# --------------------------------------------------------------------------

def contained(inner, outer):
    """span tuple = (file_idx, start_byte, end_byte). True if inner is within
    outer (equal bounds allowed — a node and its near-coextensive child share a
    span; suppression's size ordering decides which one survives)."""
    return (
        inner[0] == outer[0]
        and outer[1] <= inner[1]
        and inner[2] <= outer[2]
    )


def build_class(recs, globals_):
    recs.sort(key=lambda r: (r[FILE], r[SB]))
    matrix = [param_fill(r[NODE]) for r in recs]
    if len({len(m) for m in matrix}) != 1:
        return None  # structure/parse mismatch — cannot align slots safely

    template = recs[0]
    local_names, callee_ids, write_ids = scope_sets(template[NODE])
    slots, free_writes = template_slots(
        template[NODE], globals_, local_names, callee_ids, write_ids)
    if len(slots) != len(matrix[0]):
        return None  # traversal divergence guard

    params, notes = assemble_params(matrix, slots, free_writes)
    inout = any(d == "in/out" for _, d, _ in params)
    escape = template_has_escape(template[NODE])

    lines = template[ER] - template[SR] + 1
    instances = len(recs)
    saved = (instances - 1) * lines - instances
    return {
        "saved": saved,
        "instances": instances,
        "lines": lines,
        "size": template[SIZE],
        "params": params,
        "notes": notes,
        "escape": escape,
        "inout": inout,
        "hard": escape or inout or bool(notes),
        "spans": [(r[FILE], r[SB], r[EB]) for r in recs],
        "locs": [(r[FILE], r[SR], r[ER]) for r in recs],
        "template": template,
    }


def suppress_nested(classes):
    kept = []
    accepted = []  # (count, size, spans)
    for c in classes:
        subsumed = False
        for acount, asize, aspans in accepted:
            if acount < c["instances"] or asize <= c["size"]:
                continue
            if all(any(contained(s, a) for a in aspans) for s in c["spans"]):
                subsumed = True
                break
        if subsumed:
            continue
        kept.append(c)
        accepted.append((c["instances"], c["size"], c["spans"]))
    return kept


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def hard_tag(c):
    reasons = []
    if c["escape"]:
        reasons.append("non-local control flow")
    if c["inout"]:
        reasons.append("in/out param (by-ref)")
    if c["notes"]:
        reasons.append("divergent member access")
    return "   [HARD: " + "; ".join(reasons) + "]" if reasons else ""


def emit_report(classes, paths, sources, args):
    print(f"# clone classes (>= {args.min_instances} instances, "
          f">= {args.min_saved} est. lines saved)\n")
    if not classes:
        print("none found at current thresholds.")
        return
    for rank, c in enumerate(classes, 1):
        print(f"## #{rank}  est. saved ~{c['saved']} lines"
              f"   ({c['instances']}x, {c['lines']} lines each, "
              f"{c['size']} nodes, {len(c['params'])} params){hard_tag(c)}")
        for (fi, sr, er) in c["locs"]:
            print(f"    {paths[fi]}:{sr + 1}-{er + 1}")
        if c["params"]:
            print(f"    parameters ({len(c['params'])}):")
            for k, (label, direction, ex) in enumerate(c["params"], 1):
                print(f"      p{k} [{direction}] {label}: {{{', '.join(ex)}}}")
        for n in c["notes"]:
            print(f"    note: {n}")
        template = c["template"]
        src = sources[template[FILE]]
        body = src[template[SB]:template[EB]].decode("utf-8", "replace").splitlines()
        print("    first instance:")
        for ln in body[:6]:
            print("      " + ln)
        if len(body) > 6:
            print("      ...")
        print()


def emit_json(classes, paths):
    out = []
    for c in classes:
        out.append({
            "est_lines_saved": c["saved"],
            "instances": c["instances"],
            "lines_each": c["lines"],
            "nodes": c["size"],
            "hard_extract": c["hard"],
            "params": [
                {"label": label, "direction": direction, "examples": ex}
                for (label, direction, ex) in c["params"]
            ],
            "notes": c["notes"],
            "locations": [
                {"file": paths[fi], "start_line": sr + 1, "end_line": er + 1}
                for (fi, sr, er) in c["locs"]
            ],
        })
    json.dump(out, sys.stdout, indent=2)
    print()


def main():
    ap = argparse.ArgumentParser(description="AST clone detector for C")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--min-nodes", type=int, default=40)
    ap.add_argument("--min-instances", type=int, default=2)
    ap.add_argument("--min-lines", type=int, default=3)
    ap.add_argument("--min-saved", type=int, default=8)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--normalize-types", action="store_true")
    ap.add_argument("--no-suppress", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    parser = Parser(Language(tree_sitter_c.language()))

    table = {}
    paths = []
    sources = []
    globals_ = set()
    candidates_by_hash = {}
    for file_idx, path in enumerate(args.files):
        with open(path, "rb") as f:
            src = f.read()
        paths.append(path)
        sources.append(src)
        tree = parser.parse(src)
        collect_globals(tree.root_node, globals_)
        compute_subtree_table(tree.root_node, file_idx, args.normalize_types, table)

    for rec in table.values():
        if rec[SIZE] < args.min_nodes or (rec[ER] - rec[SR] + 1) < args.min_lines:
            continue
        candidates_by_hash.setdefault(rec[DIGEST], []).append(rec)

    classes = []
    for recs in candidates_by_hash.values():
        if len(recs) < args.min_instances:
            continue
        c = build_class(recs, globals_)
        if c and c["saved"] >= args.min_saved:
            classes.append(c)

    # Clean (code-motion) clones first; harder-to-lift ones sort after. Larger
    # node count breaks ties so the maximal class is accepted before its
    # near-coextensive children and suppresses them.
    classes.sort(key=lambda c: (c["hard"], -c["saved"], -c["size"], -c["instances"]))
    if not args.no_suppress:
        classes = suppress_nested(classes)
    classes = classes[: args.top]

    if args.json:
        emit_json(classes, paths)
    else:
        emit_report(classes, paths, sources, args)


if __name__ == "__main__":
    main()
