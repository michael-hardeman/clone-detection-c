# clonedet — AST clone detector for C

Finds duplicated code that could be lifted into a shared subprogram. Unlike a
token/line matcher (`pmd cpd`), it works on the tree-sitter AST and ranks by
*extractability*, not raw similarity: it computes the inferred parameter list for
each clone class via anti-unification and demotes clones whose extraction is
blocked by non-local control flow.

See `docs/code-quality.md` for the design rationale.

## Setup

The bundled venv is git-ignored. Recreate it:

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run

```
clonedet path/to/your/source.c        # ranked human report
clonedet --json path/to/your/source.c # machine-readable
clonedet a.c b.c c.c                  # cross-file clones too
```

Common knobs:

| flag | default | meaning |
|------|---------|---------|
| `--min-nodes N` | 40 | minimum subtree size (AST nodes) to be a candidate |
| `--min-instances N` | 2 | minimum members for a clone class |
| `--min-lines N` | 3 | minimum line span of the template |
| `--min-saved N` | 8 | only report classes with this many est. lines saved |
| `--top N` | 40 | cap the number of classes shown |
| `--normalize-types` | off | also collapse type names (find type-parameterizable clones) |
| `--no-suppress` | off | keep clone classes nested inside larger ones |

Raise `--min-nodes` (e.g. 80) for fewer, larger, higher-confidence candidates;
lower it to surface small repeated idioms.

## How it works

1. **Parse** each file with tree-sitter-c (error-tolerant — GNU extensions and
   `__int128` parse fine; partial errors don't stop analysis).
2. **Normalized Merkle hash** of every subtree, bottom-up. Parameter-like leaves
   (identifiers, literals) collapse to a class token, so two subtrees that differ
   only in variable names or constants hash equal (Type-1/Type-2 clones).
   Operators, keywords, and **type names are kept verbatim** — `<` vs `<=` and
   `i32` vs `i64` are real differences and are never merged.
3. **Bucket** by hash. A bucket with `>= --min-instances` members is a clone class.
4. **Free-variable + anti-unification.** A lexical scope pass over the candidate
   classifies every leaf: LOCAL (declared inside), GLOBAL / macro / callee (from
   the translation-unit symbol table collected at parse time), or a FREE variable
   read or written from outside. The reported parameter list is then:
   * every FREE variable — an external input the helper must receive; marked
     `in/out` (by-reference) when it is also written inside the candidate, and
   * every literal / macro / callee slot whose value **varies** across the clone
     instances, with consistent renames merged to one parameter.
   Internal renaming of locals no longer inflates the count. Each parameter is
   shown with its direction, kind, and example values.
5. **Rank** by estimated lines saved `= (instances-1)*lines - instances`. A class
   is flagged `HARD` and sorted after clean code-motion clones when it has
   non-local control flow (`return`/`goto`/`break`/`continue`), an in/out
   parameter, or divergent struct-member access across instances.
6. **Suppress** non-maximal classes — a sub-clone contained inside an
   already-reported larger clone (the larger node count wins ties) is dropped
   (use `--no-suppress` to see them).

## Limits

- **Parse coverage.** tree-sitter-c is error-tolerant but not a full GNU C front
  end; `ada83.c` produces ~4200 ERROR nodes (macros, `__int128`, inline asm,
  unusual constructs). Structural hashing degrades gracefully — errors are local
  — but inside an error region the scope pass can misread a construct, e.g. tag a
  callee as a free variable when error-recovery splits the call node. Treat a
  lone non-varying `var` parameter that is obviously a function name as such.
- **Scope analysis is lexical, not type-aware.** A name is FREE if it is not
  declared inside the candidate and not in the collected global/macro/enum table.
  It does not do use-before-declaration ordering or block-shadowing, and cannot
  distinguish a by-value from a by-reference input — `in/out` is inferred purely
  from whether the variable is assigned inside the candidate. The parameter list
  is an accurate worklist, not a compilable signature.
- **Structural, not semantic.** Commutative reorderings (`a+b` vs `b+a`) and
  statement reorderings are different trees and won't match (Type-3+).
- **Heuristic suppression.** Containment + multiplicity, not a true maximal-clone
  algorithm; `--no-suppress` shows everything.
- The `HARD` flag is a presence check, not a dataflow proof — a `break` inside a
  fully-contained loop is actually fine to extract.
