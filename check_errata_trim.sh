#!/bin/sh
# Copyright Free Mobile, 2026, Vincent Jardin
#
# Check what the protocol-gated errata actually changed.
#
# So build the tree three times:
#
#   reference the revision given on the command line
#   no-trim   RCW_ERRATA_NO_TRIM defined, every conditional block enabled.
#             This is what a board would emit if it declared no protocol
#             at all, and it is the build that must not lose anything.
#   trimmed   the normal build.
#
# then check
#
#   reference  <=  no-trim     nothing LOST
#   trimmed    <=  no-trim     nothing INVENTED
#   same loadacwindow for every awrite the trimmed build keeps (WINDOW)
#
# What the no-trim build gains over the reference (GAINED, DEDUPED) and what
# the trimmed build adds to a board (COMPLETED) is reported, not failed.
#
# usage: ./check_errata_trim.sh [reference-rev]     (default: origin/devel)

set -eu

REF=${1:-origin/devel}
TMP=$(mktemp -d)
trap 'git worktree remove --force "$TMP/ref" 2>/dev/null || true; rm -rf "$TMP"' EXIT

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
git rev-parse --verify -q "$REF^{commit}" >/dev/null ||
	{ echo "no such revision: $REF" >&2; exit 1; }

echo "reference : $REF ($(git rev-parse --short "$REF"))"
echo "under test: $(git rev-parse --short HEAD)"
echo

echo "building the reference..."
git worktree add -q --detach "$TMP/ref" "$REF"
make -s -C "$TMP/ref" RCW_CPPFLAGS=-DRCW_ERRATA_NO_TRIM >/dev/null

echo "building with the trimming off..."
make -s clean >/dev/null 2>&1 || true
make -s RCW_CPPFLAGS=-DRCW_ERRATA_NO_TRIM >/dev/null
find . -name '*.bin' -o -name '*.bin.swapped' | while read -r f; do
	mkdir -p "$TMP/notrim/$(dirname "$f")"
	cp "$f" "$TMP/notrim/$f"
done

echo "building normally..."
make -s clean >/dev/null 2>&1 || true
make -s >/dev/null
echo

REF_DIR=$TMP/ref NOTRIM_DIR=$TMP/notrim python3 - "$REF" <<'PY'
import os, subprocess, sys, collections, glob

ref_dir, notrim_dir = os.environ['REF_DIR'], os.environ['NOTRIM_DIR']
CMDS = ('write', 'awrite', 'blockcopy', 'loadacwindow', 'poll', 'wait')
FAIL = ('LOST', 'INVENTED', 'WINDOW', 'MISSING', 'CPP FAIL')

def commands(root, src, extra=()):
    """The PBI command stream of one source, as the preprocessor leaves it:
    a list of (window, command). The window is the loadacwindow in force,
    recorded for awrite only: that is the one command relative to it."""
    path = os.path.abspath(os.path.join(root, src))
    p = subprocess.run(['gcc', '-E', '-x', 'c', '-P', '-I', '..'] +
                       list(extra) + [path],
                       cwd=os.path.dirname(path), capture_output=True, text=True)
    if p.returncode:
        return None
    out, window = [], None
    for line in p.stdout.splitlines():
        t = ' '.join(line.split())
        op = t.split(' ')[0].split('.')[0] if t else ''
        if op == 'loadacwindow':
            window = t.split(' ', 1)[1]
        if op in CMDS:
            out.append((window if op == 'awrite' else None, t))
    return out

def texts(stream):
    return collections.Counter(t for _, t in stream)

def example(counter):
    k = next(iter(counter))
    return k if isinstance(k, str) else '%s under loadacwindow %s' % (k[1], k[0])

findings = []                       # (kind, board source, detail)
def note(kind, src, detail):
    findings.append((kind, src, detail))
    print('%-8s %s: %s' % (kind, src, detail))

counts = collections.Counter()
size_ref = size_new = 0
for ref_bin in sorted(glob.glob(ref_dir + '/*/*/*.bin*')):
    rel = os.path.relpath(ref_bin, ref_dir)
    src = rel.split('.bin')[0] + '.rcw'
    if not os.path.exists(src):
        counts['skipped'] += 1      # board added upstream after this branch point
        continue
    if not os.path.exists(os.path.join(notrim_dir, rel)):
        note('MISSING', src, 'not built by the no-trim build')
        counts['failed'] += 1
        continue

    ref_bytes = open(ref_bin, 'rb').read()
    size_ref += len(ref_bytes)
    size_new += os.path.getsize(rel)

    ref = commands(ref_dir, src, ['-DRCW_ERRATA_NO_TRIM'])  # reference, trimming off
    nt = commands('.', src, ['-DRCW_ERRATA_NO_TRIM'])       # trimming off
    tr = commands('.', src)                                 # normal build
    if ref is None or nt is None or tr is None:
        note('CPP FAIL', src, 'the preprocessor failed')
        counts['failed'] += 1
        continue

    # 1. reference <= no-trim
    missing = texts(ref) - texts(nt)
    extra = texts(nt) - texts(ref)
    # a command the reference issued more than once and the no-trim build
    # still issues, only fewer times, is a duplicate #include collapsing
    deduped = collections.Counter({k: v for k, v in missing.items()
                                   if texts(nt)[k]})
    missing -= deduped
    if deduped:
        note('DEDUPED', src, '%d command(s) the reference issued more than '
             'once are issued once, e.g. %s' % (sum(deduped.values()), example(deduped)))
        counts['deduped'] += 1
    if missing:
        note('LOST', src, '%d command(s) the reference had, e.g. %s'
             % (sum(missing.values()), example(missing)))
        counts['lost'] += 1
    elif open(os.path.join(notrim_dir, rel), 'rb').read() == ref_bytes:
        counts['identical'] += 1
    elif extra:
        note('GAINED', src, '%d command(s) not in the reference, e.g. %s'
             % (sum(extra.values()), example(extra)))
        counts['gained'] += 1
    else:
        counts['reordered'] += 1

    # 2. trimmed <= no-trim
    invented = texts(tr) - texts(nt)
    if invented:
        note('INVENTED', src, '%d command(s) the no-trim build never had, e.g. %s'
             % (sum(invented.values()), example(invented)))
        counts['invented'] += 1

    # 3. every awrite kept its loadacwindow
    moved = (collections.Counter(k for k in tr if k[0] is not None) -
             collections.Counter(k for k in nt if k[0] is not None))
    moved = collections.Counter({k: v for k, v in moved.items()
                                 if k[1] not in invented})
    if moved:
        note('WINDOW', src, '%d awrite(s) run under another loadacwindow than '
             'in the no-trim build, e.g. %s' % (sum(moved.values()), example(moved)))
        counts['window'] += 1

    # info: what the catalog added compared to the hand-written list
    added = texts(tr) - texts(ref)
    if added:
        note('COMPLETED', src, '%d command(s) the reference lacked, e.g. %s'
             % (sum(added.values()), example(added)))
        counts['completed'] += 1

ok = not (counts['lost'] or counts['invented'] or counts['window'] or counts['failed'])
size = ('%d -> %d bytes (%.1f%% smaller)'
        % (size_ref, size_new, 100.0 * (size_ref - size_new) / size_ref)) if size_ref else None

print()
print('no-trim build vs %s:' % sys.argv[1])
print('  byte-identical                     : %d' % counts['identical'])
print('  same commands, emitted in new order: %d' % counts['reordered'])
print('  gained a command                   : %d' % counts['gained'])
print('  LOST a command                     : %d' % counts['lost'])
print('trimmed build vs the no-trim build:')
print('  INVENTED a command                 : %d' % counts['invented'])
print('  awrite under another WINDOW        : %d' % counts['window'])
print('trimmed build vs %s:' % sys.argv[1])
print('  completed with a command           : %d' % counts['completed'])
if counts['skipped']:
    print('  only in the reference, skipped     : %d' % counts['skipped'])
if counts['failed']:
    print('  could not be compared              : %d' % counts['failed'])
if size:
    print()
    print('trimmed build: %s' % size)

summary = os.environ.get('GITHUB_STEP_SUMMARY')
if summary:
    def table(rows):
        yield '| kind | board | detail |'
        yield '|---|---|---|'
        for k, src, d in rows:
            yield '| %s | `%s` | %s |' % (k, src, d.replace('|', '\\|'))
        yield ''
    fails = [f for f in findings if f[0] in FAIL]
    changed = [f for f in findings if f[0] in ('COMPLETED', 'DEDUPED')]
    gained = [f for f in findings if f[0] == 'GAINED']
    md = ['## errata trim check: %s' % ('passed :white_check_mark:' if ok else 'FAILED :x:'), '',
          'reference `%s`, under test `%s`' % (sys.argv[1], os.environ.get('GITHUB_SHA', '')[:9]), '',
          '| assertion | violations |', '|---|---:|']
    for label, key in (('reference &sube; no-trim (nothing LOST)', 'lost'),
                       ('trimmed &sube; no-trim (nothing INVENTED)', 'invented'),
                       ('every kept awrite under its loadacwindow (WINDOW)', 'window'),
                       ('boards that could not be compared', 'failed')):
        md.append('| %s | %d %s |' % (label, counts[key], '' if counts[key] == 0 else ':x:'))
    md += ['', '| information | count |', '|---|---:|']
    for label, key in (('boards byte-identical to the reference', 'identical'),
                       ('same commands, emitted in new order', 'reordered'),
                       ('gained a command (no-trim vs reference)', 'gained'),
                       ('completed with a command (trimmed vs reference)', 'completed'),
                       ('deduplicated a repeated #include', 'deduped'),
                       ('only in the reference, skipped', 'skipped')):
        md.append('| %s | %d |' % (label, counts[key]))
    if size:
        md.append('| trimmed build | %s |' % size)
    md.append('')
    if fails:
        md += ['### Failures (%d)' % len(fails), ''] + list(table(fails))
    if changed:
        md += ['<details><summary>Boards whose PBI changed against the reference (%d)</summary>' % len(changed),
               ''] + list(table(changed)) + ['</details>', '']
    if gained:
        md += ['<details><summary>Boards the no-trim build completes (%d)</summary>' % len(gained),
               ''] + list(table(gained)) + ['</details>', '']
    with open(summary, 'a') as f:
        f.write('\n'.join(md) + '\n')

if os.environ.get('GITHUB_ACTIONS'):
    seen = collections.Counter()
    for k, src, d in findings:
        if k in FAIL: level = 'error'
        elif k in ('COMPLETED', 'DEDUPED'): level = 'notice'
        else: continue
        if seen[level] < 10:
            seen[level] += 1
            print('::%s file=%s,title=%s::%s' % (level, src, k, d))

sys.exit(0 if ok else 1)
PY
