#!/usr/bin/env python3
"""lq.py — Learnings query and management tool (SQLite + FTS5)

Usage:
  lq.py <query> [-d web,network] [-n 10]        search (OR between terms by default)
  lq.py <query> [-d web] --and                   search (AND between terms)
  lq.py --add -d web -t "#JWT #SSRF" -b "..."   add entry (dedup check runs first)
  lq.py --update <id> -b "..."                   update entry body by id
  lq.py --migrate                                import all .md files into DB (one-time)
"""

import argparse
import sqlite3
import sys
import os
import re
from datetime import date

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(ROOT, "learnings", "learnings.db")
LEARNINGS_DIR = os.path.join(ROOT, "learnings")
DOMAINS = ["web", "network", "cloud", "ctf", "bounty", "general"]
MD_FILES = {d: os.path.join(LEARNINGS_DIR, f"{d}.md") for d in DOMAINS}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS learnings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            tags        TEXT NOT NULL DEFAULT '',
            body        TEXT NOT NULL,
            entry_date  TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS learnings_fts USING fts5(
            domain,
            tags,
            body,
            content=learnings,
            content_rowid=id
        );

        CREATE TRIGGER IF NOT EXISTS learnings_ai AFTER INSERT ON learnings BEGIN
            INSERT INTO learnings_fts(rowid, domain, tags, body)
            VALUES (new.id, new.domain, new.tags, new.body);
        END;

        CREATE TRIGGER IF NOT EXISTS learnings_ad AFTER DELETE ON learnings BEGIN
            INSERT INTO learnings_fts(learnings_fts, rowid, domain, tags, body)
            VALUES ('delete', old.id, old.domain, old.tags, old.body);
        END;

        CREATE TRIGGER IF NOT EXISTS learnings_au AFTER UPDATE ON learnings BEGIN
            INSERT INTO learnings_fts(learnings_fts, rowid, domain, tags, body)
            VALUES ('delete', old.id, old.domain, old.tags, old.body);
            INSERT INTO learnings_fts(rowid, domain, tags, body)
            VALUES (new.id, new.domain, new.tags, new.body);
        END;
    """)
    conn.commit()


def build_fts_query(raw_query, and_mode=False):
    """Build FTS5 query string. Default: OR between space-separated terms."""
    terms = raw_query.strip().split()
    if not terms:
        return raw_query
    if len(terms) == 1:
        return terms[0]
    operator = " AND " if and_mode else " OR "
    return operator.join(terms)


def search(conn, query, domains=None, limit=10, and_mode=False):
    fts_query = build_fts_query(query, and_mode)
    if domains:
        placeholders = ",".join("?" * len(domains))
        sql = f"""
            SELECT l.id, l.domain, l.tags, l.body, l.entry_date,
                   bm25(learnings_fts) AS rank
            FROM learnings_fts f
            JOIN learnings l ON f.rowid = l.id
            WHERE learnings_fts MATCH ?
              AND l.domain IN ({placeholders})
            ORDER BY rank
            LIMIT ?
        """
        return conn.execute(sql, [fts_query] + list(domains) + [limit]).fetchall()
    else:
        sql = """
            SELECT l.id, l.domain, l.tags, l.body, l.entry_date,
                   bm25(learnings_fts) AS rank
            FROM learnings_fts f
            JOIN learnings l ON f.rowid = l.id
            WHERE learnings_fts MATCH ?
            ORDER BY rank
            LIMIT ?
        """
        return conn.execute(sql, [fts_query, limit]).fetchall()


def add_entry(conn, domain, tags, body, entry_date=None):
    if not entry_date:
        entry_date = date.today().isoformat()

    # Dedup check: search for significant terms from body
    sig_terms = [w for w in body.split() if len(w) > 5 and not w.startswith('#')][:4]
    if sig_terms:
        try:
            existing = search(conn, " ".join(sig_terms[:2]), domains=[domain], limit=3)
            if existing:
                print(f"[DEDUP WARNING] {len(existing)} similar entr{'y' if len(existing)==1 else 'ies'} found in {domain}:", file=sys.stderr)
                for row in existing:
                    snippet = row['body'][:100].replace('\n', ' ')
                    print(f"  id={row['id']}  {row['tags']}  {snippet}...", file=sys.stderr)
                print("[DEDUP] Use --update <id> -b '<new body>' to update in place.", file=sys.stderr)
                print("[DEDUP] Proceeding with add — confirm this is a distinct entry.", file=sys.stderr)
        except Exception:
            pass  # FTS error doesn't block add

    cursor = conn.execute(
        "INSERT INTO learnings (domain, tags, body, entry_date) VALUES (?, ?, ?, ?)",
        (domain, tags, body, entry_date)
    )
    conn.commit()
    new_id = cursor.lastrowid

    # Also append to the markdown file for human readability
    md_path = MD_FILES.get(domain)
    if md_path and os.path.exists(md_path):
        line = f"{tags} [{entry_date}] {body}\n"
        with open(md_path, 'a') as f:
            f.write(line)

    print(f"[ADDED] id={new_id} domain={domain}")
    return new_id


def update_entry(conn, entry_id, body):
    rows = conn.execute("SELECT id FROM learnings WHERE id=?", (entry_id,)).fetchall()
    if not rows:
        print(f"[ERROR] No entry with id={entry_id}", file=sys.stderr)
        sys.exit(1)
    conn.execute(
        "UPDATE learnings SET body=?, updated_at=datetime('now') WHERE id=?",
        (body, entry_id)
    )
    conn.commit()
    print(f"[UPDATED] id={entry_id}")


def parse_single_line(line):
    """Parse: #Tag1 #Tag2 [YYYY-MM-DD] body text"""
    line = line.strip()
    if not line:
        return None
    m = re.match(r'^((?:#\S+\s*)+)\[(\d{4}-\d{2}-\d{2})\]\s+(.+)$', line)
    if m:
        return m.group(1).strip(), m.group(2), m.group(3).strip()
    return None


def parse_section_block(lines, start_idx):
    """Parse multi-line ## section blocks (e.g. ctf.md technique entries)."""
    title = lines[start_idx].strip().lstrip('#').strip()
    tags = ""
    body_parts = [title]
    i = start_idx + 1
    while i < len(lines):
        l = lines[i].rstrip()
        if re.match(r'^#{1,3} ', l) and i > start_idx:
            break
        if l.startswith('- **Tags:**'):
            tags = l.replace('- **Tags:**', '').strip()
        elif re.match(r'^- \*\*\w', l):
            field = re.sub(r'^- \*\*[^*]+\*\*:?\s*', '', l).strip()
            if field:
                body_parts.append(field)
        elif l.strip() and not l.startswith('#'):
            body_parts.append(l.strip())
        i += 1
    body = " | ".join(p for p in body_parts if p)
    return tags, date.today().isoformat(), body, i


def migrate(conn):
    """Import all existing markdown learnings files into the DB."""
    total = 0
    for domain, filepath in MD_FILES.items():
        if not os.path.exists(filepath):
            print(f"[MIGRATE] {domain}: file not found, skipping")
            continue
        with open(filepath, 'r') as f:
            lines = f.readlines()

        count = 0
        i = 0
        while i < len(lines):
            line = lines[i]

            # Skip file header comments (first 5 lines starting with #)
            if i < 5 and line.startswith('# '):
                i += 1
                continue

            # Multi-line ## section block
            if re.match(r'^#{2,3} ', line.strip()):
                tags, entry_date, body, next_i = parse_section_block(lines, i)
                if body and len(body) > 10:
                    conn.execute(
                        "INSERT INTO learnings (domain, tags, body, entry_date) VALUES (?, ?, ?, ?)",
                        (domain, tags, body, entry_date)
                    )
                    count += 1
                i = next_i
                continue

            # Single-line entry
            result = parse_single_line(line)
            if result:
                tags, entry_date, body = result
                conn.execute(
                    "INSERT INTO learnings (domain, tags, body, entry_date) VALUES (?, ?, ?, ?)",
                    (domain, tags, body, entry_date)
                )
                count += 1

            i += 1

        conn.commit()
        print(f"[MIGRATE] {domain}: {count} entries imported")
        total += count

    # Rebuild FTS index after bulk insert
    conn.execute("INSERT INTO learnings_fts(learnings_fts) VALUES('rebuild')")
    conn.commit()
    print(f"[MIGRATE] Total: {total} entries. FTS index rebuilt.")


def format_row(row):
    date_part = f"[{row['entry_date']}] " if row['entry_date'] else ''
    tags_part = f"{row['tags']} " if row['tags'] else ''
    return f"[id={row['id']}][{row['domain']}] {tags_part}{date_part}{row['body']}"


def main():
    parser = argparse.ArgumentParser(
        description="Learnings query tool (SQLite + FTS5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('query', nargs='?', help='Search query (space = OR by default)')
    parser.add_argument('-d', '--domain', help='Filter by domain(s): web,network,cloud,ctf,bounty,general')
    parser.add_argument('-n', '--limit', type=int, default=10, help='Max results (default: 10)')
    parser.add_argument('--and', dest='and_mode', action='store_true', help='AND between terms (default is OR)')
    parser.add_argument('--add', action='store_true', help='Add a new entry')
    parser.add_argument('--update', type=int, metavar='ID', help='Update entry body by id')
    parser.add_argument('-t', '--tags', default='', help='Tags string e.g. "#JWT #SSRF"')
    parser.add_argument('-b', '--body', help='Entry body text')
    parser.add_argument('--date', help='Entry date (YYYY-MM-DD), default: today')
    parser.add_argument('--migrate', action='store_true', help='Import existing .md files into DB (one-time)')

    args = parser.parse_args()
    conn = get_conn()
    init_db(conn)

    if args.migrate:
        migrate(conn)
        return

    if args.add:
        if not args.domain or not args.body:
            print("--add requires -d <domain> and -b <body>", file=sys.stderr)
            sys.exit(1)
        domain = args.domain.split(',')[0].strip()
        if domain not in DOMAINS:
            print(f"[ERROR] Unknown domain '{domain}'. Valid: {', '.join(DOMAINS)}", file=sys.stderr)
            sys.exit(1)
        add_entry(conn, domain, args.tags, args.body, args.date)
        return

    if args.update is not None:
        if not args.body:
            print("--update requires -b <new body>", file=sys.stderr)
            sys.exit(1)
        update_entry(conn, args.update, args.body)
        return

    if not args.query:
        parser.print_help()
        sys.exit(1)

    domains = [d.strip() for d in args.domain.split(',')] if args.domain else None
    try:
        rows = search(conn, args.query, domains=domains, limit=args.limit, and_mode=args.and_mode)
    except sqlite3.OperationalError as e:
        print(f"[ERROR] FTS query failed: {e}", file=sys.stderr)
        print("[HINT] Avoid special characters. Wrap exact phrases in double quotes.", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print(f"[NO RESULTS] '{args.query}'" + (f" in {args.domain}" if args.domain else ""))
        return

    for row in rows:
        print(format_row(row))


if __name__ == '__main__':
    main()
