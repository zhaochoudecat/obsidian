---
name: add-frontmatter
description: When creating a new markdown file in this Obsidian vault, automatically prepend Hexo-compatible YAML frontmatter with title, date, and categories. Use this whenever the user creates a new .md document.
type: skill
model: haiku
---

# Auto Frontmatter Skill

When creating any new `.md` file in this Obsidian vault (which doubles as a Hexo blog `source/_posts/`), always add YAML frontmatter at the top.

## Rules

1. **Check first**: If the file already starts with `---`, skip — it has frontmatter.

2. **Title**: Use the content of the first `# ` heading. If not yet written, derive from the filename (without `.md`, replace hyphens/underscores with spaces).

3. **Date**: Use today's date in `YYYY-MM-DD` format.

4. **Categories**: Derive from the directory path relative to vault root:
   - `BUUCTF/WEB/new-file.md` → categories: `BUUCTF`, `WEB`
   - `靶机/QQGroup/new-file.md` → categories: `靶机`, `QQGroup`
   - `靶机/vulnhub/new-file.md` → categories: `靶机`, `vulnhub`
   - Root-level files get no categories.

5. **Image references**: All local images must use `assets/filename.png` (vault-root relative). Never use `images/` or per-post asset folders.

## Template

```yaml
---
title: "文档标题"
date: YYYY-MM-DD
categories:
 - 父目录
 - 子目录
---
```

## Example

For a new file `BUUCTF/WEB/sqli-writeup.md` with heading `# SQL注入实战`:

```yaml
---
title: "SQL注入实战"
date: 2026-05-03
categories:
 - BUUCTF
 - WEB
---

# SQL注入实战
```

Always insert the frontmatter block before any existing content.
