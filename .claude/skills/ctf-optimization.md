---
name: ctf-optimization
description: 优化 CTF WP/笔记。手动调用，需用户输入 `/ctf-optimization <文件路径>` 或明确要求"优化笔记"。
type: skill
model: sonnet
---

# CTF 笔记优化

优化指定的 CTF Writeup 或笔记文件，不改动图片，仅优化文字内容。

## 规则

### 1. 图片原样保留

**禁止删除、移动或修改任何图片引用**，包括：
- `![](assets/...)` 
- `![[...]]`

原文件中的图片位置保持不动，只改文字。

### 2. 内容优化

- **结构调整**：检查标题层级是否合理（`#` → `##` → `###`），必要时重组章节顺序
- **用词准确**：纠正技术术语错误、口语化表达、模糊描述
- **精炼输出**：删除冗余的命令输出，保留关键信息
- **知识补充**：对涉及的关键工具（如 enum4linux、getcap、capabilities）或技术概念，可用 `>` 引用块简短注释，帮助理解原理

### 3. Frontmatter 属性

检查文件是否有 YAML frontmatter。如果没有，参照同目录其他笔记的格式添加：

```yaml
---
title: <笔记标题>
date: <YYYY-MM-DD>
categories:
  - <父目录>
  - <子目录>
tags:
---
```

- `title`：取第一个 `# ` 标题内容
- `date`：取当天日期，或从 nmap 输出等线索推断操作日期
- `categories`：从文件路径推导（如 `靶机/vulnhub/xxx.md` → `靶机`, `vulnhub`）

## 执行流程

1. 读取目标文件，同时查看同目录 1-2 个其他笔记作为风格参考
2. 检查 frontmatter，缺失则补上
3. 优化文字，保留所有图片引用
4. 写回文件
