# Hasmika Kesineni — Portfolio Website

A personal portfolio website for Hasmika Kesineni, BS/MS Computer Science student at Georgia State University. Built with security, performance, and monitoring best practices applied throughout.

**Live Site:** https://hasmika123.github.io/portfolio/

---

## Features

- **HTTPS** — Automatic TLS/SSL via GitHub Pages
- **XSS Prevention** — All contact form inputs sanitized with DOMPurify before database writes
- **Contact Form + Database** — Submissions stored in Supabase (PostgreSQL) in real time
- **CDN Delivery** — Third-party libraries served via Cloudflare CDN and jsDelivr
- **Lazy Image Loading** — IntersectionObserver defers off-screen image loading
- **Minified Assets** — All external JS loaded in minified form
- **IPv6 Support** — GitHub Pages natively supports IPv4 and IPv6
- **CI/CD Pipeline** — GitHub Actions auto-validates and deploys on every push to `main`
- **Traffic Monitoring** — Google Analytics (GA4) tracks page views, sessions, and visitor location
- **AI Intrusion Detection** — Custom Python script analyzes form submissions for XSS, SQL injection, spam, and bot behavior using the Claude API

---

## Repository Structure

```
portfolio/
├── index.html              # Main site (HTML, CSS, JS all-in-one)
├── intrusion_detect.py     # AI-based security analysis script
├── schema.sql              # Supabase database schema
├── .gitignore
└── .github/
    └── workflows/
        └── deploy.yml      # GitHub Actions CI/CD pipeline
```

---

## Database Setup (Supabase)

1. Create a free project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** and run the contents of `schema.sql` to create the `contact_messages` table
3. Go to **Project Settings → API** and copy your:
   - Project URL
   - `anon` public key

> **Note:** Row Level Security (RLS) is disabled on `contact_messages`. This is intentional — the table only accepts non-sensitive public contact form submissions. See `schema.sql` for instructions on re-enabling RLS with a policy if needed.

---

## Environment Variables

Create a `.env` file in the project root (never commit this — it is in `.gitignore`):

```
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-anon-public-key
ANTHROPIC_API_KEY=your-anthropic-api-key
```

> **Important:** Use a plain text editor or `echo` to create this file. Do **not** use PowerShell's `Out-File` with UTF-8 encoding — it adds a hidden Byte Order Mark (BOM) that breaks `python-dotenv`.

---

## Running the Site Locally

The site is a single static HTML file with no build step required.

```bash
# Clone the repo
git clone https://github.com/hasmika123/portfolio.git
cd portfolio

# Open directly in your browser
open index.html
```

Or serve it with any static file server:

```bash
# Using Python
python -m http.server 8000
# Then visit http://localhost:8000
```

---

## Deployment (GitHub Pages)

Deployment is fully automated via GitHub Actions. Every push to `main`:

1. Runs a **validation job** that checks `index.html` for DOMPurify and HTTPS references
2. Runs a **deployment job** that publishes the site to GitHub Pages

No manual deployment steps are needed. The live site updates within ~30 seconds of a push.

To set up GitHub Pages on a fork:
1. Go to **Settings → Pages**
2. Set source to **GitHub Actions**

---

## Running the Intrusion Detection Script

The `intrusion_detect.py` script pulls the last 24 hours of contact form submissions from Supabase and sends them to the Claude API for security analysis.

```bash
# Install dependencies
pip install supabase anthropic python-dotenv

# Run the script
python intrusion_detect.py
```

The script outputs a formatted security report to the terminal and saves a `security_report.json` file. Each submission is analyzed for:
- SQL injection patterns
- XSS attempts
- Spam / phishing indicators
- Bot behavior

---

## Technologies Used

| Category | Technology |
|---|---|
| Hosting | GitHub Pages |
| Database | Supabase (PostgreSQL) |
| XSS Protection | DOMPurify (via Cloudflare CDN) |
| CDN | Cloudflare CDN, jsDelivr, Google Fonts |
| CI/CD | GitHub Actions |
| Analytics | Google Analytics GA4 |
| AI Security | Anthropic Claude API |
| Language | HTML, CSS, JavaScript, Python |
