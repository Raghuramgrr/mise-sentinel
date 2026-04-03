-- sentinel/scan.lua
-- Standalone git pre-commit secret scanner.
-- Invoked by .git/hooks/pre-commit after `mise install sentinel`.
-- Scans only the staged diff (added lines) — not the full file history.

-- ─── Configuration ───────────────────────────────────────────────────────────

-- Add file paths (Lua patterns) to .sentinel-ignore to suppress false positives
local IGNORE_FILE = ".sentinel-ignore"

-- Skip these file types entirely (binaries, lock files, etc.)
local SKIP_EXTENSIONS = {
  "%.png$", "%.jpg$", "%.jpeg$", "%.gif$", "%.ico$", "%.svg$", "%.webp$",
  "%.pdf$", "%.zip$", "%.tar$", "%.gz$", "%.tgz$", "%.bz2$", "%.xz$",
  "%.exe$", "%.bin$", "%.so$", "%.dylib$", "%.dll$", "%.wasm$",
  "%.lock$", "%.sum$", "package%-lock%.json$", "yarn%.lock$", "Cargo%.lock$",
}

-- ─── Secret Rules ────────────────────────────────────────────────────────────
-- pattern: extended regex passed to grep -E
-- severity: CRITICAL | HIGH | MEDIUM

local RULES = {
  -- AWS
  { name = "AWS Access Key ID",
    pattern  = "AKIA[0-9A-Z]{16}",
    severity = "CRITICAL" },
  { name = "AWS Secret Access Key",
    pattern  = "[Aa][Ww][Ss][_-]?[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*['\"]?[A-Za-z0-9/+=]{40}",
    severity = "CRITICAL" },
  { name = "AWS Session Token",
    pattern  = "[Aa][Ww][Ss][_-]?[Ss][Ee][Ss][Ss][Ii][Oo][Nn][_-]?[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[A-Za-z0-9/+=]{100,}",
    severity = "CRITICAL" },

  -- GitHub
  { name = "GitHub PAT (classic)",
    pattern  = "ghp_[A-Za-z0-9]{36}",
    severity = "CRITICAL" },
  { name = "GitHub Fine-grained PAT",
    pattern  = "github_pat_[A-Za-z0-9_]{82}",
    severity = "CRITICAL" },
  { name = "GitHub OAuth Token",
    pattern  = "gho_[A-Za-z0-9]{36}",
    severity = "CRITICAL" },
  { name = "GitHub App / Actions Token",
    pattern  = "ghs_[A-Za-z0-9]{36}",
    severity = "HIGH" },
  { name = "GitHub Refresh Token",
    pattern  = "ghr_[A-Za-z0-9]{36}",
    severity = "HIGH" },

  -- GitLab
  { name = "GitLab PAT",
    pattern  = "glpat-[A-Za-z0-9_-]{20,}",
    severity = "CRITICAL" },
  { name = "GitLab CI/Deploy Token (codeak-)",
    pattern  = "codeak-[A-Za-z0-9_-]{10,}",
    severity = "CRITICAL" },

  -- Google / GCP
  { name = "Google API Key",
    pattern  = "AIza[0-9A-Za-z_-]{35}",
    severity = "HIGH" },
  { name = "Google OAuth Client Secret",
    pattern  = "GOCSPX-[A-Za-z0-9_-]{28}",
    severity = "CRITICAL" },

  -- Azure
  { name = "Azure Storage Account Key",
    pattern  = "AccountKey=[A-Za-z0-9+/=]{88}",
    severity = "CRITICAL" },

  -- Stripe
  { name = "Stripe Live Secret Key",
    pattern  = "sk_live_[0-9a-zA-Z]{24}",
    severity = "CRITICAL" },
  { name = "Stripe Test Secret Key",
    pattern  = "sk_test_[0-9a-zA-Z]{24}",
    severity = "MEDIUM" },

  -- Slack
  { name = "Slack Bot / User Token",
    pattern  = "xox[baprs]-[0-9A-Za-z]{10,48}",
    severity = "HIGH" },
  { name = "Slack Webhook URL",
    pattern  = "hooks\\.slack\\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+",
    severity = "HIGH" },

  -- SendGrid / Mailgun / Twilio
  { name = "SendGrid API Key",
    pattern  = "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
    severity = "HIGH" },
  { name = "Mailgun API Key",
    pattern  = "key-[0-9a-z]{32}",
    severity = "HIGH" },
  { name = "Twilio Account SID",
    pattern  = "AC[0-9a-f]{32}",
    severity = "HIGH" },

  -- Package registries
  { name = "NPM Automation Token",
    pattern  = "npm_[A-Za-z0-9]{36}",
    severity = "HIGH" },
  { name = "PyPI Upload Token",
    pattern  = "pypi-[A-Za-z0-9_-]{80}",
    severity = "HIGH" },
  { name = "Docker Hub PAT",
    pattern  = "dckr_pat_[A-Za-z0-9_-]{27}",
    severity = "HIGH" },

  -- Private keys / certificates
  { name = "PEM Private Key",
    pattern  = "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY( BLOCK)?-----",
    severity = "CRITICAL" },
  { name = "PGP Private Key Block",
    pattern  = "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    severity = "CRITICAL" },

  -- JWTs
  { name = "JWT Token",
    pattern  = "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
    severity = "MEDIUM" },

  -- Generic high-signal assignments — quoted or unquoted, = or : (lower specificity, placed last)
  { name = "PASSWORD assignment",
    pattern  = "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][[:space:]]*[:=][[:space:]]*['\"]?[^'\"[:space:]#]{8,}",
    severity = "HIGH" },
  { name = "TOKEN assignment",
    pattern  = "[Tt][Oo][Kk][Ee][Nn][[:space:]]*[:=][[:space:]]*['\"]?[^'\"[:space:]#]{8,}",
    severity = "HIGH" },
  { name = "SECRET assignment",
    pattern  = "[Ss][Ee][Cc][Rr][Ee][Tt][[:space:]]*[:=][[:space:]]*['\"]?[^'\"[:space:]#]{8,}",
    severity = "HIGH" },
  { name = "API key assignment",
    pattern  = "[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*['\"]?[^'\"[:space:]#]{16,}",
    severity = "MEDIUM" },
}

-- ─── Helpers ─────────────────────────────────────────────────────────────────

local function exec(command)
  local handle = io.popen(command .. " 2>/dev/null")
  if not handle then return "" end
  local out = handle:read("*all")
  handle:close()
  return out or ""
end

local function read_lines(path)
  local lines = {}
  local f = io.open(path, "r")
  if not f then return lines end
  for line in f:lines() do
    line = line:match("^%s*(.-)%s*$")
    if line ~= "" and not line:match("^#") then
      table.insert(lines, line)
    end
  end
  f:close()
  return lines
end

local function matches_any(str, patterns)
  for _, pat in ipairs(patterns) do
    if str:match(pat) then return true end
  end
  return false
end

local function escape_for_shell(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

-- Parse unified diff and return added lines with their destination line numbers.
local function added_lines(diff_text)
  local result = {}
  local line_num = 0
  for line in diff_text:gmatch("[^\n]+") do
    local dest = line:match("^@@ %-%d+[,%d]* %+(%d+)")
    if dest then
      line_num = tonumber(dest) - 1
    elseif line:match("^%+%+%+") then
      -- skip +++ header
    elseif line:match("^%+") then
      line_num = line_num + 1
      table.insert(result, { num = line_num, content = line:sub(2) })
    elseif not line:match("^%-") then
      line_num = line_num + 1
    end
  end
  return result
end

-- ─── Scan ────────────────────────────────────────────────────────────────────

local function scan_line(content, file, num, findings)
  for _, rule in ipairs(RULES) do
    local grep = "echo " .. escape_for_shell(content)
        .. " | grep -qE " .. escape_for_shell(rule.pattern)
    if os.execute(grep) == 0 then
      table.insert(findings, {
        file     = file,
        line     = num,
        rule     = rule.name,
        severity = rule.severity,
        snippet  = content:match("^%s*(.-)%s*$"):sub(1, 120),
      })
      return  -- one finding per line is enough
    end
  end
end

-- ─── Entry point ─────────────────────────────────────────────────────────────

local function main()
  local ignore = read_lines(IGNORE_FILE)

  local staged_raw = exec("git diff --cached --name-only --diff-filter=ACMR")
  local findings   = {}

  for path in staged_raw:gmatch("[^\n]+") do
    if path ~= ""
      and not matches_any(path, SKIP_EXTENSIONS)
      and not matches_any(path, ignore)
    then
      local diff  = exec("git diff --cached -U0 -- " .. escape_for_shell(path))
      local lines = added_lines(diff)
      for _, entry in ipairs(lines) do
        scan_line(entry.content, path, entry.num, findings)
      end
    end
  end

  if #findings == 0 then
    os.exit(0)
  end

  -- ─── Report ────────────────────────────────────────────────────────────────

  io.stderr:write("\n")
  io.stderr:write("+-----------------------------------------------------------------+\n")
  io.stderr:write("|  sentinel: potential secrets detected in staged changes         |\n")
  io.stderr:write("+-----------------------------------------------------------------+\n")
  io.stderr:write("\n")

  local icons = { CRITICAL = "[CRITICAL]", HIGH = "[HIGH]    ", MEDIUM = "[MEDIUM]  " }

  for _, f in ipairs(findings) do
    io.stderr:write(string.format(
      "  %s  %s:%d\n  rule   : %s\n  snippet: %s\n\n",
      icons[f.severity] or "[UNKNOWN] ",
      f.file, f.line, f.rule, f.snippet
    ))
  end

  io.stderr:write("Commit blocked. Options:\n")
  io.stderr:write("  1. Remove the secret and use an environment variable instead.\n")
  io.stderr:write("  2. Add a path pattern to .sentinel-ignore for intentional false positives.\n")
  io.stderr:write("  3. Set SENTINEL_SKIP=1 to bypass (emergency use only).\n\n")

  if os.getenv("SENTINEL_SKIP") == "1" then
    io.stderr:write("SENTINEL_SKIP=1 set — bypassing sentinel (use with caution).\n\n")
    os.exit(0)
  end

  os.exit(1)
end

main()
