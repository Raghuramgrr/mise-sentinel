local file = require("file")

local HOOK_HEADER   = "#!/bin/sh"
local HOOK_SENTINEL = "# sentinel"
local HOOK_PATH     = ".git/hooks/pre-commit"

local function find_git_root()
  local handle = io.popen("git rev-parse --show-toplevel 2>/dev/null")
  if not handle then return nil end
  local root = handle:read("*l")
  handle:close()
  return root
end

local function file_exists(path)
  local f = io.open(path, "r")
  if f then f:close() return true end
  return false
end

function PLUGIN:BackendInstall(ctx)
  local install_path = ctx.install_path
  os.execute("mkdir -p " .. install_path)

  -- Copy scan.lua from plugin source into the versioned install directory.
  -- PLUGIN.path is the directory where this plugin's source lives.
  local src = file.join_path(PLUGIN.path, "scan.lua")
  local dst = file.join_path(install_path, "scan.lua")
  os.execute("cp " .. src .. " " .. dst)

  -- Wire up the git pre-commit hook in the user's current repo.
  local git_root = find_git_root()
  if not git_root then
    error("sentinel: not inside a git repository — cannot install pre-commit hook")
  end

  local hook_file = git_root .. "/" .. HOOK_PATH
  local call_line = "lua " .. dst

  if file_exists(hook_file) then
    -- Avoid double-installing: skip if the hook already calls this scanner.
    local f = io.open(hook_file, "r")
    local existing = f:read("*all")
    f:close()
    if existing:find(dst, 1, true) then
      return {}  -- already installed
    end
    -- Append to existing hook (chain-safe).
    local out = io.open(hook_file, "a")
    if out then
      out:write("\n" .. HOOK_SENTINEL .. "\n" .. call_line .. "\n")
      out:close()
    end
  else
    -- Create a fresh hook.
    os.execute("mkdir -p " .. git_root .. "/.git/hooks")
    local out = io.open(hook_file, "w")
    if out then
      out:write(HOOK_HEADER .. "\n" .. HOOK_SENTINEL .. "\n" .. call_line .. "\n")
      out:close()
      os.execute("chmod +x " .. hook_file)
    end
  end

  return {}
end
