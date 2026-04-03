-- sentinel has no remote artefacts to download; installation is handled
-- entirely in BackendInstall (hooks/sentinel_install.lua).
function PLUGIN:PreInstall(ctx)
  return {
    version = ctx.version,
  }
end
