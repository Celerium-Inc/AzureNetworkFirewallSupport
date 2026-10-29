# Azure Functions PowerShell worker runs this file on every cold start.
# The platform template calls Disable-AzContextAutosave / Connect-AzAccount -Identity.
# This app does not install Az modules (managedDependency is disabled). Keep this file
# as a no-op so it replaces that template.
