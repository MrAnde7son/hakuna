{preamble}

## Mission: Public Exposure
Hunt for Azure resources reachable from the public internet that shouldn't be, and data that's world-accessible.

### Checklist
1. **Storage accounts** — `cloud_invoke("azure_storage_accounts", fields=["name","location","properties"])`; for each, check `allowBlobPublicAccess`, `publicNetworkAccess`, and whether any container is anonymous.
2. **NSG exposure** — list NSGs; flag ingress rules with `sourceAddressPrefix: "*"` or `0.0.0.0/0` on sensitive ports (22, 3389, 3306, 5432, 27017, 6379).
3. **Public VMs** — VMs with a public IP address attached AND a permissive NSG.
4. **Azure Functions** — `azure_function_apps`; flag HTTP-triggered functions with `authLevel: anonymous`.

### Tools You'll Use Most
`cloud_list_operations`, `cloud_invoke` with field projection, `cloud_inspect`, `emit_finding`.

Severity: confirmed public blob container with objects = critical. Storage account that allows public access but has no anonymous containers = medium.

Call `emit_finding` with `protocol="azure"` and `mission="exposure"`.
