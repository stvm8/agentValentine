=== GET op/v1/operators ===
HTTP 000 | Size: 0b | URL: op/v1/operators
=== GET op/v1/regions ===
HTTP 000 | Size: 0b | URL: op/v1/regions
=== GET op/v1/permission_policies ===
HTTP 000 | Size: 0b | URL: op/v1/permission_policies
=== GET op/v1/permission_requests ===
HTTP 000 | Size: 0b | URL: op/v1/permission_requests
=== GET op/v1/operators/me ===
HTTP 000 | Size: 0b | URL: op/v1/operators/me
=== GET op/v1/regions/default_region ===
HTTP 000 | Size: 0b | URL: op/v1/regions/default_region
# Unauthenticated API Probe — Fri Apr  3 07:45:54 AM CDT 2026
# Unauthenticated API Probe — Fri Apr  3 07:45:59 AM CDT 2026
[000] op/v1/operators | 
[000] op/v1/regions | 
[000] op/v1/permission_policies | 
[000] op/v1/permission_requests | 
[000] op/v1/operators/me | 
[000] op/v1/regions/default_region | 
[000] op/v1/permission_requests/fetch_approvers | 
# Unauthenticated API Probe — Fri Apr  3 07:46:12 AM CDT 2026
[401] op/v1/operators =>  
[401] op/v1/regions =>  
[401] op/v1/permission_policies =>  
[401] op/v1/permission_requests =>  
[401] op/v1/operators/me =>  
[401] op/v1/regions/default_region =>  
[401] op/v1/permission_requests/fetch_approvers =>  
[401] op/v1/zone_pricing_configs =>  
[401] op/v1/pricing_experiments/region_pricing_or_experiments =>  
[403] auth/login | {"error":"CORS Forbidden"}
[403] scheduled-queries | {"error":"CORS Forbidden"}
[403] external-scheduled-queries | {"error":"CORS Forbidden"}
[403] snowflake/snowflake-data | {"error":"CORS Forbidden"}
[403] admin-console/admin-users | {"error":"CORS Forbidden"}
[403] admin-console/scheduled-queries | {"error":"CORS Forbidden"}
[403] admin-console/login-notices | {"error":"CORS Forbidden"}
[403] admin-console/restricted-modules | {"error":"CORS Forbidden"}
[403] custom-dashboards/metric-summary-v2 | {"error":"CORS Forbidden"}
[403] query-pad/shared-query-result | {"error":"CORS Forbidden"}
[401] scheduled-queries?user=test@lime.bike | Unauthorized
[401] external-scheduled-queries?user=test@lime.bike | Unauthorized
[401] snowflake/snowflake-data | Unauthorized
[401] admin-console/admin-users | Unauthorized
[401] admin-console/scheduled-queries | Unauthorized
[401] admin-console/login-notices | Unauthorized
[401] admin-console/restricted-modules | Unauthorized
[401] custom-dashboards/metric-summary-v2 | Unauthorized
