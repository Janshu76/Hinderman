$ErrorActionPreference = "Stop"
$baseUrl = if ($env:WARDEN_BASE_URL) { $env:WARDEN_BASE_URL } else { "http://localhost:8000" }
$adminKey = if ($env:WARDEN_ADMIN_API_KEY) { $env:WARDEN_ADMIN_API_KEY } else { "warden-demo-admin-key" }
$headers = @{ Authorization = "Bearer $adminKey" }

Write-Host "1. Send a normal prompt"
Invoke-RestMethod -Method Post -Uri "$baseUrl/gateway/v1/chat" -ContentType "application/json" -Body (@{
    messages = @(@{ role = "user"; content = "Explain what a traffic gateway does in one sentence." })
} | ConvertTo-Json -Depth 5) | ConvertTo-Json -Depth 8

Write-Host "`n2. Send the same request with sensitive data; the model should receive a masked value"
Invoke-RestMethod -Method Post -Uri "$baseUrl/gateway/v1/chat" -ContentType "application/json" -Body (@{
    messages = @(@{ role = "user"; content = "Explain what a traffic gateway does. Contact person@example.com." })
} | ConvertTo-Json -Depth 5) | ConvertTo-Json -Depth 8

Write-Host "`n3. Change the email policy live from mask to block"
$policies = Invoke-RestMethod -Method Get -Uri "$baseUrl/api/policies"
$policies.rules = @($policies.rules | Where-Object { $_.category -ne "email" })
$policies.rules += @{
    category = "email"; min_severity = "low"; action = "block"; replacement = "[REDACTED]"; priority = 10; enabled = $true
}
Invoke-RestMethod -Method Put -Uri "$baseUrl/api/policies" -Headers $headers -ContentType "application/json" -Body ($policies | ConvertTo-Json -Depth 8) | Out-Null

Write-Host "`n4. Send the sensitive request again; the gateway should block it without calling the model"
Invoke-RestMethod -Method Post -Uri "$baseUrl/gateway/v1/chat" -ContentType "application/json" -Body (@{
    messages = @(@{ role = "user"; content = "Explain what a traffic gateway does. Contact person@example.com." })
} | ConvertTo-Json -Depth 5) | ConvertTo-Json -Depth 8
