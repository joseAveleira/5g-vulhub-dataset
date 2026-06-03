# ========================================
#  TEST DE CONTENEDORES VULNHUB CTF (19 SERVICIOS)
# ========================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST DE CONTENEDORES VULNHUB CTF" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar que Docker está corriendo
Write-Host "1. Verificando Docker daemon..." -ForegroundColor Yellow
try {
    $dockerTest = docker ps 2>&1
    Write-Host "   [OK] Docker está funcionando" -ForegroundColor Green
} catch {
    Write-Host "   [ERROR] Docker NO está funcionando" -ForegroundColor Red
    exit
}
Write-Host ""

# 2. Verificar cantidad de contenedores
Write-Host "2. Contenedores corriendo:" -ForegroundColor Yellow
$containers = docker ps --format "{{.Names}}"
$containerCount = ($containers -split "`n" | Where-Object { $_ }).Count
Write-Host "   Total: $containerCount contenedores corriendo" -ForegroundColor Cyan
Write-Host ""

# 3. Verificar cada servicio (19 servicios)
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  3. VERIFICACION POR SERVICIO (19)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$services = @(
    # Servicios HTTP (16)
    @{ name = "Spring"; port = 8180; type = "HTTP" },
    @{ name = "Struts2"; port = 8081; type = "HTTP" },
    @{ name = "Drupal"; port = 8082; type = "HTTP" },
    @{ name = "Jenkins"; port = 8083; type = "HTTP" },
    @{ name = "ApacheDruid"; port = 8888; type = "HTTP" },
    @{ name = "PHP-FPM"; port = 8086; type = "HTTP" },
    @{ name = "Tomcat"; port = 8087; type = "HTTP" },
    @{ name = "Elasticsearch"; port = 9200; type = "HTTP" },
    @{ name = "phpMyAdmin"; port = 8088; type = "HTTP" },
    @{ name = "WordPress"; port = 8089; type = "HTTP" },
    @{ name = "Nexus"; port = 8090; type = "HTTP" },
    @{ name = "Grafana"; port = 3000; type = "HTTP" },
    @{ name = "Joomla"; port = 8091; type = "HTTP" },
    @{ name = "WebLogic"; port = 7001; type = "HTTP" },
    @{ name = "Solr"; port = 8983; type = "HTTP" },
    @{ name = "Fastjson"; port = 8092; type = "HTTP" },
    
    # Servicios NO HTTP (3)
    @{ name = "Redis"; port = 6379; type = "TCP" },
    @{ name = "MySQL"; port = 3307; type = "TCP" },
    @{ name = "OpenSSH"; port = 2222; type = "TCP" }
)

$success = 0
$failed = 0
$details = @()

foreach ($svc in $services) {
    Write-Host ""
    Write-Host "[$($svc.name)] Tipo: $($svc.type)" -ForegroundColor White
    Write-Host "  Puerto: $($svc.port)" -ForegroundColor Gray
    
    if ($svc.type -eq "TCP") {
        # Probar solo TCP (sin TimeoutSeconds para PowerShell 5.1)
        $tcpTest = Test-NetConnection -ComputerName localhost -Port $svc.port -InformationLevel Quiet 2>&1
        
        if ($tcpTest -eq $true) {
            Write-Host "  [OK] Puerto $($svc.port) ABIERTO" -ForegroundColor Green
            $success++
            $details += [PSCustomObject]@{ Servicio = $svc.name; Puerto = $svc.port; Estado = "OK" }
        } else {
            Write-Host "  [ERROR] Puerto $($svc.port) CERRADO" -ForegroundColor Red
            $failed++
            $details += [PSCustomObject]@{ Servicio = $svc.name; Puerto = $svc.port; Estado = "FALLIDO" }
        }
    } else {
        # Probar HTTP + TCP fallback
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$($svc.port)" -TimeoutSec 3 -UseBasicParsing 2>&1
            Write-Host "  [OK] HTTP responde (código $($response.StatusCode))" -ForegroundColor Green
            $success++
            $details += [PSCustomObject]@{ Servicio = $svc.name; Puerto = $svc.port; Estado = "OK" }
        } catch {
            # Fallback: solo probar TCP
            $tcpTest = Test-NetConnection -ComputerName localhost -Port $svc.port -InformationLevel Quiet 2>&1
            
            if ($tcpTest -eq $true) {
                Write-Host "  [OK] Puerto TCP ABIERTO (servicio no responde HTTP)" -ForegroundColor Yellow
                $success++
                $details += [PSCustomObject]@{ Servicio = $svc.name; Puerto = $svc.port; Estado = "OK (TCP)" }
            } else {
                Write-Host "  [ERROR] Puerto CERRADO o servicio no responde" -ForegroundColor Red
                $failed++
                $details += [PSCustomObject]@{ Servicio = $svc.name; Puerto = $svc.port; Estado = "FALLIDO" }
            }
        }
    }
}

# 4. Mostrar tabla resumen
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TABLA RESUMEN" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$details | Format-Table -AutoSize

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESULTADO FINAL" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Exitosos: $success / 19" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "  Fallidos: $failed / 19" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($failed -eq 0) {
    Write-Host "  [OK] TODOS LOS 19 CONTENEDORES ESTAN FUNCIONANDO!" -ForegroundColor Green
    Write-Host "  PUEDES INICIAR TUS ATAQUES CTF" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] ALGUNOS CONTENEDORES NO ESTAN FUNCIONANDO" -ForegroundColor Red
    Write-Host "  Verifica: docker logs <nombre-contenedor>" -ForegroundColor Yellow
}
Write-Host ""