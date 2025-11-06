## Análisis de Requisitos Adicionales de Seguridad (ID 10-14)

### ID 10: Mecanismo para revocar tokens (OAuth-REVOCATION)
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Problema identificado:**
- **No existe endpoint de revocación** según RFC 7009
- No hay almacenamiento de tokens activos
- No hay blacklist de tokens revocados

**Endpoint faltante:**
```java
// FALTA COMPLETAMENTE - Debería existir:
@PostMapping("/token/revoke")
public ResponseEntity<?> revokeToken(@RequestBody TokenRevocationRequest request) {
    // Implementación según RFC 7009
}
```

**Solución requerida:**
```java
@RestController
public class TokenRevocationController {
    @Autowired
    private TokenBlacklistService blacklistService;
    
    @PostMapping("/oauth/revoke")
    public ResponseEntity<?> revokeToken(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestHeader("Authorization") String clientAuth) {
        
        // Validar cliente
        if (!validateClient(clientAuth)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        // Agregar token a blacklist
        blacklistService.revokeToken(token);
        
        // RFC 7009: Siempre retornar 200 OK
        return ResponseEntity.ok().build();
    }
}
```

---

### ID 11: Mecanismo para revocar client_secrets
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Problemas identificados:**
1. No hay endpoint para rotar/revocar secrets
2. No hay versionado de secrets
3. No hay auditoría de cambios de secrets
4. Secrets hardcodeados con `{noop}`

**Ubicación del problema:**
- **Falta endpoint de gestión de secrets**
- `CcpRegisteredClientRepository.java` no proporcionado

**Implementación necesaria:**
```java
@RestController
@RequestMapping("/admin/clients")
public class ClientManagementController {
    
    @PostMapping("/{clientId}/rotate-secret")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> rotateClientSecret(@PathVariable String clientId) {
        // Generar nuevo secret
        String newSecret = generateSecureSecret();
        
        // Actualizar en CyberArk
        cyberArkService.updateSecret(clientId, newSecret);
        
        // Invalidar tokens existentes del cliente
        tokenService.revokeAllTokensForClient(clientId);
        
        // Auditar el cambio
        auditService.logSecretRotation(clientId, getCurrentUser());
        
        return ResponseEntity.ok(Map.of(
            "client_id", clientId,
            "new_secret", newSecret,
            "rotated_at", Instant.now()
        ));
    }
    
    @PostMapping("/{clientId}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> revokeClient(@PathVariable String clientId, 
                                         @RequestBody RevokeReason reason) {
        // Marcar cliente como revocado
        clientRepository.revokeClient(clientId, reason);
        
        // Revocar todos los tokens
        tokenService.revokeAllTokensForClient(clientId);
        
        return ResponseEntity.ok().build();
    }
}
```

---

### ID 12: Rotación de Refresh Token
**⏸️ PENDIENTE PARA FASE 3**
**🟡 SEVERIDAD MEDIA** (cuando se implemente)

**Estado actual:**
- Marcado como PENDIENTE FASE 3
- No hay implementación de refresh tokens actualmente

**Para implementar en Fase 3:**
```java
// Ejemplo de implementación futura
public class RefreshTokenRotation {
    @PostMapping("/token/refresh")
    public TokenResponse refreshToken(@RequestBody RefreshRequest request) {
        // 1. Validar refresh token actual
        // 2. Generar NUEVO refresh token (rotación)
        // 3. Invalidar refresh token anterior
        // 4. Retornar nuevo access token + nuevo refresh token
    }
}
```

---

### ID 13: Datos sensibles solo en POST body
**⚠️ PARCIALMENTE CUMPLE**
**🔴 SEVERIDAD ALTA**

**Verificación en código actual:**

**✅ CORRECTO en `TokenController.java`:**
```java
@PostMapping("/token")  // ✅ Usa POST
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    // ✅ Credenciales en body, no en headers o URL
}
```

**❌ PROBLEMA en `application.properties`:**
```properties
spring.security.user.name=user
spring.security.user.password=password  // ⚠️ Contraseña en archivo de configuración
```

**❌ RIESGO potencial - No hay validación para prevenir:**
```java
// Debería rechazar esto:
@GetMapping("/token")  // ❌ GET con credenciales
@RequestParam String clientSecret  // ❌ Secret en URL
```

**Solución requerida:**
```java
@Component
public class SensitiveDataFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain chain) {
        // Rechazar credenciales en GET o headers
        if (request.getMethod().equals("GET") && 
            (request.getParameter("password") != null || 
             request.getParameter("client_secret") != null)) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write("Sensitive data must be in POST body");
            return;
        }
        chain.doFilter(request, response);
    }
}
```

---

### ID 14: No usar API Keys para autenticación
**⏸️ PENDIENTE PARA FASE 3**
**🟡 SEVERIDAD MEDIA** (cuando se implemente)

**Estado actual:**
- Marcado como PENDIENTE FASE 3
- No se observan API Keys en el código actual
- Usa OAuth2 client credentials (correcto)

**Verificación actual:**
```java
// ✅ Usa OAuth2, no API Keys
ClientAuthenticationMethod.CLIENT_SECRET_BASIC
```

---

## Resumen Consolidado ID 10-14

| ID | Requisito | Estado | Severidad | Urgencia |
|----|-----------|--------|-----------|----------|
| 10 | **Revocación de tokens** | **❌ No implementado** | **🔴 ALTA** | **Inmediato** |
| 11 | **Revocación client_secrets** | **❌ No implementado** | **🔴🔴 CRÍTICA** | **Urgente** |
| 12 | Rotación refresh token | ⏸️ Pendiente Fase 3 | 🟡 MEDIA | Fase 3 |
| 13 | **Datos sensibles en POST** | **⚠️ Parcial** | **🔴 ALTA** | **Inmediato** |
| 14 | No API Keys | ⏸️ Pendiente Fase 3 | 🟡 MEDIA | Fase 3 |

## 🚨 Acciones Críticas Requeridas

### Implementación Inmediata:

1. **Crear TokenBlacklistService:**
```java
@Service
public class TokenBlacklistService {
    private final Cache<String, Boolean> blacklist;
    
    public void revokeToken(String jti) {
        blacklist.put(jti, true);
    }
    
    public boolean isRevoked(String jti) {
        return blacklist.getIfPresent(jti) != null;
    }
}
```

2. **Agregar AdminController para gestión:**
```java
@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    // Endpoints de revocación
    // Rotación de secrets
    // Auditoría
}
```

3. **Configurar auditoría:**
```java
@Component
public class SecurityAuditLogger {
    public void logTokenRevocation(String token, String reason) { }
    public void logSecretRotation(String clientId) { }
    public void logSuspiciousActivity(String details) { }
}
```

**Compliance actual: 0.5/5 requisitos activos (10%)**

**Estado: CRÍTICO - Vulnerabilidades de seguridad severas** ⛔

## Análisis de Requisitos de Seguridad (ID 15-16 + ACCESO Y CONSUMO)

### ID 15: Todas las APIs requieren grant type para acceso
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Archivo:** `OauthTokenRequest.java`

**Problema identificado:**
```java
// OauthTokenRequest.java - NO tiene campo grant_type
public class OauthTokenRequest {
    private String clientId;
    private String clientSecret;
    private List<String> scopes;
    // ⚠️ FALTA: private String grantType;
}
```

**Implementación requerida:**
```java
// 1. Modificar OauthTokenRequest
public class OauthTokenRequest {
    @NotNull
    @Schema(description = "Grant type según RFC 6749")
    private String grantType; // client_credentials, authorization_code, refresh_token, password
    
    // Validación en el controller
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@RequestBody @Valid OauthTokenRequest request) {
        // Validar grant_type obligatorio
        if (!isValidGrantType(request.getGrantType())) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "unsupported_grant_type"));
        }
        
        switch(request.getGrantType()) {
            case "client_credentials":
                return handleClientCredentials(request);
            case "authorization_code":
                return handleAuthorizationCode(request);
            default:
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "unsupported_grant_type"));
        }
    }
}
```

---

### ID 16: No transmitir autenticación en URL
**⚠️ RIESGO PRESENTE**
**🔴 SEVERIDAD ALTA**

**Problema identificado:**
- No hay validación activa que prevenga esto
- El endpoint `/token` acepta POST pero no rechaza GET explícitamente

**Validación faltante:**
```java
@Component
@Order(1)
public class CredentialProtectionFilter extends OncePerRequestFilter {
    
    private static final Set<String> SENSITIVE_PARAMS = Set.of(
        "password", "client_secret", "refresh_token", "access_token"
    );
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Rechazar credenciales en URL (query params)
        for (String param : SENSITIVE_PARAMS) {
            if (request.getParameter(param) != null) {
                response.setStatus(HttpStatus.BAD_REQUEST.value());
                response.getWriter().write(
                    "{\"error\":\"Credentials must not be sent in URL\"}"
                );
                return;
            }
        }
        
        // Rechazar credenciales en headers no autorizados
        if (request.getHeader("X-Password") != null || 
            request.getHeader("X-Client-Secret") != null) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }
        
        chain.doFilter(request, response);
    }
}
```

---

## ACCESO Y CONSUMO

### ID 1: Límite de peticiones (Rate Limiting) para mitigar DDoS
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Problema:** No hay rate limiting configurado

**Implementación requerida:**

**Opción 1 - Con Bucket4j:**
```java
@Configuration
public class RateLimitConfig {
    
    @Bean
    public Bucket createBucket() {
        Bandwidth limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        return Bucket4j.builder()
            .addLimit(limit)
            .build();
    }
}

@Component
public class RateLimitFilter extends OncePerRequestFilter {
    @Autowired
    private RateLimitService rateLimitService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        String clientId = extractClientId(request);
        Bucket bucket = rateLimitService.resolveBucket(clientId);
        
        if (!bucket.tryConsume(1)) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setHeader("X-Rate-Limit-Retry-After", 
                String.valueOf(bucket.estimateAbilityToConsume(1)));
            response.getWriter().write("{\"error\":\"rate_limit_exceeded\"}");
            return;
        }
        
        chain.doFilter(request, response);
    }
}
```

**Opción 2 - Con Spring Cloud Gateway (si está disponible):**
```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: oauth-server
          filters:
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10
                redis-rate-limiter.burstCapacity: 20
```

---

### ID 2: Usar cabecera HSTS (HTTP Strict Transport Security)
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Implementación requerida:**

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configuración existente...
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 año
                    .preload(true)
                )
                .frameOptions(frame -> frame.deny())
                .xssProtection(xss -> xss.mode(XSS.Mode.BLOCK))
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'"))
            );
        
        return http.build();
    }
}
```

---

### ID 3: Control de acceso mediante lista blanca de IPs (APIs privadas)
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA** (para APIs privadas)

**Implementación requerida:**

```java
@Component
@Order(0)
public class IPWhitelistFilter extends OncePerRequestFilter {
    
    @Value("${security.ip.whitelist:}")
    private Set<String> whitelistedIPs;
    
    @Value("${security.ip.whitelist.enabled:false}")
    private boolean whitelistEnabled;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        if (!whitelistEnabled) {
            chain.doFilter(request, response);
            return;
        }
        
        String clientIP = getClientIP(request);
        
        if (!whitelistedIPs.contains(clientIP)) {
            log.warn("Rejected request from non-whitelisted IP: {}", clientIP);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("{\"error\":\"IP not authorized\"}");
            return;
        }
        
        chain.doFilter(request, response);
    }
    
    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }
        return request.getRemoteAddr();
    }
}
```

**Configuración en application.properties:**
```properties
security.ip.whitelist.enabled=true
security.ip.whitelist=192.168.1.100,192.168.1.101,10.0.0.0/24
```

---

### ID 4: Validación de estructura y tipo de datos
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Estado actual:**
- ✅ Usa `@RequestBody` con objetos tipados
- ❌ No hay validación con Bean Validation

**Mejoras requeridas:**

```java
// 1. Agregar dependencia en pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

// 2. Modificar DTOs con validaciones
public class OauthTokenRequest {
    
    @NotBlank(message = "Client ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Invalid client ID format")
    @Size(min = 5, max = 50)
    private String clientId;
    
    @NotBlank(message = "Client secret is required")
    @Size(min = 32, max = 256, message = "Invalid secret length")
    private String clientSecret;
    
    @NotNull(message = "Grant type is required")
    @Pattern(regexp = "^(client_credentials|authorization_code|refresh_token|password)$")
    private String grantType;
    
    @NotEmpty(message = "At least one scope is required")
    @Size(max = 10, message = "Too many scopes requested")
    private List<@Pattern(regexp = "^[a-z:]+$") String> scopes;
}

// 3. Validar en controller
@PostMapping("/token")
public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request,
                                  BindingResult bindingResult) {
    if (bindingResult.hasErrors()) {
        Map<String, String> errors = bindingResult.getFieldErrors().stream()
            .collect(Collectors.toMap(
                FieldError::getField,
                FieldError::getDefaultMessage
            ));
        return ResponseEntity.badRequest().body(errors);
    }
    // Proceso normal...
}
```

---

## Resumen Total de Cumplimiento

### OAuth2/Autenticación (ID 1-16)

| ID | Requisito | Estado | Severidad |
|----|-----------|--------|-----------|
| 1-14 | (Análisis previo) | Mayoría ❌ | Variable |
| **15** | **Grant type obligatorio** | **❌ No implementado** | **🔴 ALTA** |
| **16** | **No auth en URL** | **⚠️ Riesgo** | **🔴 ALTA** |

### Acceso y Consumo

| ID | Requisito | Estado | Severidad |
|----|-----------|--------|-----------|
| **1** | **Rate limiting** | **❌ No implementado** | **🔴🔴 CRÍTICA** |
| **2** | **HSTS header** | **❌ No implementado** | **🔴 ALTA** |
| **3** | **IP whitelist** | **❌ No implementado** | **🔴 ALTA** |
| **4** | **Validación datos** | **⚠️ Parcial** | **🔴 ALTA** |

## 🚨 Prioridad de Implementación

### CRÍTICAS (Implementar YA):
1. Rate Limiting (DDoS)
2. Revocación de secrets (ID 11 anterior)
3. Replay attacks (ID 4 anterior)

### URGENTES (Antes de producción):
4. HSTS Headers
5. Grant Type obligatorio
6. Validación completa de datos
7. IP Whitelist (si es API privada)

**Estado Global: 2/20 requisitos cumplidos (10%)** ⛔

**Recomendación: NO DESPLEGAR EN PRODUCCIÓN**