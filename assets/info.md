## Análisis Detallado de Problemas de Seguridad

### ID 1: Verificación de permisos de aplicación después de validar JWT
**❌ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 30-62)

**Problema específico:**
```java
// Solo valida credenciales del cliente, NO verifica permisos específicos de API
if (registeredClient == null ||
    !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid client credentials");
}
```

**Falta implementar:**
- No hay verificación de scopes contra los endpoints específicos
- No existe validación de que el cliente tenga permisos para APIs específicas
- El JWT se genera con todos los scopes del cliente sin validación adicional

**Solución requerida:**
```java
// Agregar verificación de scopes específicos
if (!registeredClient.getScopes().containsAll(request.getScopes())) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body("Client not authorized for requested scopes");
}
```

---

### ID 2: Restricción de autenticación usuario/contraseña para información sensible
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java`
- **Método:** `userDetailsService()` (líneas 97-104)

```java
@Bean
UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withUsername("user")
            .password("{noop}user") // ⚠️ Permite acceso sin restricción de sensibilidad
            .authorities("ROLE_USER")
            .build();
    return new InMemoryUserDetailsManager(userDetails);
}
```

**Problemas identificados:**
1. No hay clasificación de APIs (sensible vs no sensible)
2. No existe lógica para rechazar solicitudes a datos sensibles con autenticación básica
3. El `TokenController` no valida el tipo de autenticación usado

**Solución requerida:**
```java
// Agregar clasificación de datos y validación
if (authMethod.equals("password") && isSensitiveScope(requestedScopes)) {
    throw new AccessDeniedException("Password auth not allowed for sensitive data");
}
```

---

### ID 3: Autenticación mediante certificado para información sensible
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java` (línea 42-45)
- **Archivo:** `SecurityConfig.java`

```java
// TokenController.java - Solo acepta CLIENT_SECRET_BASIC
OAuth2ClientAuthenticationToken authenticationToken = new OAuth2ClientAuthenticationToken(
        registeredClient,
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, // ⚠️ Solo método básico
        registeredClient.getClientSecret()
);
```

**Falta completamente:**
- No hay configuración de SSL mutual (mTLS)
- No existe soporte para `ClientAuthenticationMethod.TLS_CLIENT_AUTH`
- No hay validación de certificados X.509

**Solución requerida:**
```java
// Habilitar mTLS en application.properties
server.ssl.client-auth=need
server.ssl.trust-store=classpath:truststore.jks
server.ssl.trust-store-password=changeit

// Agregar soporte para autenticación por certificado
ClientAuthenticationMethod.TLS_CLIENT_AUTH
```

---

### ID 4: Implementación del parámetro nonce para prevenir ataques replay
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 49-57)

```java
JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("https://localhost:9054")
        .subject(request.getClientId())
        .audience(List.of("api-gateway", "resource-server"))
        .issuedAt(now)
        .expiresAt(expiresAt)
        .claim("scope", String.join(" ", registeredClient.getScopes()))
        // ⚠️ FALTA: .claim("nonce", generateNonce())
        // ⚠️ FALTA: .claim("jti", UUID.randomUUID().toString())
        .build();
```

**Problemas:**
1. No hay generación de nonce
2. No hay almacenamiento de nonces usados
3. No hay validación contra replay attacks
4. Falta el claim "jti" (JWT ID) único

**Solución requerida:**
```java
// Agregar nonce y jti
.claim("nonce", UUID.randomUUID().toString())
.claim("jti", UUID.randomUUID().toString())

// Implementar cache para validar nonces usados
@Autowired
private Cache<String, Boolean> nonceCache;

if (nonceCache.getIfPresent(nonce) != null) {
    throw new SecurityException("Nonce already used - possible replay attack");
}
```

---

### ID 5: No configurar scope default de OAuth 2.0
**✅ CUMPLE**
**🟢 SIN RIESGO**

**Verificación correcta en:**
- **Archivo:** `TokenController.java` (línea 56)
- Los scopes se toman explícitamente del cliente registrado sin defaults

---

## Resumen de Severidades

| Requisito | Estado | Severidad | Acción Requerida |
|-----------|--------|-----------|-------------------|
| ID 1 | ❌ Parcial | 🔴 **ALTA** | Implementar verificación de scopes |
| ID 2 | ❌ No implementado | 🔴 **ALTA** | Agregar restricción por tipo de auth |
| ID 3 | ❌ No implementado | 🔴 **ALTA** | Configurar mTLS |
| ID 4 | ❌ No implementado | 🔴🔴 **CRÍTICA** | Implementar nonce y jti urgentemente |
| ID 5 | ✅ Cumple | 🟢 **OK** | Ninguna |

**Estado del sistema: NO SEGURO PARA PRODUCCIÓN** ⛔

## Análisis de Requisitos Adicionales de Seguridad (ID 6-9)

### ID 6: Bloqueo después de 3 intentos fallidos de autenticación
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 30-40)

**Problema específico:**
```java
if (registeredClient == null ||
    !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid client credentials");
    // ⚠️ No hay contador de intentos fallidos
    // ⚠️ No hay bloqueo temporal o permanente
    // ⚠️ No hay registro de intentos fallidos
}
```

**Falta implementar:**
- Sistema de conteo de intentos fallidos
- Mecanismo de bloqueo temporal/permanente
- Almacenamiento de intentos por cliente
- Tiempo de desbloqueo automático

**Solución requerida:**
```java
@Autowired
private LoadingCache<String, AtomicInteger> failedAttemptsCache;

// En el método getToken()
int attempts = failedAttemptsCache.get(clientId).incrementAndGet();
if (attempts >= 3) {
    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
        .body("Account locked due to multiple failed attempts");
}
```

---

### ID 7: No extraer algoritmo de firma JWT del header
**✅ PARCIALMENTE CUMPLE**
**🟡 SEVERIDAD MEDIA**

**Ubicación verificada:**
- **Archivo:** `SecurityConfig.java`
- **Método:** `generateRSAKey()` (líneas 130-142)

**Implementación actual:**
```java
// El algoritmo está implícito en RSAKey pero no explícitamente definido
@Bean
public JwtEncoder jwtEncoder() {
    JWKSource<SecurityContext> jwkSource = jwkSource();
    return new NimbusJwtEncoder(jwkSource);
    // ⚠️ No especifica explícitamente RS256/RS512
}
```

**Observaciones:**
- Usa RSA por defecto (bueno)
- No especifica explícitamente el algoritmo (RS256/RS384/RS512)
- No vulnerable a "algorithm confusion" pero podría ser más explícito

**Mejora recomendada:**
```java
// Especificar algoritmo explícitamente
JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
    .type(JOSEObjectType.JWT)
    .build();
```

---

### ID 8: No almacenar datos sensibles en el JWT
**⚠️ RIESGO POTENCIAL**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 49-57)

```java
JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("https://localhost:9054")
        .subject(request.getClientId()) // ⚠️ ClientId expuesto
        .audience(List.of("api-gateway", "resource-server"))
        .issuedAt(now)
        .expiresAt(expiresAt)
        .claim("scope", String.join(" ", registeredClient.getScopes())) // ⚠️ Todos los scopes expuestos
        .build();
```

**Problemas identificados:**
1. ClientId visible en el subject (podría ser sensible)
2. Todos los scopes del cliente expuestos
3. No hay validación de qué información se incluye

**Datos sensibles que NO deben estar:**
- ❌ Contraseñas
- ❌ Client secrets
- ❌ PII (Información Personal Identificable)
- ❌ Números de cuenta
- ❌ Datos de tarjetas

**Recomendación:**
```java
// Usar identificadores opacos o referencias
.subject(hashClientId(request.getClientId()))
.claim("scope", filterPublicScopes(registeredClient.getScopes()))
```

---

### ID 9: Validar id_client en refresh token
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **No existe implementación de refresh token**

**Problemas identificados:**
1. No hay endpoint para refresh token
2. No hay validación de client_id en renovación
3. No hay lógica de refresh token en `TokenController`

**Implementación faltante:**
```java
@PostMapping("/token/refresh")
public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
    // ⚠️ FALTA: Validar que el client_id del refresh token 
    // coincida con el client_id de la solicitud
    
    String originalClientId = extractClientIdFromRefreshToken(request.getRefreshToken());
    if (!originalClientId.equals(request.getClientId())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body("Client ID mismatch in refresh token");
    }
}
```

---

## Resumen Consolidado de Severidades (ID 1-9)

| ID | Requisito | Estado | Severidad | Impacto |
|----|-----------|--------|-----------|---------|
| 1 | Verificación permisos post-JWT | ❌ Parcial | 🔴 **ALTA** | Acceso no autorizado |
| 2 | Restricción usuario/contraseña | ❌ No implementado | 🔴 **ALTA** | Datos sensibles expuestos |
| 3 | Autenticación por certificado | ❌ No implementado | 🔴 **ALTA** | Sin autenticación fuerte |
| 4 | Parámetro nonce | ❌ No implementado | 🔴🔴 **CRÍTICA** | Replay attacks |
| 5 | No scope default | ✅ Cumple | 🟢 **OK** | - |
| 6 | **Bloqueo 3 intentos** | **❌ No implementado** | **🔴🔴 CRÍTICA** | **Fuerza bruta** |
| 7 | **Algoritmo JWT fijo** | **⚠️ Parcial** | **🟡 MEDIA** | **Algorithm confusion** |
| 8 | **No datos sensibles en JWT** | **⚠️ Riesgo** | **🔴 ALTA** | **Exposición de datos** |
| 9 | **Validar client_id refresh** | **❌ No existe** | **🔴 ALTA** | **Token hijacking** |

## Prioridad de Corrección

### 🔴🔴 **CRÍTICAS - Corregir INMEDIATAMENTE**
1. **ID 6:** Implementar bloqueo por intentos fallidos
2. **ID 4:** Agregar nonce y jti

### 🔴 **ALTAS - Bloquean producción**
3. **ID 9:** Implementar refresh token con validación
4. **ID 8:** Auditar y limpiar datos en JWT
5. **ID 1:** Verificación de permisos
6. **ID 2:** Restricción por tipo de autenticación
7. **ID 3:** Autenticación por certificado

### 🟡 **MEDIAS - Mejorar antes de producción**
8. **ID 7:** Especificar algoritmo explícitamente

**Estado Global: CRÍTICO - NO APTO PARA PRODUCCIÓN** ⛔

**Compliance: 1/9 requisitos cumplidos (11%)**


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

## Análisis Detallado de Requisitos de Seguridad (ID 5-10)

### ID 5: Acotar la longitud de datos esperados por la API
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `OauthTokenRequest.java`
- **Archivo:** `TokenController.java`

**Problema específico:**
```java
// OauthTokenRequest.java - Sin límites de longitud
public class OauthTokenRequest {
    private String clientId;        // ⚠️ Sin límite de tamaño
    private String clientSecret;    // ⚠️ Sin límite de tamaño
    private List<String> scopes;    // ⚠️ Sin límite de elementos o tamaño
}

// TokenController.java - No valida tamaño del request
@PostMapping("/token")
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    // ⚠️ Acepta payloads de cualquier tamaño
    // ⚠️ No hay validación de longitud de campos
}
```

**Problemas identificados:**
1. Sin límites de longitud en campos de entrada
2. No hay validación de tamaño del request completo
3. Vulnerable a buffer overflow y DoS por memoria
4. Sin restricciones en cantidad de elementos en listas

**Solución requerida:**
```java
// 1. Agregar dependencia en pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

// 2. Modificar OauthTokenRequest con validaciones
import jakarta.validation.constraints.*;

@Data
public class OauthTokenRequest {
    @NotBlank(message = "Client ID es requerido")
    @Size(min = 5, max = 100, message = "Client ID debe tener entre 5 y 100 caracteres")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Client ID contiene caracteres inválidos")
    private String clientId;
    
    @NotBlank(message = "Client secret es requerido")
    @Size(min = 32, max = 512, message = "Client secret debe tener entre 32 y 512 caracteres")
    private String clientSecret;
    
    @NotBlank(message = "Grant type es requerido")
    @Pattern(regexp = "^(client_credentials|authorization_code|refresh_token|password)$")
    private String grantType;
    
    @NotNull(message = "Scopes son requeridos")
    @Size(min = 1, max = 10, message = "Debe haber entre 1 y 10 scopes")
    private List<@NotBlank @Size(max = 50) String> scopes;
}

// 3. Modificar TokenController para validar
@PostMapping("/token")
public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request,
                                  BindingResult bindingResult) {
    // Validar errores de Bean Validation
    if (bindingResult.hasErrors()) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : bindingResult.getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(Map.of(
            "error", "invalid_request",
            "error_description", "Validación fallida",
            "details", errors
        ));
    }
    
    // Validación adicional de tamaño total del request
    if (calculateRequestSize(request) > 4096) { // 4KB max
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
            .body(Map.of("error", "Request excede tamaño máximo permitido"));
    }
    
    // Resto del código...
}

// 4. Configurar límites globales en application.properties
server.max-http-request-header-size=16KB
server.tomcat.max-swallow-size=2MB
server.tomcat.max-http-form-post-size=2MB
```

---

### ID 6: Implementar mecanismos de autorización para validar si el cliente autenticado tiene permitido realizar la acción o información solicitada
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Ubicación del problema:**
- **Archivo:** `TokenController.java` (líneas 30-62)
- **Archivo:** `SecurityConfig.java`

**Problema específico:**
```java
// TokenController.java - Solo valida credenciales, NO autorización
@PostMapping("/token")
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    RegisteredClient registeredClient = 
        registeredClientRepository.findByClientId(request.getClientId());

    // ✅ Autenticación (valida identidad)
    if (registeredClient == null ||
        !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid client credentials");
    }

    // ❌ FALTA: Autorización (validar permisos)
    // - ¿Este cliente puede solicitar estos scopes?
    // - ¿Este cliente tiene acceso a estas APIs?
    // - ¿El cliente tiene rol apropiado para esta operación?

    // Genera JWT con TODOS los scopes sin validar autorización
    JwtClaimsSet claims = JwtClaimsSet.builder()
            .claim("scope", String.join(" ", registeredClient.getScopes()))
            .build();
}
```

**Falta implementar:**
- No hay verificación de scopes contra los permitidos al cliente
- No existe validación de roles para operaciones sensibles
- No hay control de acceso basado en recursos/endpoints específicos
- El JWT se genera con todos los scopes sin validación

**Solución requerida:**
```java
// 1. Crear servicio de autorización
@Service
public class AuthorizationService {
    
    public AuthorizationResult validateScopeAuthorization(
            RegisteredClient client, 
            List<String> requestedScopes) {
        
        Set<String> allowedScopes = client.getScopes();
        
        for (String scope : requestedScopes) {
            if (!allowedScopes.contains(scope)) {
                return AuthorizationResult.denied(
                    "insufficient_scope",
                    "Cliente no autorizado para scope: " + scope
                );
            }
        }
        return AuthorizationResult.allowed();
    }
    
    public AuthorizationResult validateRoleAuthorization(
            RegisteredClient client,
            String requiredRole) {
        
        Set<String> clientRoles = extractClientRoles(client);
        
        if (!clientRoles.contains(requiredRole)) {
            return AuthorizationResult.denied(
                "access_denied",
                "Cliente no tiene el rol requerido: " + requiredRole
            );
        }
        return AuthorizationResult.allowed();
    }
}

// 2. Modificar TokenController con autorización
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    AuthorizationService authorizationService;

    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        
        // 1. AUTENTICACIÓN
        RegisteredClient registeredClient = 
            registeredClientRepository.findByClientId(request.getClientId());

        if (registeredClient == null ||
            !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_client"));
        }

        // 2. AUTORIZACIÓN
        
        // 2.1 Validar scopes solicitados
        AuthorizationResult scopeAuth = authorizationService
            .validateScopeAuthorization(registeredClient, request.getScopes());
        
        if (!scopeAuth.isAllowed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                    "error", scopeAuth.getErrorCode(),
                    "error_description", scopeAuth.getErrorDescription()
                ));
        }
        
        // 2.2 Validar grant type permitido
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(new AuthorizationGrantType(request.getGrantType()))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                    "error", "unauthorized_grant_type",
                    "error_description", "Cliente no autorizado para este grant type"
                ));
        }
        
        // 2.3 Validar rol para scopes admin
        for (String scope : request.getScopes()) {
            if (scope.startsWith("admin:")) {
                AuthorizationResult roleAuth = authorizationService
                    .validateRoleAuthorization(registeredClient, "ROLE_ADMIN");
                
                if (!roleAuth.isAllowed()) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of(
                            "error", "insufficient_permissions",
                            "error_description", "Scopes admin requieren ROLE_ADMIN"
                        ));
                }
            }
        }

        // 3. Generar token con scopes AUTORIZADOS únicamente
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .claim("scope", String.join(" ", request.getScopes()))
                .claim("client_roles", extractClientRoles(registeredClient))
                .claim("jti", UUID.randomUUID().toString())
                .build();
        // ...
    }
}
```

---

### ID 7: La generación de GUID (IDENTIFICADOR ÚNICO GLOBAL) debe ser totalmente aleatoria y no proveer signos de un patrón
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🟡 SEVERIDAD MEDIA**

**Ubicación verificada:**
- **Archivo:** `SecurityConfig.java` (línea 136)
- **Archivo:** `TokenController.java` (falta jti)

**Implementación actual:**
```java
// SecurityConfig.java - Uso correcto de UUID para key ID
private RSAKey generateRSAKey() {
    KeyPair keyPair = generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
           .privateKey(privateKey)
           .keyID(UUID.randomUUID().toString())  // ✅ UUID v4 - Criptográficamente seguro
           .build();
}

// TokenController.java - JWT NO incluye jti
JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("https://localhost:9054")
        .subject(request.getClientId())
        // ❌ FALTA: .claim("jti", UUID.randomUUID().toString())
        // ❌ FALTA: .claim("nonce", generateNonce())
        .build();
```

**Observaciones:**
- ✅ UUID.randomUUID() usa UUID versión 4 (random)
- ✅ Utiliza SecureRandom internamente (Java 21)
- ✅ 122 bits de entropía, criptográficamente seguro
- ❌ No se agrega jti (JWT ID) único a los tokens
- ❌ No se agrega nonce para prevenir replay

**Solución requerida:**
```java
// 1. Crear generador seguro de identificadores
@Component
public class SecureIdentifierGenerator {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    
    public String generateUUID() {
        return UUID.randomUUID().toString();
    }
    
    public String generateSecureToken(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    public String generateNonce() {
        return generateSecureToken(32); // 256 bits
    }
}

// 2. Modificar TokenController
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    private SecureIdentifierGenerator idGenerator;
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        // ... validaciones
        
        String jti = idGenerator.generateUUID();
        String nonce = idGenerator.generateNonce();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://localhost:9054")
                .subject(request.getClientId())
                .claim("jti", jti)       // ✅ Identificador único
                .claim("nonce", nonce)   // ✅ Prevenir replay
                .claim("scope", String.join(" ", request.getScopes()))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .build();
        // ...
    }
}
```

**❌ Anti-patrones a evitar:**
```java
// NUNCA usar patrones predecibles
String badId = System.currentTimeMillis() + "-" + clientId; // ❌ Predecible
String badId2 = "TOKEN-" + counter++; // ❌ Secuencial
String badId3 = MD5(clientId + timestamp); // ❌ Puede ser forzado
```

---

### ID 8: Todas las funciones sensibles como creación, modificación o eliminación de datos deberán ser validadas considerando el grupo de usuarios y su rol
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java` (líneas 97-104)
- **Sistema de roles:** Solo ROLE_USER genérico

**Problema específico:**
```java
// SecurityConfig.java - Un solo usuario sin roles diferenciados
@Bean
UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withUsername("user")
            .password("{noop}user")
            .authorities("ROLE_USER")  // ⚠️ Un solo rol genérico
            .build();
    return new InMemoryUserDetailsManager(userDetails);
}

// SecurityConfig.java - No hay control por operación
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/token").permitAll()
            .anyRequest().authenticated())  // ⚠️ Solo requiere autenticación, no roles específicos
            // ...
}
```

**Falta implementar:**
- Sistema de roles diferenciados (ADMIN, USER, VIEWER)
- Control de acceso basado en roles (RBAC) para operaciones CRUD
- Validación de permisos para funciones sensibles
- Auditoría de operaciones de modificación/eliminación

**Solución requerida:**
```java
// 1. Definir roles y permisos
public enum Permission {
    CLIENT_READ("client:read"),
    CLIENT_CREATE("client:create"),
    CLIENT_UPDATE("client:update"),
    CLIENT_DELETE("client:delete"),
    SECRET_ROTATE("secret:rotate"),
    TOKEN_REVOKE("token:revoke"),
    AUDIT_VIEW("audit:view");
    
    private final String permission;
    Permission(String permission) { this.permission = permission; }
}

public enum Role {
    VIEWER(Set.of(Permission.CLIENT_READ, Permission.TOKEN_READ)),
    USER(Set.of(Permission.CLIENT_READ, Permission.CLIENT_CREATE)),
    ADMIN(Set.of(/* todos los permisos */));
    
    private final Set<Permission> permissions;
    Role(Set<Permission> permissions) { this.permissions = permissions; }
}

// 2. Modificar SecurityConfig con múltiples roles
@Bean
UserDetailsService userDetailsService() {
    UserDetails viewer = User.withUsername("viewer")
            .password("{noop}viewer123")
            .authorities(Role.VIEWER.getGrantedAuthorities())
            .build();
    
    UserDetails user = User.withUsername("user")
            .password("{noop}user123")
            .authorities(Role.USER.getGrantedAuthorities())
            .build();
    
    UserDetails admin = User.withUsername("admin")
            .password("{noop}admin123")
            .authorities(Role.ADMIN.getGrantedAuthorities())
            .build();
    
    return new InMemoryUserDetailsManager(viewer, user, admin);
}

@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            // Endpoints públicos
            .requestMatchers("/login", "/error").permitAll()
            
            // Lectura - VIEWER+
            .requestMatchers(HttpMethod.GET, "/api/clients/**")
                .hasAnyRole("VIEWER", "USER", "ADMIN")
            
            // Creación - USER+
            .requestMatchers(HttpMethod.POST, "/api/clients/**")
                .hasAnyRole("USER", "ADMIN")
            
            // Modificación - ADMIN only
            .requestMatchers(HttpMethod.PUT, "/api/clients/**")
                .hasRole("ADMIN")
            
            // Eliminación - ADMIN only
            .requestMatchers(HttpMethod.DELETE, "/api/clients/**")
                .hasRole("ADMIN")
            
            // Operaciones sensibles - ADMIN only
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/*/revoke").hasRole("ADMIN")
            .requestMatchers("/api/*/rotate").hasRole("ADMIN")
            
            .anyRequest().authenticated())
            // ...
}

// 3. Crear controlador administrativo con auditoría
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    
    @Autowired
    private AuditService auditService;
    
    @PostMapping("/clients/{clientId}/rotate-secret")
    @PreAuthorize("hasAuthority('secret:rotate')")
    public ResponseEntity<?> rotateClientSecret(
            @PathVariable String clientId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        // Auditar operación sensible
        auditService.logSensitiveOperation(
            "SECRET_ROTATION",
            clientId,
            userDetails.getUsername(),
            "Rotando client secret"
        );
        
        // ... lógica de rotación
        
        return ResponseEntity.ok(Map.of(
            "client_id", clientId,
            "rotated_at", Instant.now(),
            "rotated_by", userDetails.getUsername()
        ));
    }
    
    @DeleteMapping("/clients/{clientId}")
    @PreAuthorize("hasAuthority('client:delete')")
    public ResponseEntity<?> deleteClient(
            @PathVariable String clientId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid DeletionRequest request) {
        
        // Auditar eliminación
        auditService.logSensitiveOperation(
            "CLIENT_DELETION",
            clientId,
            userDetails.getUsername(),
            request.getReason()
        );
        
        // Validar razón obligatoria
        if (request.getReason() == null || request.getReason().isEmpty()) {
            return ResponseEntity.badRequest()
                .body("Razón de eliminación requerida para operaciones sensibles");
        }
        
        // ... lógica de eliminación
        
        return ResponseEntity.ok(Map.of("deleted", true));
    }
}

// 4. Servicio de auditoría
@Service
public class AuditService {
    
    public void logSensitiveOperation(String operation, String resourceId, 
                                     String username, String details) {
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Instant.now())
            .operation(operation)
            .resourceId(resourceId)
            .username(username)
            .details(details)
            .ipAddress(getCurrentRequestIP())
            .build();
        
        auditRepository.save(auditLog);
        
        log.warn("SENSITIVE_OPERATION: operation={}, resource={}, user={}, ip={}", 
                 operation, resourceId, username, auditLog.getIpAddress());
    }
}

// 5. Habilitar Method Security
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
}
```

---

### ID 9: Todo acceso desde la API hacia el backend debe ser mediante canales cifrados
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `MainConfiguration.java`
- **Archivo:** `application.properties`

**Problema específico:**
```java
// MainConfiguration.java - RestTemplate sin configuración SSL explícita
@Configuration
public class MainConfiguration {

    @Bean("clienteRestBalanced")
    @LoadBalanced
    public RestTemplate getRestTemplateBalanced() {
        return new RestTemplate();  // ⚠️ No configura SSL/TLS explícitamente
        // ⚠️ No valida certificados
        // ⚠️ No verifica hostname
        // ⚠️ Podría aceptar certificados auto-firmados
    }
}
```

```properties
# application.properties - SSL configurado para servidor pero no para cliente
server.ssl.trust-store=classpath:oauthserver-truststore.p12
eureka.client.serviceUrl.defaultZone=https://localhost:9100/eureka/

# ⚠️ Falta configuración de TLS para RestTemplate
# ⚠️ No hay validación de protocolos permitidos (TLS 1.3/1.2)
```

**Falta implementar:**
- Configuración SSL/TLS en RestTemplate
- Verificación de certificados y hostname
- Protocolos TLS 1.3/1.2 forzados
- Rechazo de conexiones HTTP

**Solución requerida:**
```java
// 1. Agregar dependencia en pom.xml
<dependency>
    <groupId>org.apache.httpcomponents.client5</groupId>
    <artifactId>httpclient5</artifactId>
</dependency>

// 2. Configurar RestTemplate con SSL
@Configuration
public class MainConfiguration {

    @Value("${server.ssl.trust-store}")
    private Resource trustStore;
    
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @Bean("clienteRestBalanced")
    @LoadBalanced
    public RestTemplate getRestTemplateBalanced() throws Exception {
        // Configurar SSL Context
        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial(
                    loadKeyStore(trustStore, trustStorePassword),
                    null  // No usar TrustSelfSignedStrategy en producción
                )
                .setProtocol("TLSv1.3")  // ✅ Forzar TLS 1.3
                .build();
        
        // SSL Socket Factory con verificación de hostname
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[]{"TLSv1.3", "TLSv1.2"},
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()  // ✅ Verificar hostname
        );
        
        // Connection Manager
        PoolingHttpClientConnectionManager connectionManager = 
            PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .setMaxConnTotal(100)
                .setMaxConnPerRoute(20)
                .build();
        
        // HTTP Client
        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();
        
        // RestTemplate configurado
        HttpComponentsClientHttpRequestFactory requestFactory = 
            new HttpComponentsClientHttpRequestFactory(httpClient);
        requestFactory.setConnectTimeout(5000);
        
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        
        // Interceptor para forzar HTTPS
        restTemplate.getInterceptors().add((request, body, execution) -> {
            if (!"https".equals(request.getURI().getScheme())) {
                throw new IllegalStateException(
                    "Solo se permiten conexiones HTTPS. Intento: " + request.getURI()
                );
            }
            return execution.execute(request, body);
        });
        
        return restTemplate;
    }
    
    private KeyStore loadKeyStore(Resource resource, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(resource.getInputStream(), password.toCharArray());
        return keyStore;
    }
}

// 3. Actualizar application.properties
server.ssl.enabled=true
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2
server.ssl.ciphers=TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256
server.ssl.trust-store-password=trustOAuth
server.ssl.trust-store-type=PKCS12

// 4. Crear filtro para rechazar conexiones HTTP
@Component
@Order(0)
public class HttpsEnforcementFilter extends OncePerRequestFilter {
    
    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        if (sslEnabled && !request.isSecure()) {
            String httpsUrl = "https://" + 
                             request.getServerName() + 
                             ":" + request.getServerPort() + 
                             request.getRequestURI();
            
            log.warn("Petición HTTP bloqueada, redirigiendo a HTTPS: {}", httpsUrl);
            
            response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
            response.setHeader("Location", httpsUrl);
            return;
        }
        
        chain.doFilter(request, response);
    }
}
```

---

### ID 10: Todo consumo a una API deberá ser mediante HTTPS
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java`
- **Archivo:** `WebConfig.java`
- **Archivo:** `application.properties`

**Problema específico:**
```properties
# application.properties - Puerto HTTPS configurado
server.port=9054
eureka.instance.secure-port-enabled=true
eureka.instance.non-secure-port-enabled=false  # ✅ HTTP deshabilitado

# ⚠️ Falta: HSTS headers
# ⚠️ Falta: Forzar canal seguro en Spring Security
# ⚠️ Falta: Validación de TLS version
```

```java
// WebConfig.java - CORS permite cualquier origen sin validar HTTPS
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")  // ⚠️ Permite HTTP y HTTPS
                .allowedMethods("POST");
    }
}

// SecurityConfig.java - No fuerza HTTPS
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(/* ... */)
            .csrf(AbstractHttpConfigurer::disable);
    // ⚠️ FALTA: .requiresChannel(channel -> channel.anyRequest().requiresSecure())
    // ⚠️ FALTA: HSTS headers
}
```

**Falta implementar:**
- Headers HSTS (HTTP Strict Transport Security)
- Forzar canal seguro en Spring Security
- Validación de protocolo TLS
- CORS solo para orígenes HTTPS

**Solución requerida:**
```java
// 1. Modificar SecurityConfig con HSTS y canal seguro
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/error", "/.well-known/**").permitAll()
            .requestMatchers("/api/token").permitAll()
            .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            
            // ✅ Headers de seguridad
            .headers(headers -> headers
                // HSTS - Forzar HTTPS por 1 año
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                    .preload(true)
                )
                .frameOptions(frame -> frame.deny())
                .contentTypeOptions(Customizer.withDefaults())
                .xssProtection(xss -> xss
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; upgrade-insecure-requests;")
                )
            )
            
            // ✅ Requerir canal seguro (HTTPS)
            .requiresChannel(channel -> channel
                .anyRequest().requiresSecure()
            );

    return http.build();
}

// 2. Modificar WebConfig para CORS seguro
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${cors.allowed.origins:https://localhost:9100,https://localhost:9054}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)  // ✅ Solo HTTPS
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("Authorization", "Content-Type")
                .allowCredentials(true)
                .maxAge(3600);
    }
    
    @PostConstruct
    public void validateCorsOrigins() {
        for (String origin : allowedOrigins) {
            if (!origin.startsWith("https://")) {
                throw new IllegalArgumentException(
                    "Origen CORS debe usar HTTPS: " + origin
                );
            }
        }
    }
}

// 3. Actualizar application.properties
# HTTPS obligatorio
server.ssl.enabled=true
server.ssl.key-store=classpath:oauthserver-keystore.p12
server.ssl.key-store-password=keyOAuth
server.ssl.key-store-type=PKCS12
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2
server.ssl.ciphers=TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256

# CORS - Solo HTTPS
cors.allowed.origins=https://localhost:9100,https://api-gateway:9200

// 4. Crear filtro de validación HTTPS
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class HttpsOnlyFilter extends OncePerRequestFilter {
    
    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        if (sslEnabled && !request.isSecure()) {
            String httpsUrl = "https://" + 
                             request.getServerName() + 
                             ":" + request.getServerPort() + 
                             request.getRequestURI();
            
            log.warn("Petición HTTP bloqueada: {}", request.getRequestURI());
            
            response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
            response.setHeader("Location", httpsUrl);
            response.getWriter().write(
                "{\"error\":\"HTTPS required\",\"redirect\":\"" + httpsUrl + "\"}"
            );
            return;
        }
        
        chain.doFilter(request, response);
    }
}

// 5. Configurar redirección HTTP → HTTPS (opcional)
@Configuration
public class HttpToHttpsRedirectConfig {
    
    @Value("${server.http.port:9053}")
    private int httpPort;
    
    @Value("${server.port:9054}")
    private int httpsPort;
    
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        
        tomcat.addAdditionalTomcatConnectors(httpConnector());
        return tomcat;
    }
    
    private Connector httpConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("http");
        connector.setPort(httpPort);
        connector.setSecure(false);
        connector.setRedirectPort(httpsPort);
        return connector;
    }
}
```

---

## Resumen Consolidado de Severidades (ID 5-10)

| ID | Requisito | Estado | Severidad | Impacto |
|----|-----------|--------|-----------|---------|
| 5 | Acotar longitud de datos | ❌ No implementado | 🔴 **ALTA** | DoS y buffer overflow |
| 6 | Mecanismos de autorización | ❌ No implementado | 🔴🔴 **CRÍTICA** | Acceso no autorizado |
| 7 | GUID aleatorio | ⚠️ Parcial | 🟡 **MEDIA** | Falta jti/nonce en JWT |
| 8 | Validación por roles CRUD | ❌ No implementado | 🔴🔴 **CRÍTICA** | Sin control de operaciones sensibles |
| 9 | Canales cifrados backend | ⚠️ Parcial | 🔴 **ALTA** | MitM attacks |
| 10 | HTTPS obligatorio | ⚠️ Parcial | 🔴 **ALTA** | Comunicaciones sin cifrar |

## Prioridad de Corrección

### 🔴🔴 **CRÍTICAS - Corregir INMEDIATAMENTE**
1. **ID 6:** Implementar sistema de autorización completo
2. **ID 8:** Crear control de acceso basado en roles para CRUD

### 🔴 **ALTAS - Bloquean producción**
3. **ID 5:** Agregar validación de longitud con Bean Validation
4. **ID 9:** Configurar RestTemplate con SSL/TLS seguro
5. **ID 10:** Forzar HTTPS con HSTS y canal seguro

### 🟡 **MEDIAS - Mejorar antes de producción**
6. **ID 7:** Agregar jti y nonce a todos los JWTs

**Estado Global: CRÍTICO - NO APTO PARA PRODUCCIÓN** ⛔

**Compliance: 0/6 requisitos cumplidos (0%)**

```java
import jakarta.validation.constraints.*;

@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode
public class OauthTokenRequest {
    
    @Schema(description="ClientId que se utiliza en la boveda de Cyberark")
    @NotBlank(message = "Client ID is required")
    @Size(min = 5, max = 100, message = "Client ID must be between 5 and 100 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Client ID contains invalid characters")
    private String clientId;
    
    @Schema(description="Secret guardado en la boveda de Cyberark")
    @NotBlank(message = "Client secret is required")
    @Size(min = 32, max = 512, message = "Client secret must be between 32 and 512 characters")
    private String clientSecret;
    
    @Schema(description="Grant type según RFC 6749")
    @NotBlank(message = "Grant type is required")
    @Pattern(regexp = "^(client_credentials|authorization_code|refresh_token|password)$",
             message = "Invalid grant type")
    private String grantType;
    
    @Schema(description="Scopes del ClientId")
    @NotNull(message = "Scopes are required")
    @Size(min = 1, max = 10, message = "Scopes must contain between 1 and 10 elements")
    private List<@NotBlank @Size(max = 50) @Pattern(regexp = "^[a-z:_-]+$") String> scopes;
}
```

**2. Modificar TokenController para validar:**

```java
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    RegisteredClientRepository registeredClientRepository;

    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request,
                                      BindingResult bindingResult) {
        
        // Validar errores de Bean Validation
        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            for (FieldError error : bindingResult.getFieldErrors()) {
                errors.put(error.getField(), error.getDefaultMessage());
            }
            return ResponseEntity.badRequest().body(Map.of(
                "error", "invalid_request",
                "error_description", "Validation failed",
                "details", errors
            ));
        }
        
        // Validación adicional de tamaño del request completo
        if (calculateRequestSize(request) > 4096) { // 4KB max
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(Map.of("error", "Request size exceeds maximum allowed"));
        }
        
        // Resto del código existente...
    }
    
    private long calculateRequestSize(OauthTokenRequest request) {
        return request.getClientId().length() + 
               request.getClientSecret().length() +
               request.getScopes().stream().mapToInt(String::length).sum();
    }
}
```

**3. Agregar configuración global en application.properties:**

```properties
# Límites de request
server.max-http-request-header-size=16KB
spring.servlet.multipart.max-file-size=1MB
spring.servlet.multipart.max-request-size=1MB
server.tomcat.max-swallow-size=2MB
server.tomcat.max-http-form-post-size=2MB
```

**4. Agregar dependencia de validación en pom.xml:**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

### Impacto:
- ✅ Previene buffer overflow
- ✅ Protege contra DoS por consumo de memoria
- ✅ Valida formato de datos
- ✅ Mejora performance y estabilidad

---

## ID 6: Implementar mecanismos de autorización para validar si el cliente autenticado tiene permitido realizar la acción o información solicitada
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

### Ubicación del problema:
- **Archivo:** `TokenController.java` (líneas 30-62)
- **Archivo:** `SecurityConfig.java`

### Problema específico:

```java
// TokenController.java - Solo valida credenciales, NO autorización
@PostMapping("/token")
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    RegisteredClient registeredClient = registeredClientRepository.findByClientId(request.getClientId());

    // ✅ Autenticación (validar identidad)
    if (registeredClient == null ||
        !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid client credentials");
    }

    // ❌ FALTA: Autorización (validar permisos)
    // - ¿Este cliente puede solicitar estos scopes?
    // - ¿Este cliente tiene acceso a estas APIs?
    // - ¿El cliente tiene rol apropiado para esta operación?

    // Genera JWT con TODOS los scopes sin validar autorización
    JwtClaimsSet claims = JwtClaimsSet.builder()
            .claim("scope", String.join(" ", registeredClient.getScopes()))
            .build();
}
```

### Solución requerida:

**1. Crear sistema de autorización:**

```java
package com.eglobal.sicarem.oauth2.servidor.authorization;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Set;

@Service
public class AuthorizationService {
    
    /**
     * Valida si el cliente tiene autorización para los scopes solicitados
     */
    public AuthorizationResult validateScopeAuthorization(
            RegisteredClient client, 
            List<String> requestedScopes) {
        
        Set<String> allowedScopes = client.getScopes();
        
        // Validar que TODOS los scopes solicitados estén permitidos
        for (String scope : requestedScopes) {
            if (!allowedScopes.contains(scope)) {
                return AuthorizationResult.denied(
                    "insufficient_scope",
                    "Client is not authorized for scope: " + scope
                );
            }
        }
        
        return AuthorizationResult.allowed();
    }
    
    /**
     * Valida si el cliente tiene autorización basada en roles
     */
    public AuthorizationResult validateRoleAuthorization(
            RegisteredClient client,
            String requiredRole) {
        
        // Extraer roles del cliente (desde metadata o claims)
        Set<String> clientRoles = extractClientRoles(client);
        
        if (!clientRoles.contains(requiredRole)) {
            return AuthorizationResult.denied(
                "access_denied",
                "Client does not have required role: " + requiredRole
            );
        }
        
        return AuthorizationResult.allowed();
    }
    
    /**
     * Valida autorización basada en recursos/endpoints específicos
     */
    public AuthorizationResult validateResourceAuthorization(
            RegisteredClient client,
            String resource,
            String action) {
        
        // Verificar en metadata del cliente o base de datos
        Map<String, Set<String>> resourcePermissions = 
            getClientResourcePermissions(client.getClientId());
        
        Set<String> allowedActions = resourcePermissions.get(resource);
        
        if (allowedActions == null || !allowedActions.contains(action)) {
            return AuthorizationResult.denied(
                "access_denied",
                String.format("Client not authorized for %s on %s", action, resource)
            );
        }
        
        return AuthorizationResult.allowed();
    }
    
    private Set<String> extractClientRoles(RegisteredClient client) {
        // Implementar extracción de roles desde client settings o metadata
        return client.getClientSettings().getSetting("roles");
    }
    
    private Map<String, Set<String>> getClientResourcePermissions(String clientId) {
        // Implementar consulta de permisos desde BD o cache
        // Ejemplo: {"api-gateway": ["read", "write"], "resource-server": ["read"]}
        return Map.of();
    }
}

// Clase de resultado
@Data
public class AuthorizationResult {
    private boolean allowed;
    private String errorCode;
    private String errorDescription;
    
    public static AuthorizationResult allowed() {
        AuthorizationResult result = new AuthorizationResult();
        result.setAllowed(true);
        return result;
    }
    
    public static AuthorizationResult denied(String code, String description) {
        AuthorizationResult result = new AuthorizationResult();
        result.setAllowed(false);
        result.setErrorCode(code);
        result.setErrorDescription(description);
        return result;
    }
}
```

**2. Modificar TokenController con autorización:**

```java
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    RegisteredClientRepository registeredClientRepository;
    
    @Autowired
    AuthorizationService authorizationService;

    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request,
                                      BindingResult bindingResult) {
        
        // 1. AUTENTICACIÓN - Validar identidad del cliente
        RegisteredClient registeredClient = 
            registeredClientRepository.findByClientId(request.getClientId());

        if (registeredClient == null ||
            !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_client"));
        }

        // 2. AUTORIZACIÓN - Validar permisos del cliente
        
        // 2.1 Validar scopes solicitados
        AuthorizationResult scopeAuth = authorizationService
            .validateScopeAuthorization(registeredClient, request.getScopes());
        
        if (!scopeAuth.isAllowed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                    "error", scopeAuth.getErrorCode(),
                    "error_description", scopeAuth.getErrorDescription()
                ));
        }
        
        // 2.2 Validar grant type permitido para este cliente
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(new AuthorizationGrantType(request.getGrantType()))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                    "error", "unauthorized_grant_type",
                    "error_description", "Client not authorized for this grant type"
                ));
        }
        
        // 2.3 Validar rol del cliente (ejemplo: solo ADMIN puede solicitar scopes admin:*)
        for (String scope : request.getScopes()) {
            if (scope.startsWith("admin:")) {
                AuthorizationResult roleAuth = authorizationService
                    .validateRoleAuthorization(registeredClient, "ROLE_ADMIN");
                
                if (!roleAuth.isAllowed()) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of(
                            "error", "insufficient_permissions",
                            "error_description", "Admin scopes require ROLE_ADMIN"
                        ));
                }
            }
        }

        // 3. Generar token con scopes AUTORIZADOS únicamente
        Instant now = Instant.now();
        Instant expiresAt = now.plus(1, ChronoUnit.HOURS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://localhost:9054")
                .subject(request.getClientId())
                .audience(List.of("api-gateway", "resource-server"))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("scope", String.join(" ", request.getScopes())) // Solo scopes autorizados
                .claim("client_roles", extractClientRoles(registeredClient))
                .claim("jti", UUID.randomUUID().toString()) // JWT ID único
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        return ResponseEntity.ok(Map.of(
                "access_token", jwt.getTokenValue(),
                "token_type", "Bearer",
                "expires_in", ChronoUnit.SECONDS.between(now, expiresAt),
                "scope", String.join(" ", request.getScopes())
        ));
    }
    
    private Set<String> extractClientRoles(RegisteredClient client) {
        return client.getClientSettings().getSetting("roles");
    }
}
```

**3. Crear interceptor para validación en recursos:**

```java
package com.eglobal.sicarem.oauth2.servidor.interceptor;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {
    
    @Autowired
    private AuthorizationService authorizationService;
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                           HttpServletResponse response, 
                           Object handler) throws Exception {
        
        // Extraer JWT del header Authorization
        String token = extractToken(request);
        if (token == null) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return false;
        }
        
        // Decodificar JWT y extraer claims
        Jwt jwt = parseJwt(token);
        String clientId = jwt.getSubject();
        List<String> scopes = Arrays.asList(jwt.getClaimAsString("scope").split(" "));
        
        // Determinar recurso y acción solicitada
        String resource = extractResource(request);
        String action = extractAction(request);
        
        // Validar autorización
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        AuthorizationResult result = authorizationService
            .validateResourceAuthorization(client, resource, action);
        
        if (!result.isAllowed()) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write(result.getErrorDescription());
            return false;
        }
        
        return true;
    }
}
```

### Impacto:
- ✅ Separación clara entre autenticación y autorización
- ✅ Control granular de permisos por scope, rol y recurso
- ✅ Previene escalación de privilegios
- ✅ Cumple principio de menor privilegio

---

## ID 7: La generación de GUID (IDENTIFICADOR ÚNICO GLOBAL) debe ser totalmente aleatoria y no proveer signos de un patrón
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🟡 SEVERIDAD MEDIA**

### Ubicación verificada:
- **Archivo:** `SecurityConfig.java` (línea 136)
- **Archivo:** `TokenController.java` (falta implementación)

### Análisis actual:

```java
// SecurityConfig.java - Uso correcto de UUID
private RSAKey generateRSAKey() {
    KeyPair keyPair = generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
           .privateKey(privateKey)
           .keyID(UUID.randomUUID().toString())  // ✅ UUID v4 - Criptográficamente fuerte
           .build();
}
```

### Verificación de UUID.randomUUID():
- ✅ Usa UUID versión 4 (random)
- ✅ Utiliza `SecureRandom` internamente (Java 21)
- ✅ 122 bits de entropía
- ✅ Criptográficamente seguro

### Problema identificado:

```java
// TokenController.java - JWT NO incluye jti (JWT ID)
JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("https://localhost:9054")
        .subject(request.getClientId())
        // ... otros claims
        // ❌ FALTA: .claim("jti", UUID.randomUUID().toString())
        .build();
```

### Solución requerida:

**1. Agregar jti a todos los JWTs:**

```java
@PostMapping("/token")
public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
    // ... validaciones previas
    
    JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("https://localhost:9054")
            .subject(request.getClientId())
            .audience(List.of("api-gateway", "resource-server"))
            .issuedAt(now)
            .expiresAt(expiresAt)
            .claim("scope", String.join(" ", request.getScopes()))
            .claim("jti", UUID.randomUUID().toString())  // ✅ JWT ID único
            .build();
    
    // ... resto del código
}
```

**2. Si se requiere mayor entropía, usar SecureRandom explícitamente:**

```java
package com.eglobal.sicarem.oauth2.servidor.util;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SecureIdentifierGenerator {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * Genera un identificador único usando UUID v4
     * (Suficiente para la mayoría de casos)
     */
    public String generateUUID() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Genera un identificador de alta entropía usando SecureRandom
     * Útil para tokens, secrets, nonces
     */
    public String generateSecureToken(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    /**
     * Genera nonce para prevenir replay attacks
     */
    public String generateNonce() {
        return generateSecureToken(32); // 256 bits de entropía
    }
    
    /**
     * Genera client secret seguro
     */
    public String generateClientSecret() {
        return generateSecureToken(64); // 512 bits
    }
}
```

**3. Usar el generador en TokenController:**

```java
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    private SecureIdentifierGenerator idGenerator;
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        // ... validaciones
        
        String jti = idGenerator.generateUUID();
        String nonce = idGenerator.generateNonce();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .claim("jti", jti)       // ✅ Identificador único
                .claim("nonce", nonce)   // ✅ Para prevenir replay
                // ... otros claims
                .build();
    }
}
```

### ❌ Anti-patrones a evitar:

```java
// ❌ NUNCA usar patrones predecibles
String badId = System.currentTimeMillis() + "-" + request.getClientId(); // Predecible
String badId2 = "TOKEN-" + counter++; // Secuencial
String badId3 = MD5(clientId + timestamp); // Puede ser forzado
```

### Impacto:
- ✅ GUIDs imposibles de predecir
- ✅ No hay patrones detectables
- ✅ Previene ataques de adivinación
- ✅ Cumple estándares criptográficos

---

## ID 8: Todas las funciones sensibles como creación, modificación o eliminación de datos deberán ser validadas considerando el grupo de usuarios y su rol
**❌ NO IMPLEMENTADO**
**🔴🔴 SEVERIDAD CRÍTICA**

### Ubicación del problema:
- **Archivo:** `SecurityConfig.java` (líneas 97-104)
- **Sistema de roles:** Inexistente más allá de ROLE_USER básico

### Problema específico:

```java
// SecurityConfig.java - Solo un usuario sin roles diferenciados
@Bean
UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withUsername("user")
            .password("{noop}user")
            .authorities("ROLE_USER")  // ⚠️ Un solo rol genérico
            .build();
    return new InMemoryUserDetailsManager(userDetails);
}
```

### Falta completamente:
1. **Sistema de roles diferenciados** (ADMIN, USER, VIEWER, etc.)
2. **Control de acceso basado en roles (RBAC)**
3. **Validación de operaciones CRUD por rol**
4. **Auditoría de operaciones sensibles**

### Solución requerida:

**1. Definir estructura de roles y permisos:**

```java
package com.eglobal.sicarem.oauth2.servidor.security;

public enum Permission {
    // Permisos de lectura
    CLIENT_READ("client:read"),
    TOKEN_READ("token:read"),
    
    // Permisos de escritura
    CLIENT_CREATE("client:create"),
    CLIENT_UPDATE("client:update"),
    CLIENT_DELETE("client:delete"),
    
    // Permisos de administración
    SECRET_ROTATE("secret:rotate"),
    TOKEN_REVOKE("token:revoke"),
    AUDIT_VIEW("audit:view");
    
    private final String permission;
    
    Permission(String permission) {
        this.permission = permission;
    }
    
    public String getPermission() {
        return permission;
    }
}

public enum Role {
    VIEWER(Set.of(
        Permission.CLIENT_READ,
        Permission.TOKEN_READ
    )),
    
    USER(Set.of(
        Permission.CLIENT_READ,
        Permission.TOKEN_READ,
        Permission.CLIENT_CREATE
    )),
    
    ADMIN(Set.of(
        Permission.CLIENT_READ,
        Permission.CLIENT_CREATE,
        Permission.CLIENT_UPDATE,
        Permission.CLIENT_DELETE,
        Permission.SECRET_ROTATE,
        Permission.TOKEN_REVOKE,
        Permission.AUDIT_VIEW
    ));
    
    private final Set<Permission> permissions;
    
    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }
    
    public Set<Permission> getPermissions() {
        return permissions;
    }
    
    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        
        this.permissions.forEach(permission -> 
            authorities.add(new SimpleGrantedAuthority(permission.getPermission()))
        );
        
        return authorities;
    }
}
```

**2. Modificar SecurityConfig con múltiples roles:**

```java
@Bean
UserDetailsService userDetailsService() {
    // Usuario viewer - solo lectura
    UserDetails viewer = User.withUsername("viewer")
            .password("{noop}viewer123")
            .authorities(Role.VIEWER.getGrantedAuthorities().toArray(new GrantedAuthority[0]))
            .build();
    
    // Usuario normal - lectura y creación
    UserDetails normalUser = User.withUsername("user")
            .password("{noop}user123")
            .authorities(Role.USER.getGrantedAuthorities().toArray(new GrantedAuthority[0]))
            .build();
    
    // Administrador - todos los permisos
    UserDetails admin = User.withUsername("admin")
            .password("{noop}admin123")
            .authorities(Role.ADMIN.getGrantedAuthorities().toArray(new GrantedAuthority[0]))
            .build();
    
    return new InMemoryUserDetailsManager(viewer, normalUser, admin);
}

@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            // Endpoints públicos
            .requestMatchers("/login", "/error", "/.well-known/**").permitAll()
            
            // Tokens - requiere autenticación
            .requestMatchers(HttpMethod.POST, "/api/token").authenticated()
            
            // Operaciones de lectura - VIEWER+
            .requestMatchers(HttpMethod.GET, "/api/clients/**").hasAnyRole("VIEWER", "USER", "ADMIN")
            
            // Creación - USER+
            .requestMatchers(HttpMethod.POST, "/api/clients/**").hasAnyRole("USER", "ADMIN")
            
            // Modificación - ADMIN only
            .requestMatchers(HttpMethod.PUT, "/api/clients/**").hasRole("ADMIN")
            .requestMatchers(HttpMethod.PATCH, "/api/clients/**").hasRole("ADMIN")
            
            // Eliminación - ADMIN only
            .requestMatchers(HttpMethod.DELETE, "/api/clients/**").hasRole("ADMIN")
            
            // Operaciones sensibles - ADMIN only
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/*/revoke").hasRole("ADMIN")
            .requestMatchers("/api/*/rotate").hasRole("ADMIN")
            
            .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);

    return http.build();
}
```

**3. Crear controlador administrativo con validación de roles:**

```java
package com.eglobal.sicarem.oauth2.servidor.controller;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")  // ✅ Solo administradores
public class AdminController {
    
    @Autowired
    private RegisteredClientRepository clientRepository;
    
    @Autowired
    private AuditService auditService;
    
    /**
     * Rotar client secret - Operación SENSIBLE
     */
    @PostMapping("/clients/{clientId}/rotate-secret")
    @PreAuthorize("hasAuthority('secret:rotate')")  // ✅ Permiso específico
    public ResponseEntity<?> rotateClientSecret(
            @PathVariable String clientId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        // Auditar quién realiza la operación
        auditService.logSensitiveOperation(
            "SECRET_ROTATION",
            clientId,
            userDetails.getUsername(),
            "Rotating client secret"
        );
        
        // Validar que el cliente existe
        RegisteredClient client = clientRepository.findByClientId(clientId);
        if (client == null) {
            return ResponseEntity.notFound().build();
        }
        
        // Generar nuevo secret
        String newSecret = generateSecureSecret();
        
        // Actualizar en repositorio
        // ... lógica de actualización
        
        // Auditar éxito
        auditService.logSuccess("SECRET_ROTATION", clientId, userDetails.getUsername());
        
        return ResponseEntity.ok(Map.of(
            "client_id", clientId,
            "rotated_at", Instant.now(),
            "rotated_by", userDetails.getUsername()
        ));
    }
    
    /**
     * Eliminar cliente - Operación SENSIBLE
     */
    @DeleteMapping("/clients/{clientId}")
    @PreAuthorize("hasAuthority('client:delete')")
    public ResponseEntity<?> deleteClient(
            @PathVariable String clientId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid DeletionRequest request) {
        
        // Auditar operación destructiva
        auditService.logSensitiveOperation(
            "CLIENT_DELETION",
            clientId,
            userDetails.getUsername(),
            request.getReason()
        );
        
        // Validar razón de eliminación
        if (request.getReason() == null || request.getReason().isEmpty()) {
            return ResponseEntity.badRequest()
                .body("Deletion reason is required for sensitive operations");
        }
        
        // Revocar todos los tokens del cliente
        tokenService.revokeAllTokensForClient(clientId);
        
        // Eliminar cliente
        clientRepository.deleteById(clientId);
        
        // Auditar éxito
        auditService.logSuccess("CLIENT_DELETION", clientId, userDetails.getUsername());
        
        return ResponseEntity.ok(Map.of(
            "deleted", true,
            "client_id", clientId,
            "deleted_by", userDetails.getUsername(),
            "deleted_at", Instant.now()
        ));
    }
}
```

**4. Crear servicio de auditoría:**

```java
package com.eglobal.sicarem.oauth2.servidor.service;

@Service
public class AuditService {
    
    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    
    /**
     * Registra operaciones sensibles
     */
    public void logSensitiveOperation(String operation, 
                                     String resourceId, 
                                     String username,
                                     String details) {
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Instant.now())
            .operation(operation)
            .resourceId(resourceId)
            .username(username)
            .details(details)
            .ipAddress(getCurrentRequestIP())
            .userAgent(getCurrentRequestUserAgent())
            .build();
        
        // Guardar en base de datos
        auditRepository.save(auditLog);
        
        // Log estructurado
        log.warn("SENSITIVE_OPERATION: operation={}, resource={}, user={}, ip={}", 
                 operation, resourceId, username, auditLog.getIpAddress());
    }
    
    /**
     * Registra operaciones exitosas
     */
    public void logSuccess(String operation, String resourceId, String username) {
        log.info("OPERATION_SUCCESS: operation={}, resource={}, user={}", 
                 operation, resourceId, username);
    }
    
    /**
     * Registra intentos fallidos (potencial ataque)
     */
    public void logFailure(String operation, String resourceId, String username, String reason) {
        log.error("OPERATION_FAILED: operation={}, resource={}, user={}, reason={}", 
                  operation, resourceId, username, reason);
        
        // Alertar si hay intentos repetidos
        checkForSuspiciousActivity(username, operation);
    }
}
```

**5. Agregar Method Security:**

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
    // Habilita @PreAuthorize, @PostAuthorize, @Secured
}
```

### Impacto:
- ✅ Control granular de operaciones sensibles
- ✅ Segregación de funciones por rol
- ✅ Auditoría completa de operaciones CRUD
- ✅ Previene escalación de privilegios
- ✅ Cumple principio de menor privilegio

---

## ID 9: Todo acceso desde la API hacia el backend debe ser mediante canales cifrados
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

### Ubicación verificada:
- **Archivo:** `application.properties`
- **Archivo:** `MainConfiguration.java`

### Análisis actual:

```properties
# application.properties - SSL configurado para servidor
server.ssl.trust-store=classpath:oauthserver-truststore.p12
server.ssl.trust-store-p=trustOAuth
eureka.instance.secure-port-enabled=true
eureka.instance.secure-port=9054

# ✅ Eureka usa HTTPS
eureka.client.serviceUrl.defaultZone=https://localhost:9100/eureka/
```

### Problema identificado:

```java
// MainConfiguration.java - RestTemplate sin configuración SSL explícita
@Configuration
public class MainConfiguration {

    @Bean("clienteRestBalanced")
    @LoadBalanced
    public RestTemplate getRestTemplateBalanced() {
        return new RestTemplate();  // ⚠️ No configura SSL/TLS explícitamente
    }
}
```

### Riesgos:
1. RestTemplate podría aceptar certificados auto-firmados sin validación
2. No hay verificación de hostname
3. Posible downgrade attack a HTTP
4. No hay configuración de TLS 1.3

### Solución requerida:

**1. Configurar RestTemplate con SSL seguro:**

```java
package com.eglobal.sicarem.oauth2.servidor;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.security.KeyStore;

@Configuration
public class MainConfiguration {

    @Value("${server.ssl.trust-store}")
    private Resource trustStore;
    
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @Bean("clienteRestBalanced")
    @LoadBalanced
    public RestTemplate getRestTemplateBalanced() throws Exception {
        // Configurar SSL Context con truststore
        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial(
                    loadKeyStore(trustStore, trustStorePassword),
                    null  // No usar TrustSelfSignedStrategy en producción
                )
                .setProtocol("TLSv1.3")  // ✅ Forzar TLS 1.3
                .build();
        
        // Configurar SSL Socket Factory con verificación de hostname
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[]{"TLSv1.3", "TLSv1.2"},  // Protocolos permitidos
                null,  // Usar cipher suites por defecto (seguros)
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()  // ✅ Verificar hostname
        );
        
        // Connection Manager con SSL
        PoolingHttpClientConnectionManager connectionManager = 
            PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .setMaxConnTotal(100)
                .setMaxConnPerRoute(20)
                .build();
        
        // HTTP Client configurado
        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();
        
        // RestTemplate con HTTP Client configurado
        HttpComponentsClientHttpRequestFactory requestFactory = 
            new HttpComponentsClientHttpRequestFactory(httpClient);
        requestFactory.setConnectTimeout(5000);
        requestFactory.setConnectionRequestTimeout(5000);
        
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        
        // Interceptor para forzar HTTPS
        restTemplate.getInterceptors().add((request, body, execution) -> {
            if (!"https".equals(request.getURI().getScheme())) {
                throw new IllegalStateException(
                    "Only HTTPS connections are allowed. Attempted: " + request.getURI()
                );
            }
            return execution.execute(request, body);
        });
        
        return restTemplate;
    }
    
    private KeyStore loadKeyStore(Resource resource, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(resource.getInputStream(), password.toCharArray());
        return keyStore;
    }
}
```

**2. Actualizar application.properties:**

```properties
# Configuración SSL/TLS
server.ssl.enabled=true
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2
server.ssl.ciphers=TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256

# Truststore
server.ssl.trust-store=classpath:oauthserver-truststore.p12
server.ssl.trust-store-password=trustOAuth
server.ssl.trust-store-type=PKCS12

# Keystore (para mTLS si es necesario)
server.ssl.key-store=classpath:oauthserver-keystore.p12
server.ssl.key-store-password=keyOAuth
server.ssl.key-store-type=PKCS12

# Cliente SSL - Validación estricta
server.ssl.client-auth=want  # 'need' para mTLS obligatorio
```

**3. Agregar dependencia de Apache HttpClient 5:**

```xml
<dependency>
    <groupId>org.apache.httpcomponents.client5</groupId>
    <artifactId>httpclient5</artifactId>
</dependency>
```

**4. Crear filtro para rechazar conexiones HTTP:**

```java
@Component
@Order(0)
public class HttpsEnforcementFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Verificar que la conexión sea HTTPS
        if (!request.isSecure()) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write(
                "{\"error\":\"HTTPS required\",\"message\":\"Only HTTPS connections are allowed\"}"
            );
            return;
        }
        
        // Validar protocolo TLS
        String protocol = (String) request.getAttribute("jakarta.servlet.request.ssl_session.protocol");
        if (protocol != null && !protocol.startsWith("TLSv1.")) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("{\"error\":\"Unsupported TLS protocol\"}");
            return;
        }
        
        chain.doFilter(request, response);
    }
}
```

### Impacto:
- ✅ Todas las comunicaciones cifradas con TLS 1.3/1.2
- ✅ Verificación de certificados y hostname
- ✅ Previene man-in-the-middle attacks
- ✅ No permite downgrade a HTTP

---

## ID 10: Todo consumo a una API deberá ser mediante HTTPS
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

### Ubicación verificada:
- **Archivo:** `application.properties` (línea 10)
- **Archivo:** `SecurityConfig.java`

### Análisis actual:

```properties
# application.properties
server.port=9054  # ✅ Puerto HTTPS configurado

eureka.instance.secure-port-enabled=true
eureka.instance.secure-port=9054
eureka.instance.non-secure-port-enabled=false  # ✅ HTTP deshabilitado
```

### Problemas identificados:

1. **No hay redirección HTTP → HTTPS**
2. **No hay validación de HSTS (HTTP Strict Transport Security)**
3. **WebConfig permite CORS sin restricción de protocolo**

```java
// WebConfig.java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")  // ⚠️ Permite cualquier origen (incluso HTTP)
                .allowedMethods("POST")
                .allowedHeaders("Content-Type");
    }
}
```

### Solución requerida:

**1. Configurar HTTPS estricto en application.properties:**

```properties
# HTTPS obligatorio
server.port=9054
server.ssl.enabled=true
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2

# Keystore para HTTPS
server.ssl.key-store=classpath:oauthserver-keystore.p12
server.ssl.key-store-password=keyOAuth
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=oauthserver

# Truststore
server.ssl.trust-store=classpath:oauthserver-truststore.p12
server.ssl.trust-store-password=trustOAuth

# Configuración de puerto HTTP para redirección (opcional)
# server.http.port=9053
```

**2. Modificar SecurityConfig para HSTS y HTTPS:**

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/error", "/.well-known/**").permitAll()
                .requestMatchers("/api/token").permitAll()
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            
            // ✅ Configuración de seguridad de headers
            .headers(headers -> headers
                // HSTS - Forzar HTTPS por 1 año
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                    .preload(true)
                )
                // X-Frame-Options
                .frameOptions(frame -> frame.deny())
                // X-Content-Type-Options
                .contentTypeOptions(Customizer.withDefaults())
                // X-XSS-Protection
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                // Content Security Policy
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; form-action 'self'; upgrade-insecure-requests;")
                )
                // Referrer Policy
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
            )
            
            // ✅ Requerir canal seguro (HTTPS)
            .requiresChannel(channel -> channel
                .anyRequest().requiresSecure()
            );

        return http.build();
    }
}
```

**3. Modificar WebConfig para CORS seguro:**

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${cors.allowed.origins:https://localhost:9100,https://localhost:9054}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)  // ✅ Solo orígenes HTTPS específicos
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("Authorization", "Content-Type", "X-Requested-With")
                .exposedHeaders("X-Total-Count", "X-Page-Number")
                .allowCredentials(true)  // ✅ Habilitar credenciales
                .maxAge(3600);
    }
    
    /**
     * Validar que los orígenes permitidos sean HTTPS
     */
    @PostConstruct
    public void validateCorsOrigins() {
        for (String origin : allowedOrigins) {
            if (!origin.startsWith("https://")) {
                throw new IllegalArgumentException(
                    "CORS origin must use HTTPS: " + origin
                );
            }
        }
    }
}
```

**4. Crear filtro de validación HTTPS:**

```java
package com.eglobal.sicarem.oauth2.servidor.filter;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class HttpsOnlyFilter extends OncePerRequestFilter {
    
    private static final Logger log = LoggerFactory.getLogger(HttpsOnlyFilter.class);
    
    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Si SSL está habilitado, validar que la petición sea HTTPS
        if (sslEnabled && !request.isSecure()) {
            
            // Construir URL HTTPS
            String httpsUrl = "https://" + 
                             request.getServerName() + 
                             ":" + request.getServerPort() + 
                             request.getRequestURI();
            
            if (request.getQueryString() != null) {
                httpsUrl += "?" + request.getQueryString();
            }
            
            log.warn("HTTP request blocked, redirecting to HTTPS: {}", httpsUrl);
            
            // Redireccionar a HTTPS
            response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
            response.setHeader("Location", httpsUrl);
            response.getWriter().write(
                "{\"error\":\"HTTPS required\",\"redirect\":\"" + httpsUrl + "\"}"
            );
            return;
        }
        
        // Validar protocolo TLS
        if (request.isSecure()) {
            Object tlsVersion = request.getAttribute("jakarta.servlet.request.ssl_session_id");
            log.debug("Secure connection established: TLS version info available");
        }
        
        chain.doFilter(request, response);
    }
}
```

**5. Configurar redirección HTTP → HTTPS (opcional):**

```java
@Configuration
public class HttpToHttpsRedirectConfig {
    
    @Value("${server.http.port:9053}")
    private int httpPort;
    
    @Value("${server.port:9054}")
    private int httpsPort;
    
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        
        // Agregar conector HTTP para redirección
        tomcat.addAdditionalTomcatConnectors(httpConnector());
        return tomcat;
    }
    
    private Connector httpConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("http");
        connector.setPort(httpPort);
        connector.setSecure(false);
        connector.setRedirectPort(httpsPort);
        return connector;
    }
}
```

**6. Actualizar application.properties:**

```properties
# HTTPS obligatorio
server.ssl.enabled=true

# Configuración CORS - Solo HTTPS
cors.allowed.origins=https://localhost:9100,https://api-gateway:9200

# Headers de seguridad
server.ssl.ciphers=TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2

# Logging de seguridad
logging.level.org.springframework.security.web.header=DEBUG
```

**7. Validación en tests:**

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HttpsEnforcementTest {
    
    @LocalServerPort
    private int port;
    
    @Test
    void shouldRejectHttpRequests() {
        // Intentar conexión HTTP
        assertThrows(Exception.class, () -> {
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getForEntity("http://localhost:" + port + "/api/token", String.class);
        });
    }
    
    @Test
    void shouldAcceptHttpsRequests() throws Exception {
        // Configurar RestTemplate con SSL
        RestTemplate restTemplate = createSslRestTemplate();
        
        ResponseEntity<String> response = restTemplate.getForEntity(
            "https://localhost:" + port + "/actuator/health", 
            String.class
        );
        
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
```

### Impacto:
- ✅ Todo tráfico forzado a HTTPS
- ✅ HSTS habilitado (1 año con subdomains)
- ✅ Redirección automática HTTP → HTTPS
- ✅ Validación de TLS 1.3/1.2
- ✅ CORS solo permite orígenes HTTPS
- ✅ Headers de seguridad completos

---

## Resumen Consolidado - Requisitos ID 5-10

| ID | Requisito | Estado | Severidad | Prioridad |
|----|-----------|--------|-----------|-----------|
| **5** | **Acotar longitud de datos** | **❌ No implementado** | **🔴 ALTA** | **Inmediato** |
| **6** | **Mecanismos de autorización** | **❌ No implementado** | **🔴🔴 CRÍTICA** | **Urgente** |
| **7** | **GUID aleatorio** | **⚠️ Parcial** | **🟡 MEDIA** | **Alta** |
| **8** | **Validación por roles CRUD** | **❌ No implementado** | **🔴🔴 CRÍTICA** | **Urgente** |
| **9** | **Canales cifrados backend** | **⚠️ Parcial** | **🔴 ALTA** | **Inmediato** |
| **10** | **HTTPS obligatorio** | **⚠️ Parcial** | **🔴 ALTA** | **Inmediato** |

## 🚨 Acciones Críticas Requeridas - Priorización

### **URGENTE - Implementar INMEDIATAMENTE** (Severidad Crítica):

1. **ID 6 - Sistema de Autorización:**
   - Crear `AuthorizationService` con validación de scopes, roles y recursos
   - Implementar RBAC en `SecurityConfig`
   - Agregar validación en `TokenController`
   - **Impacto:** Sin esto, cualquier cliente autenticado puede acceder a cualquier recurso

2. **ID 8 - Validación por Roles en Operaciones CRUD:**
   - Definir roles (VIEWER, USER, ADMIN) con permisos específicos
   - Crear `AdminController` con `@PreAuthorize`
   - Implementar `AuditService` para operaciones sensibles
   - **Impacto:** Operaciones críticas sin control de acceso

### **ALTA - Implementar ANTES de Producción** (Severidad Alta):

3. **ID 5 - Límites de Longitud:**
   - Agregar Bean Validation a DTOs
   - Implementar validación en controllers
   - Configurar límites globales
   - **Impacto:** Vulnerable a DoS y buffer overflow

4. **ID 9 - Cifrado Backend:**
   - Configurar RestTemplate con SSL/TLS 1.3
   - Validar certificados y hostname
   - Agregar interceptor anti-downgrade
   - **Impacto:** Man-in-the-middle attacks

5. **ID 10 - HTTPS Obligatorio:**
   - Configurar HSTS headers
   - Forzar canal seguro en Spring Security
   - Modificar CORS para solo HTTPS
   - Crear filtro de validación HTTPS
   - **Impacto:** Comunicaciones sin cifrar

### **MEDIA - Completar para Hardening** (Severidad Media):

6. **ID 7 - GUID Aleatorio:**
   - Agregar `jti` y `nonce` a JWTs
   - Crear `SecureIdentifierGenerator`
   - **Impacto:** Menor, ya usa UUID v4

## 📊 Estado Global del Sistema

### Compliance Actual:
- **Requisitos Cumplidos:** 0/6 (0%)
- **Parcialmente Implementados:** 3/6 (50%)
- **No Implementados:** 3/6 (50%)

### Bloqueadores de Producción:
- ❌ No hay sistema de autorización (ID 6)
- ❌ No hay control de roles para CRUD (ID 8)
- ❌ Sin validación de longitud de datos (ID 5)
- ⚠️ Cifrado de backend incompleto (ID 9)
- ⚠️ HTTPS sin forzar completamente (ID 10)

### Recomendación Final:
**🔴 NO APTO PARA PRODUCCIÓN**

El sistema requiere implementación urgente de:
1. Sistema de autorización completo
2. Control de acceso basado en roles
3. Validación de datos y límites
4. Endurecimiento de HTTPS y cifrado

**Tiempo estimado de corrección:** 2-3 sprints para implementar todos los requisitos críticos.

---