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

## Análisis Detallado de Requisitos de Seguridad (Acceso/Consumo IDs 11-12, Perfilado, Sesión/Expiración)

---

## ACCESO / CONSUMO

### ID 11: Configurar la cookie SameSite
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Configurar la propiedad SameSite en cookies HTTP para prevenir ataques de falsificación de solicitud entre sitios (CSRF).

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java`
- **Archivo:** `application.properties`
- **No existe configuración de cookies**

**Problema específico:**
```java
// SecurityConfig.java - CSRF deshabilitado sin alternativa
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(/* ... */)
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable); // ⚠️ CSRF deshabilitado
    // ⚠️ No hay configuración de SameSite en cookies
    // ⚠️ No hay gestión de sesiones con cookies seguras
    return http.build();
}
```

```properties
# application.properties - Sin configuración de cookies
# ⚠️ FALTA: Configuración de cookies SameSite
# ⚠️ FALTA: Configuración de cookies HttpOnly
# ⚠️ FALTA: Configuración de cookies Secure
```

**Problemas identificados:**
1. CSRF completamente deshabilitado sin mitigación alternativa
2. No hay configuración de atributo SameSite en cookies
3. No hay configuración de cookies HttpOnly y Secure
4. Vulnerable a ataques CSRF en flujos con autenticación

**Solución requerida:**

```java
// 1. Modificar SecurityConfig para habilitar CSRF con SameSite
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
        
        // ✅ Habilitar CSRF con configuración personalizada
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers("/api/token") // Solo para endpoint OAuth2
        )
        
        // ✅ Configuración de sesiones con cookies seguras
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false)
        );

    return http.build();
}

// 2. Crear configurador personalizado de cookies
@Configuration
public class CookieConfig {
    
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        
        // ✅ Configurar SameSite
        serializer.setSameSite("Strict"); // Strict, Lax, o None
        
        // ✅ Configurar cookies seguras
        serializer.setUseSecureCookie(true); // Solo HTTPS
        serializer.setUseHttpOnlyCookie(true); // No accesible desde JavaScript
        
        // Configuración adicional
        serializer.setCookieName("JSESSIONID");
        serializer.setCookiePath("/");
        serializer.setDomainNamePattern("^.+?\\.(\\w+\\.[a-z]+)$");
        
        return serializer;
    }
}

// 3. Configurar en application.properties
server.servlet.session.cookie.same-site=strict
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.max-age=3600
server.servlet.session.cookie.name=OAUTH_SESSION
server.servlet.session.timeout=20m

// 4. Para APIs REST sin estado, usar CSRF con tokens en headers
@Configuration
public class CsrfSecurityConfig {
    
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieCustomizer(cookie -> cookie
            .sameSite("Strict")
            .secure(true)
            .httpOnly(true)
            .path("/")
        );
        return repository;
    }
}

// 5. Si se usa OAuth2 sin sesiones, implementar protección alternativa
@Component
public class CsrfTokenFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Para APIs REST stateless, validar custom header
        String csrfHeader = request.getHeader("X-CSRF-Token");
        String csrfCookie = getCsrfCookieValue(request);
        
        if (isProtectedMethod(request.getMethod())) {
            if (csrfHeader == null || !csrfHeader.equals(csrfCookie)) {
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write("{\"error\":\"CSRF token missing or invalid\"}");
                return;
            }
        }
        
        chain.doFilter(request, response);
    }
    
    private boolean isProtectedMethod(String method) {
        return !method.equals("GET") && 
               !method.equals("HEAD") && 
               !method.equals("OPTIONS");
    }
    
    private String getCsrfCookieValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("XSRF-TOKEN".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}

// 6. Agregar dependencias necesarias
// En pom.xml
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-core</artifactId>
</dependency>
```

**Opciones de configuración SameSite:**

```java
// Strict: La cookie NO se envía en requests cross-site
serializer.setSameSite("Strict"); 
// Mejor protección, pero puede romper funcionalidad legítima

// Lax: La cookie se envía en navegación top-level GET
serializer.setSameSite("Lax");
// Balance entre seguridad y usabilidad (recomendado)

// None: La cookie se envía en todos los requests (requiere Secure)
serializer.setSameSite("None");
serializer.setUseSecureCookie(true); // Obligatorio con None
// Solo si necesitas funcionalidad cross-site explícita
```

**Evidencias requeridas según documento:**
- **Opc1:** Configuración del navegador mostrando cookie con atributo SameSite
- **Opc2:** Captura de Postman/navegador con headers de cookies
- **Opc3:** Código fuente de configuración de cookies

**Notas importantes:**
- Para OAuth2 client credentials flow (sin sesión), SameSite es menos relevante
- Para authorization code flow o password flow, es CRÍTICO
- El proyecto actual usa principalmente client credentials (stateless)

---

### ID 12: El uso de métodos HTTP como PUT o DELETE deben ser sustituidos por POST
**⚠️ NO APLICA ACTUALMENTE / PENDIENTE IMPLEMENTACIÓN**
**🟡 SEVERIDAD MEDIA**

**Descripción del requisito:**
Sustituir métodos HTTP PUT y DELETE por POST para todas las operaciones.

**Ubicación verificada:**
- **Archivo:** `TokenController.java`
- **No existen otros controllers públicos**

**Análisis actual:**
```java
// TokenController.java - Solo usa POST
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @PostMapping("/token")  // ✅ Ya usa POST
    public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
        // ...
    }
}

// SecurityConfig.java - No restringe métodos adicionales
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/token").permitAll()  // ⚠️ Permite todos los métodos
            .anyRequest().authenticated())
        // ...
}
```

**Estado actual:**
- ✅ El único endpoint público (`/api/token`) ya usa POST
- ⚠️ No hay restricción explícita de métodos PUT/DELETE
- ⚠️ Endpoints futuros podrían usar PUT/DELETE sin control

**Problemas potenciales:**
1. No hay validación de métodos HTTP permitidos
2. PUT/DELETE podrían ser habilitados accidentalmente
3. Sin documentación de política de métodos HTTP

**Solución requerida:**

```java
// 1. Restringir métodos HTTP en SecurityConfig
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            // Permitir solo GET y POST
            .requestMatchers(HttpMethod.GET, "/actuator/**", "/error").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/token", "/login").permitAll()
            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // CORS preflight
            
            // Denegar explícitamente PUT, DELETE, PATCH, HEAD
            .requestMatchers(HttpMethod.PUT, "/**").denyAll()
            .requestMatchers(HttpMethod.DELETE, "/**").denyAll()
            .requestMatchers(HttpMethod.PATCH, "/**").denyAll()
            .requestMatchers(HttpMethod.HEAD, "/**").denyAll()
            
            .anyRequest().authenticated())
        // ...
        
        return http.build();
}

// 2. Crear filtro personalizado para validar métodos
@Component
@Order(0)
public class HttpMethodValidationFilter extends OncePerRequestFilter {
    
    private static final Set<String> ALLOWED_METHODS = Set.of("GET", "POST", "OPTIONS");
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        String method = request.getMethod();
        
        // Validar método HTTP
        if (!ALLOWED_METHODS.contains(method)) {
            log.warn("Método HTTP no permitido: {} desde {}", 
                    method, request.getRemoteAddr());
            
            response.setStatus(HttpStatus.METHOD_NOT_ALLOWED.value());
            response.setHeader("Allow", "GET, POST, OPTIONS");
            response.getWriter().write(
                "{\"error\":\"method_not_allowed\"," +
                "\"message\":\"Solo GET y POST están permitidos\"," +
                "\"allowed_methods\":[\"GET\",\"POST\",\"OPTIONS\"]}"
            );
            return;
        }
        
        chain.doFilter(request, response);
    }
}

// 3. Si necesitas operaciones tipo UPDATE/DELETE, usar POST con acción
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    // ❌ Evitar esto
    // @PutMapping("/clients/{id}")
    // @DeleteMapping("/clients/{id}")
    
    // ✅ Usar esto en su lugar
    @PostMapping("/clients/{id}/update")
    public ResponseEntity<?> updateClient(@PathVariable String id, 
                                         @RequestBody ClientUpdateRequest request) {
        // Lógica de actualización
        return ResponseEntity.ok(/* ... */);
    }
    
    @PostMapping("/clients/{id}/delete")
    public ResponseEntity<?> deleteClient(@PathVariable String id) {
        // Lógica de eliminación
        return ResponseEntity.ok(Map.of("deleted", true));
    }
    
    // O usar un campo "action" en el body
    @PostMapping("/clients/{id}")
    public ResponseEntity<?> manageClient(@PathVariable String id,
                                         @RequestBody ClientActionRequest request) {
        switch (request.getAction()) {
            case "update":
                return updateClientInternal(id, request);
            case "delete":
                return deleteClientInternal(id);
            default:
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "invalid_action"));
        }
    }
}

// 4. Configurar Tomcat para deshabilitar métodos
// En application.properties
server.tomcat.relaxed-query-chars=<,>,[,\,],^,`,{,|}
server.tomcat.reject-illegal-header=true

# Deshabilitar métodos no deseados a nivel de Tomcat
server.allowed-methods=GET,POST,OPTIONS

// 5. Documentar en Swagger las restricciones
@Configuration
public class OpenApiConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("OAuth2 Authorization Server API")
                .version("1.0")
                .description("**Métodos HTTP permitidos:** GET, POST, OPTIONS\n\n" +
                            "**Métodos bloqueados:** PUT, DELETE, PATCH, HEAD"))
            .servers(List.of(
                new Server().url("https://localhost:9054")
            ));
    }
}
```

**Justificación del requisito:**
1. **Seguridad en Firewalls:** Algunos firewalls bloquean PUT/DELETE
2. **Simplificación:** Menos métodos = menor superficie de ataque
3. **Compatibilidad:** Mejor soporte en proxies y balanceadores
4. **Auditoría:** Más fácil de auditar con menos métodos

**Evidencias requeridas según documento:**
- **Opc1:** Configuración del postmapping en código
- **Opc2:** Capturas de Postman con peticiones mostrando que se utiliza POST
- **Opc3:** Captura de error al intentar usar PUT/DELETE

**Nota importante:**
Si el cliente solicita explícitamente usar PUT/DELETE por estándares REST, documentar la justificación y obtener aprobación por escrito.

---

## PERFILADO DE API / AUTORIZACIÓN

### ID 1: El perfilado de una API refiere al control de acceso entre el cliente/consumidor y la API - Esquema de 6 pasos
**❌ NO IMPLEMENTADO COMPLETAMENTE**
**🔴🔴 SEVERIDAD CRÍTICA**

**Descripción del requisito:**
Implementar un esquema de control de acceso de 6 pasos para validar permisos entre cliente y API.

**Esquema de 6 pasos propuesto:**

**Paso 1:** Cliente envía credenciales (client_id, client_secret, scope)
**Paso 2:** Servidor valida credenciales y genera token de acceso
**Paso 3:** Cliente envía token en cada request a la API
**Paso 4:** API valida el token
**Paso 5:** API valida que el scope del token incluye el permiso necesario
**Paso 6:** API procesa la solicitud y retorna respuesta

**Ubicación del problema:**
- **Archivo:** `TokenController.java` (Pasos 1-2 parcialmente implementados)
- **Archivo:** `SecurityConfig.java` (Pasos 3-6 no implementados)
- **No existe middleware de validación de scopes**

**Análisis por paso:**

```java
// ===== PASO 1: Cliente envía credenciales =====
// ✅ IMPLEMENTADO PARCIALMENTE en TokenController

@PostMapping("/token")
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    // ✅ Recibe client_id, client_secret, scopes
    RegisteredClient registeredClient = 
        registeredClientRepository.findByClientId(request.getClientId());
}

// ❌ FALTA: Validación estructural del request
// ❌ FALTA: Validación de grant_type
// ❌ FALTA: Logging de intentos de autenticación

// ===== PASO 2: Servidor valida y genera token =====
// ⚠️ PARCIALMENTE IMPLEMENTADO

// ✅ Valida credenciales básicas
if (registeredClient == null ||
    !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body("Invalid client credentials");
}

// ❌ FALTA: Validar que scopes solicitados están permitidos
// ❌ FALTA: Validar grant_type autorizado para el cliente
// ❌ FALTA: Generar jti y nonce

JwtClaimsSet claims = JwtClaimsSet.builder()
        .claim("scope", String.join(" ", registeredClient.getScopes()))
        // ❌ FALTA: jti, nonce, roles, permisos
        .build();

// ===== PASO 3: Cliente envía token en request =====
// ❌ NO IMPLEMENTADO - No hay endpoints protegidos aún

// ===== PASO 4: API valida el token =====
// ❌ NO IMPLEMENTADO - No hay validación JWT en endpoints

// ===== PASO 5: API valida scopes =====
// ❌ NO IMPLEMENTADO - No hay validación de scopes

// ===== PASO 6: API procesa y retorna =====
// ❌ NO IMPLEMENTADO - No hay endpoints de negocio
```

**Solución requerida - Implementación completa de 6 pasos:**

```java
// ========================================
// PASO 1: Recibir y validar credenciales
// ========================================

@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    private AuthenticationService authService;
    
    @Autowired
    private AuditService auditService;
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request,
                                      BindingResult bindingResult,
                                      HttpServletRequest httpRequest) {
        
        // ✅ PASO 1.1: Validar estructura del request
        if (bindingResult.hasErrors()) {
            auditService.logFailedAuthentication(
                request.getClientId(), 
                "invalid_request_structure",
                httpRequest.getRemoteAddr()
            );
            return ResponseEntity.badRequest().body(Map.of(
                "error", "invalid_request",
                "error_description", "Request validation failed"
            ));
        }
        
        // ✅ PASO 1.2: Validar grant_type
        if (!"client_credentials".equals(request.getGrantType())) {
            auditService.logFailedAuthentication(
                request.getClientId(),
                "unsupported_grant_type",
                httpRequest.getRemoteAddr()
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "unsupported_grant_type",
                "error_description", "Solo client_credentials es soportado"
            ));
        }
        
        // Continuar al Paso 2...
    }
}

// ========================================
// PASO 2: Validar credenciales y generar token
// ========================================

@Service
public class AuthenticationService {
    
    @Autowired
    private RegisteredClientRepository clientRepository;
    
    @Autowired
    private JwtEncoder jwtEncoder;
    
    @Autowired
    private SecureIdentifierGenerator idGenerator;
    
    public TokenResponse authenticateAndGenerateToken(OauthTokenRequest request) {
        
        // ✅ PASO 2.1: Validar client_id existe
        RegisteredClient client = clientRepository.findByClientId(request.getClientId());
        if (client == null) {
            throw new InvalidClientException("Cliente no encontrado");
        }
        
        // ✅ PASO 2.2: Validar client_secret
        if (!client.getClientSecret().equals("{noop}" + request.getClientSecret())) {
            throw new InvalidClientException("Credenciales inválidas");
        }
        
        // ✅ PASO 2.3: Validar scopes solicitados vs permitidos
        Set<String> allowedScopes = client.getScopes();
        for (String requestedScope : request.getScopes()) {
            if (!allowedScopes.contains(requestedScope)) {
                throw new InsufficientScopeException(
                    "Scope no autorizado: " + requestedScope
                );
            }
        }
        
        // ✅ PASO 2.4: Generar token con todos los claims necesarios
        Instant now = Instant.now();
        Instant expiresAt = now.plus(1, ChronoUnit.HOURS);
        
        String jti = idGenerator.generateUUID();
        String nonce = idGenerator.generateNonce();
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://localhost:9054")
                .subject(request.getClientId())
                .audience(List.of("api-gateway", "resource-server"))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("scope", String.join(" ", request.getScopes()))
                .claim("jti", jti)  // ✅ JWT ID único
                .claim("nonce", nonce)  // ✅ Prevenir replay
                .claim("client_id", request.getClientId())
                .build();
        
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));
        
        return new TokenResponse(
            jwt.getTokenValue(),
            "Bearer",
            ChronoUnit.SECONDS.between(now, expiresAt),
            String.join(" ", request.getScopes())
        );
    }
}

// ========================================
// PASO 3: Cliente envía token en headers
// ========================================

// Documentar en API docs cómo enviar el token:
// Authorization: Bearer <token>

// ========================================
// PASO 4: API valida el token
// ========================================

@Component
public class JwtValidationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtDecoder jwtDecoder;
    
    @Autowired
    private TokenBlacklistService blacklistService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Extraer token del header
        String token = extractToken(request);
        
        if (token == null && requiresAuthentication(request)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("{\"error\":\"missing_token\"}");
            return;
        }
        
        if (token != null) {
            try {
                // ✅ PASO 4.1: Decodificar y validar firma
                Jwt jwt = jwtDecoder.decode(token);
                
                // ✅ PASO 4.2: Validar expiración
                if (jwt.getExpiresAt().isBefore(Instant.now())) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write("{\"error\":\"token_expired\"}");
                    return;
                }
                
                // ✅ PASO 4.3: Validar jti no está en blacklist
                String jti = jwt.getClaimAsString("jti");
                if (blacklistService.isRevoked(jti)) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write("{\"error\":\"token_revoked\"}");
                    return;
                }
                
                // ✅ PASO 4.4: Guardar JWT en contexto
                request.setAttribute("jwt", jwt);
                request.setAttribute("client_id", jwt.getSubject());
                request.setAttribute("scopes", jwt.getClaimAsString("scope").split(" "));
                
            } catch (JwtException e) {
                log.error("Token inválido: {}", e.getMessage());
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write("{\"error\":\"invalid_token\"}");
                return;
            }
        }
        
        chain.doFilter(request, response);
    }
    
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
    
    private boolean requiresAuthentication(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.equals("/api/token") && 
               !path.equals("/login") && 
               !path.startsWith("/error");
    }
}

// ========================================
// PASO 5: API valida scopes
// ========================================

@Component
public class ScopeValidationInterceptor implements HandlerInterceptor {
    
    @Override
    public boolean preHandle(HttpServletRequest request,
                           HttpServletResponse response,
                           Object handler) throws Exception {
        
        // Obtener scopes del token
        String[] tokenScopes = (String[]) request.getAttribute("scopes");
        
        if (tokenScopes == null) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("{\"error\":\"no_scopes_in_token\"}");
            return false;
        }
        
        // Determinar scope requerido para el endpoint
        String requiredScope = determineRequiredScope(request);
        
        // ✅ PASO 5.1: Validar que el token tiene el scope requerido
        boolean hasScope = Arrays.asList(tokenScopes).contains(requiredScope);
        
        if (!hasScope) {
            log.warn("Acceso denegado: scope requerido '{}', scopes disponibles: {}", 
                    requiredScope, Arrays.toString(tokenScopes));
            
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write(String.format(
                "{\"error\":\"insufficient_scope\"," +
                "\"error_description\":\"Scope requerido: %s\"," +
                "\"scopes_available\":%s}",
                requiredScope, Arrays.toString(tokenScopes)
            ));
            return false;
        }
        
        return true;
    }
    
    private String determineRequiredScope(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        // Mapeo de endpoints a scopes requeridos
        if (path.startsWith("/api/clients")) {
            if ("GET".equals(method)) return "client:read";
            if ("POST".equals(method)) return "client:create";
            if ("PUT".equals(method)) return "client:update";
            if ("DELETE".equals(method)) return "client:delete";
        }
        
        if (path.startsWith("/api/admin")) {
            return "admin:manage";
        }
        
        return "api:access"; // Scope default
    }
}

// ========================================
// PASO 6: API procesa y retorna respuesta
// ========================================

@RestController
@RequestMapping("/api/clients")
public class ClientController {
    
    @Autowired
    private ClientService clientService;
    
    @Autowired
    private AuditService auditService;
    
    // ✅ PASO 6: Procesar request autorizado
    @GetMapping("/{clientId}")
    public ResponseEntity<?> getClient(@PathVariable String clientId,
                                      HttpServletRequest request) {
        
        // En este punto, el token ya fue validado (Paso 4)
        // y los scopes fueron verificados (Paso 5)
        
        String requestingClientId = (String) request.getAttribute("client_id");
        
        // ✅ PASO 6.1: Ejecutar lógica de negocio
        Client client = clientService.findById(clientId);
        
        if (client == null) {
            return ResponseEntity.notFound().build();
        }
        
        // ✅ PASO 6.2: Validar autorización adicional (si necesario)
        if (!requestingClientId.equals(clientId) && 
            !hasAdminScope(request)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Solo puedes ver tu propio perfil"));
        }
        
        // ✅ PASO 6.3: Auditar acceso
        auditService.logResourceAccess(
            requestingClientId,
            "GET /api/clients/" + clientId,
            "success"
        );
        
        // ✅ PASO 6.4: Retornar respuesta
        return ResponseEntity.ok(client);
    }
    
    private boolean hasAdminScope(HttpServletRequest request) {
        String[] scopes = (String[]) request.getAttribute("scopes");
        return scopes != null && Arrays.asList(scopes).contains("admin:manage");
    }
}

// ========================================
// Configuración WebMvc para registrar interceptores
// ========================================

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Autowired
    private ScopeValidationInterceptor scopeInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(scopeInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/token", "/login", "/error");
    }
}
```

**Diagrama del esquema de 6 pasos:**

```
┌─────────────┐                                      ┌──────────────────┐
│   Cliente   │                                      │ OAuth2 Server    │
│ (Aplicación)│                                      │  (TokenController)│
└──────┬──────┘                                      └────────┬─────────┘
       │                                                      │
       │ PASO 1: POST /token                                 │
       │ { client_id, client_secret, scope, grant_type }     │
       ├─────────────────────────────────────────────────────>│
       │                                                      │
       │                      PASO 2: Validar credenciales   │
       │                             Validar scopes          │
       │                             Generar JWT con jti     │
       │                                                      │
       │         PASO 2: Response 200 OK                     │
       │         { access_token, token_type, expires_in }    │
       │<─────────────────────────────────────────────────────┤
       │                                                      │
       │                                                      │
       │                                      ┌───────────────┴─────────┐
       │                                      │    API Resource         │
       │ PASO 3: GET /api/clients            │    (ClientController)    │
       │ Authorization: Bearer <token>        └───────────────┬─────────┘
       ├─────────────────────────────────────────────────────>│
       │                                                      │
       │                      PASO 4: Validar token JWT      │
       │                              Verificar firma        │
       │                              Verificar expiración   │
       │                              Verificar blacklist    │
       │                                                      │
       │                      PASO 5: Validar scopes         │
       │                              Verificar permisos     │
       │                              Verificar autorización │
       │                                                      │
       │                      PASO 6: Procesar request       │
       │                              Ejecutar lógica        │
       │                              Auditar acceso         │
       │                                                      │
       │         Response 200 OK                             │
       │         { data... }                                 │
       │<─────────────────────────────────────────────────────┤
       │                                                      │
```

**Evidencias requeridas según documento:**

**Paso 1:** Captura donde se vea client_id, secret_id, scope. Mostrar estructura del JWT
**Paso 2:** Código donde se valida el token. Mostrar JWT y su configuración
**Paso 3:** Postman del token de acceso mostrando longitud
**Paso 4:** Código o BD donde está configurado y error que regresa
**Paso 5:** Mensaje de error cuando token es inválido
**Paso 6:** Log y postman de la respuesta

---

## SESIÓN / EXPIRACIÓN

### ID 1: Para flujos de baja transaccionalidad, el consumo debe ser por sesión la cual se limita a 20 minutos
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Para APIs de baja transaccionalidad, configurar sesiones con timeout de 20 minutos.

**Ubicación del problema:**
- **Archivo:** `TokenController.java` (línea 48)
- **Archivo:** `SecurityConfig.java`
- **Archivo:** `application.properties`

**Problema específico:**
```java
// TokenController.java - Token válido por 1 HORA (no 20 minutos)
Instant now = Instant.now();
Instant expiresAt = now.plus(1, ChronoUnit.HOURS); // ⚠️ 60 minutos, no 20

JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuedAt(now)
        .expiresAt(expiresAt)  // ⚠️ Expiración incorrecta
        .build();
```

```properties
# application.properties - Sin configuración de timeout de sesión
# ⚠️ FALTA: Configuración de session timeout
# ⚠️ FALTA: Diferenciación entre alta y baja transaccionalidad
```

```java
// SecurityConfig.java - Sin gestión de sesiones
@Bean
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(/* ... */)
        // ⚠️ FALTA: Configuración de sessionManagement
        .csrf(AbstractHttpConfigurer::disable);
}
```

**Problemas identificados:**
1. Token de acceso válido por 60 minutos (debería ser 20)
2. No hay diferenciación entre flujos de alta/baja transaccionalidad
3. No hay configuración de timeout de sesión
4. No hay renovación automática de sesiones

**Solución requerida:**

```java
// 1. Crear enum para tipos de transaccionalidad
public enum TransactionType {
    LOW("low", 20, ChronoUnit.MINUTES),      // Baja: 20 minutos
    HIGH("high", 1, ChronoUnit.DAYS);        // Alta: 1 día
    
    private final String type;
    private final long duration;
    private final ChronoUnit unit;
    
    TransactionType(String type, long duration, ChronoUnit unit) {
        this.type = type;
        this.duration = duration;
        this.unit = unit;
    }
    
    public Instant calculateExpiration(Instant from) {
        return from.plus(duration, unit);
    }
}

// 2. Modificar OauthTokenRequest para incluir tipo de transacción
@Data
public class OauthTokenRequest {
    private String clientId;
    private String clientSecret;
    private String grantType;
    private List<String> scopes;
    
    @Schema(description = "Tipo de transaccionalidad: low o high")
    @Pattern(regexp = "^(low|high)$", message = "Debe ser 'low' o 'high'")
    private String transactionType = "low"; // ✅ Default: baja transaccionalidad
}

// 3. Modificar TokenController para usar timeout correcto
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        
        // Validaciones previas...
        
        Instant now = Instant.now();
        
        // ✅ Determinar expiración según tipo de transaccionalidad
        TransactionType txType = "high".equals(request.getTransactionType()) 
            ? TransactionType.HIGH 
            : TransactionType.LOW;
        
        Instant expiresAt = txType.calculateExpiration(now);
        
        long expiresInSeconds = ChronoUnit.SECONDS.between(now, expiresAt);
        
        log.info("Generando token para cliente {} con tipo {} (expira en {} segundos)",
                request.getClientId(), txType, expiresInSeconds);
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://localhost:9054")
                .subject(request.getClientId())
                .audience(List.of("api-gateway", "resource-server"))
                .issuedAt(now)
                .expiresAt(expiresAt)  // ✅ 20 minutos o 1 día
                .claim("scope", String.join(" ", request.getScopes()))
                .claim("jti", UUID.randomUUID().toString())
                .claim("transaction_type", txType.name())  // ✅ Guardar tipo
                .build();
        
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));
        
        return ResponseEntity.ok(Map.of(
                "access_token", jwt.getTokenValue(),
                "token_type", "Bearer",
                "expires_in", expiresInSeconds,  // ✅ 1200 seg (20 min) o 86400 seg (1 día)
                "scope", String.join(" ", request.getScopes()),
                "transaction_type", txType.name()
        ));
    }
}

// 4. Configurar gestión de sesiones en SecurityConfig
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(/* ... */)
        
        // ✅ Configuración de sesiones
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .invalidSessionUrl("/login?expired=true")
            .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .expiredUrl("/login?expired=true")
        );
    
    return http.build();
}

// 5. Configurar en application.properties
# Sesión para flujos de baja transaccionalidad
server.servlet.session.timeout=20m
server.servlet.session.cookie.max-age=1200

# Configuración de tokens
oauth2.token.low-transaction.expiration=20m
oauth2.token.high-transaction.expiration=1d

// 6. Crear servicio para validar expiración
@Service
public class SessionValidationService {
    
    public boolean isTokenExpired(Jwt jwt) {
        Instant expiresAt = jwt.getExpiresAt();
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
    
    public boolean shouldRenewToken(Jwt jwt) {
        Instant expiresAt = jwt.getExpiresAt();
        Instant now = Instant.now();
        
        // Renovar si quedan menos de 5 minutos
        long minutesRemaining = ChronoUnit.MINUTES.between(now, expiresAt);
        return minutesRemaining < 5;
    }
    
    public String getTransactionType(Jwt jwt) {
        return jwt.getClaimAsString("transaction_type");
    }
}

// 7. Crear filtro para validar expiración en cada request
@Component
public class SessionExpirationFilter extends OncePerRequestFilter {
    
    @Autowired
    private SessionValidationService sessionService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        Jwt jwt = (Jwt) request.getAttribute("jwt");
        
        if (jwt != null) {
            // Validar expiración
            if (sessionService.isTokenExpired(jwt)) {
                log.warn("Token expirado para cliente: {}", jwt.getSubject());
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write(
                    "{\"error\":\"token_expired\"," +
                    "\"error_description\":\"El token ha expirado. Solicite uno nuevo.\"}"
                );
                return;
            }
            
            // Advertir si está próximo a expirar
            if (sessionService.shouldRenewToken(jwt)) {
                response.setHeader("X-Token-Expires-Soon", "true");
                response.setHeader("X-Token-Renewal-Recommended", "true");
            }
        }
        
        chain.doFilter(request, response);
    }
}
```

**Tabla de configuración de timeouts:**

| Tipo de Transaccionalidad | Timeout de Token | Uso Recomendado |
|---------------------------|------------------|-----------------|
| **Baja (LOW)** | 20 minutos | APIs de consulta, reportes, operaciones ocasionales |
| **Alta (HIGH)** | 1 día | APIs transaccionales, procesamiento batch, integraciones continuas |

**Evidencias requeridas según documento:**
- Explicación de cómo está implementado
- Indicar si son de alta o baja transaccionalidad
- Captura de Postman con configuración del token mostrando expires_in

---

### ID 2: En el caso de una alta tasa transaccional, la sesión deberá ser por día. Los ataques de replay serán mitigados mediante la cabecera nonce
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Para APIs de alta transaccionalidad, configurar sesión de 1 día y usar nonce en headers para prevenir replay attacks.

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **No hay implementación de nonce en headers**

**Problema específico:**
```java
// TokenController.java - No genera nonce
JwtClaimsSet claims = JwtClaimsSet.builder()
        .expiresAt(expiresAt)
        // ⚠️ FALTA: nonce en JWT
        .build();

// No hay validación de nonce en requests subsecuentes
```

**Solución requerida:**

```java
// 1. Modificar TokenController para incluir nonce
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @Autowired
    private SecureIdentifierGenerator idGenerator;
    
    @Autowired
    private NonceValidationService nonceService;
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        
        // ... validaciones previas
        
        Instant now = Instant.now();
        
        // Determinar tipo de transacción
        TransactionType txType = "high".equals(request.getTransactionType())
            ? TransactionType.HIGH
            : TransactionType.LOW;
        
        Instant expiresAt = txType.calculateExpiration(now);
        
        // ✅ Generar nonce único
        String nonce = idGenerator.generateNonce();
        String jti = idGenerator.generateUUID();
        
        // ✅ Guardar nonce en cache para validación futura
        nonceService.storeNonce(nonce, jti, expiresAt);
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://localhost:9054")
                .subject(request.getClientId())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("scope", String.join(" ", request.getScopes()))
                .claim("jti", jti)
                .claim("nonce", nonce)  // ✅ Incluir nonce
                .claim("transaction_type", txType.name())
                .build();
        
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));
        
        return ResponseEntity.ok(Map.of(
                "access_token", jwt.getTokenValue(),
                "token_type", "Bearer",
                "expires_in", ChronoUnit.SECONDS.between(now, expiresAt),
                "nonce", nonce,  // ✅ Retornar nonce al cliente
                "transaction_type", txType.name()
        ));
    }
}

// 2. Crear servicio de validación de nonce
@Service
public class NonceValidationService {
    
    // Cache de nonces usados (expiración automática)
    private final Cache<String, NonceInfo> nonceCache;
    
    public NonceValidationService() {
        this.nonceCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.DAYS)  // Máximo 1 día
                .maximumSize(100_000)
                .build();
    }
    
    /**
     * Almacenar nonce generado
     */
    public void storeNonce(String nonce, String jti, Instant expiresAt) {
        NonceInfo info = new NonceInfo(jti, false, Instant.now(), expiresAt);
        nonceCache.put(nonce, info);
        log.debug("Nonce almacenado: {} para jti: {}", nonce, jti);
    }
    
    /**
     * Validar que el nonce no ha sido usado (prevenir replay)
     */
    public ValidationResult validateNonce(String nonce, String jti) {
        NonceInfo info = nonceCache.getIfPresent(nonce);
        
        // Nonce no existe = posible replay o token expirado
        if (info == null) {
            log.warn("Nonce no encontrado o expirado: {}", nonce);
            return ValidationResult.invalid("Nonce inválido o expirado");
        }
        
        // Validar que el jti coincida
        if (!info.getJti().equals(jti)) {
            log.error("Nonce válido pero jti no coincide. Posible ataque de replay");
            return ValidationResult.invalid("Token manipulado");
        }
        
        // Validar que no ha sido usado previamente
        if (info.isUsed()) {
            log.error("REPLAY ATTACK DETECTED: Nonce {} ya fue usado", nonce);
            return ValidationResult.replayAttack("Nonce ya fue usado - posible replay attack");
        }
        
        // ✅ Marcar nonce como usado
        info.setUsed(true);
        info.setLastUsedAt(Instant.now());
        nonceCache.put(nonce, info);
        
        log.debug("Nonce validado y marcado como usado: {}", nonce);
        return ValidationResult.valid();
    }
    
    /**
     * Verificar si el nonce ha expirado
     */
    public boolean isExpired(String nonce) {
        NonceInfo info = nonceCache.getIfPresent(nonce);
        return info == null || info.getExpiresAt().isBefore(Instant.now());
    }
}

@Data
class NonceInfo {
    private final String jti;
    private boolean used;
    private Instant createdAt;
    private Instant expiresAt;
    private Instant lastUsedAt;
    
    public NonceInfo(String jti, boolean used, Instant createdAt, Instant expiresAt) {
        this.jti = jti;
        this.used = used;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }
}

@Data
class ValidationResult {
    private final boolean valid;
    private final String errorMessage;
    private final boolean isReplayAttack;
    
    public static ValidationResult valid() {
        return new ValidationResult(true, null, false);
    }
    
    public static ValidationResult invalid(String message) {
        return new ValidationResult(false, message, false);
    }
    
    public static ValidationResult replayAttack(String message) {
        return new ValidationResult(false, message, true);
    }
}

// 3. Crear filtro para validar nonce en cada request
@Component
@Order(2)
public class NonceValidationFilter extends OncePerRequestFilter {
    
    @Autowired
    private NonceValidationService nonceService;
    
    @Autowired
    private SecurityAuditService auditService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Obtener JWT del request
        Jwt jwt = (Jwt) request.getAttribute("jwt");
        
        if (jwt != null) {
            String nonce = jwt.getClaimAsString("nonce");
            String jti = jwt.getClaimAsString("jti");
            String transactionType = jwt.getClaimAsString("transaction_type");
            
            // ✅ Validar nonce para flujos de alta transaccionalidad
            if ("HIGH".equals(transactionType)) {
                
                if (nonce == null || jti == null) {
                    log.error("Token de alta transaccionalidad sin nonce o jti");
                    response.setStatus(HttpStatus.BAD_REQUEST.value());
                    response.getWriter().write(
                        "{\"error\":\"invalid_token\"," +
                        "\"error_description\":\"Token debe incluir nonce y jti\"}"
                    );
                    return;
                }
                
                // Validar nonce
                ValidationResult result = nonceService.validateNonce(nonce, jti);
                
                if (!result.isValid()) {
                    
                    // Si es replay attack, auditar y alertar
                    if (result.isReplayAttack()) {
                        auditService.logReplayAttack(
                            jwt.getSubject(),
                            nonce,
                            jti,
                            request.getRemoteAddr(),
                            request.getRequestURI()
                        );
                        
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        response.getWriter().write(
                            "{\"error\":\"replay_attack_detected\"," +
                            "\"error_description\":\"" + result.getErrorMessage() + "\"}"
                        );
                    } else {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.getWriter().write(
                            "{\"error\":\"invalid_nonce\"," +
                            "\"error_description\":\"" + result.getErrorMessage() + "\"}"
                        );
                    }
                    return;
                }
                
                log.debug("Nonce validado correctamente para request de alta transaccionalidad");
            }
        }
        
        chain.doFilter(request, response);
    }
}

// 4. Servicio de auditoría para replay attacks
@Service
public class SecurityAuditService {
    
    private static final Logger log = LoggerFactory.getLogger(SecurityAuditService.class);
    
    @Autowired
    private AuditRepository auditRepository;
    
    @Autowired
    private AlertService alertService;
    
    public void logReplayAttack(String clientId, String nonce, String jti,
                               String ipAddress, String requestUri) {
        
        SecurityIncident incident = SecurityIncident.builder()
                .timestamp(Instant.now())
                .incidentType("REPLAY_ATTACK")
                .severity("CRITICAL")
                .clientId(clientId)
                .nonce(nonce)
                .jti(jti)
                .sourceIp(ipAddress)
                .requestUri(requestUri)
                .build();
        
        // Guardar en BD
        auditRepository.save(incident);
        
        // Log crítico
        log.error("🚨 REPLAY ATTACK DETECTED: clientId={}, nonce={}, jti={}, ip={}, uri={}",
                 clientId, nonce, jti, ipAddress, requestUri);
        
        // Enviar alerta al equipo de seguridad
        alertService.sendSecurityAlert(incident);
        
        // Considerar bloqueo temporal del cliente
        if (shouldBlockClient(clientId)) {
            blockClientTemporarily(clientId);
        }
    }
    
    private boolean shouldBlockClient(String clientId) {
        // Verificar si hay múltiples intentos de replay
        long recentAttacks = auditRepository.countRecentAttacks(
            clientId, 
            Instant.now().minus(5, ChronoUnit.MINUTES)
        );
        return recentAttacks >= 3; // 3 intentos en 5 minutos = bloqueo
    }
    
    private void blockClientTemporarily(String clientId) {
        log.error("BLOQUEANDO CLIENTE {} por múltiples intentos de replay attack", clientId);
        // Implementar lógica de bloqueo
    }
}

// 5. Documentar uso del nonce para el cliente
/**
 * Para flujos de alta transaccionalidad (transaction_type=high):
 * 
 * 1. El cliente recibe el nonce en la respuesta del token:
 *    {
 *      "access_token": "eyJ...",
 *      "nonce": "abc123...",
 *      "transaction_type": "HIGH"
 *    }
 * 
 * 2. El cliente debe incluir el nonce en CADA request subsecuente:
 *    Authorization: Bearer eyJ...
 *    X-Nonce: abc123...
 * 
 * 3. El servidor valida que:
 *    - El nonce existe
 *    - El nonce corresponde al jti del token
 *    - El nonce NO ha sido usado previamente
 * 
 * 4. Si el nonce ya fue usado = REPLAY ATTACK = request bloqueado
 * 
 * IMPORTANTE: Cada token tiene un nonce único que solo puede usarse UNA VEZ
 */
```

**Configuración de timeouts para alta transaccionalidad:**

```properties
# application.properties

# Alta transaccionalidad: sesión de 1 día
oauth2.token.high-transaction.expiration=1d
oauth2.token.high-transaction.nonce-required=true

# Configuración de cache de nonces
caffeine.cache.nonce.max-size=100000
caffeine.cache.nonce.expire-after-write=1d

# Configuración de alertas de seguridad
security.replay-attack.alert-threshold=3
security.replay-attack.block-duration=30m
```

**Evidencias requeridas según documento:**
- **Opc1:** Captura de Postman mostrando token con nonce
- **Opc2:** Configuración en código del nonce

---

### ID 3: Manejo de excepciones
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Documentar y demostrar el manejo de excepciones de manera estructurada.

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **No existe manejo centralizado de excepciones**

**Problema específico:**
```java
// TokenController.java - Manejo de errores básico sin estructura
@PostMapping("/token")
public ResponseEntity<?> getToken(@RequestBody OauthTokenRequest request) {
    
    if (registeredClient == null || !validSecret) {
        // ⚠️ Respuesta simple sin estructura de error estándar
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body("Invalid client credentials");
    }
    
    // ⚠️ No hay try-catch para excepciones inesperadas
    // ⚠️ No hay logging estructurado de errores
    // ⚠️ No hay códigos de error específicos
}
```

**Problemas identificados:**
1. No hay manejo centralizado de excepciones
2. Respuestas de error inconsistentes
3. No hay logging estructurado de errores
4. Sin códigos de error específicos para cada tipo de falla
5. No se documentan las excepciones posibles

**Solución requerida:**

```java
// 1. Crear estructura estándar de errores
@Data
@Builder
public class ErrorResponse {
    private String error;
    private String errorDescription;
    private String errorCode;
    private Instant timestamp;
    private String path;
    private Integer status;
    private Map<String, String> details;
}

// 2. Crear excepciones personalizadas
public class OAuth2Exception extends RuntimeException {
    private final String errorCode;
    private final HttpStatus httpStatus;
    private final Map<String, String> details;
    
    public OAuth2Exception(String message, String errorCode, HttpStatus status) {
        super(message);
        this.errorCode = errorCode;
        this.httpStatus = status;
        this.details = new HashMap<>();
    }
}

public class InvalidClientException extends OAuth2Exception {
    public InvalidClientException(String message) {
        super(message, "AUTH001", HttpStatus.UNAUTHORIZED);
    }
}

public class InsufficientScopeException extends OAuth2Exception {
    public InsufficientScopeException(String message) {
        super(message, "AUTH002", HttpStatus.FORBIDDEN);
    }
}

public class InvalidGrantTypeException extends OAuth2Exception {
    public InvalidGrantTypeException(String message) {
        super(message, "AUTH003", HttpStatus.BAD_REQUEST);
    }
}

public class TokenExpiredException extends OAuth2Exception {
    public TokenExpiredException(String message) {
        super(message, "AUTH004", HttpStatus.UNAUTHORIZED);
    }
}

public class ReplayAttackException extends OAuth2Exception {
    public ReplayAttackException(String message) {
        super(message, "SEC001", HttpStatus.FORBIDDEN);
    }
}

// 3. Crear manejador global de excepciones
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    /**
     * Manejar excepciones de OAuth2
     */
    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<ErrorResponse> handleOAuth2Exception(
            OAuth2Exception ex,
            HttpServletRequest request) {
        
        log.error("OAuth2 Error [{}]: {} en {}", 
                 ex.getErrorCode(), ex.getMessage(), request.getRequestURI());
        
        ErrorResponse error = ErrorResponse.builder()
                .error(ex.getErrorCode())
                .errorDescription(ex.getMessage())
                .errorCode(ex.getErrorCode())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(ex.getHttpStatus().value())
                .details(ex.getDetails())
                .build();
        
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(error);
    }
    
    /**
     * Manejar errores de validación (Bean Validation)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        
        Map<String, String> validationErrors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
            validationErrors.put(error.getField(), error.getDefaultMessage())
        );
        
        log.warn("Validation error en {}: {}", request.getRequestURI(), validationErrors);
        
        ErrorResponse error = ErrorResponse.builder()
                .error("VAL001")
                .errorDescription("Validación de request fallida")
                .errorCode("VAL001")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(HttpStatus.BAD_REQUEST.value())
                .details(validationErrors)
                .build();
        
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(error);
    }
    
    /**
     * Manejar errores JWT
     */
    @ExceptionHandler({JwtException.class, JwtValidationException.class})
    public ResponseEntity<ErrorResponse> handleJwtException(
            Exception ex,
            HttpServletRequest request) {
        
        log.error("JWT Error en {}: {}", request.getRequestURI(), ex.getMessage());
        
        ErrorResponse error = ErrorResponse.builder()
                .error("AUTH005")
                .errorDescription("Token JWT inválido")
                .errorCode("AUTH005")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(HttpStatus.UNAUTHORIZED.value())
                .build();
        
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(error);
    }
    
    /**
     * Manejar errores de acceso denegado
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {
        
        log.warn("Acceso denegado en {}: {}", request.getRequestURI(), ex.getMessage());
        
        ErrorResponse error = ErrorResponse.builder()
                .error("AUTH006")
                .errorDescription("Acceso denegado")
                .errorCode("AUTH006")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(HttpStatus.FORBIDDEN.value())
                .build();
        
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(error);
    }
    
    /**
     * Manejar errores HTTP genéricos
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex,
            HttpServletRequest request) {
        
        log.warn("Método no soportado en {}: {}", request.getRequestURI(), ex.getMethod());
        
        ErrorResponse error = ErrorResponse.builder()
                .error("HTTP001")
                .errorDescription("Método HTTP no soportado: " + ex.getMethod())
                .errorCode("HTTP001")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(HttpStatus.METHOD_NOT_ALLOWED.value())
                .build();
        
        return ResponseEntity
                .status(HttpStatus.METHOD_NOT_ALLOWED)
                .header("Allow", String.join(", ", ex.getSupportedMethods()))
                .body(error);
    }
    
    /**
     * Manejar cualquier excepción no controlada
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {
        
        log.error("Error inesperado en {}: ", request.getRequestURI(), ex);
        
        ErrorResponse error = ErrorResponse.builder()
                .error("SYS001")
                .errorDescription("Error interno del servidor")
                .errorCode("SYS001")
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();
        
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(error);
    }
}

// 4. Modificar TokenController para usar excepciones
@RestController
@RequestMapping("/api")
public class TokenController {
    
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        
        try {
            // Validar client_id
            RegisteredClient client = 
                registeredClientRepository.findByClientId(request.getClientId());
            
            if (client == null) {
                throw new InvalidClientException("Cliente no encontrado");
            }
            
            // Validar client_secret
            if (!client.getClientSecret().equals("{noop}" + request.getClientSecret())) {
                throw new InvalidClientException("Credenciales inválidas");
            }
            
            // Validar grant_type
            if (!"client_credentials".equals(request.getGrantType())) {
                throw new InvalidGrantTypeException(
                    "Grant type no soportado: " + request.getGrantType()
                );
            }
            
            // Validar scopes
            for (String scope : request.getScopes()) {
                if (!client.getScopes().contains(scope)) {
                    throw new InsufficientScopeException(
                        "Scope no autorizado: " + scope
                    );
                }
            }
            
            // Generar token
            // ...
            
            return ResponseEntity.ok(/* token response */);
            
        } catch (OAuth2Exception e) {
            // Las excepciones OAuth2 serán manejadas por GlobalExceptionHandler
            throw e;
        } catch (Exception e) {
            // Cualquier otra excepción
            log.error("Error inesperado generando token para {}: ", 
                     request.getClientId(), e);
            throw new RuntimeException("Error generando token", e);
        }
    }
}

// 5. Documentar códigos de error
/**
 * CÓDIGOS DE ERROR - OAUTH2 AUTHORIZATION SERVER
 * 
 * Autenticación (AUTH):
 * - AUTH001: Cliente inválido o no encontrado
 * - AUTH002: Scopes insuficientes
 * - AUTH003: Grant type inválido
 * - AUTH004: Token expirado
 * - AUTH005: Token JWT inválido
 * - AUTH006: Acceso denegado
 * 
 * Seguridad (SEC):
 * - SEC001: Replay attack detectado
 * - SEC002: Nonce inválido
 * - SEC003: Cliente bloqueado
 * 
 * Validación (VAL):
 * - VAL001: Validación de request fallida
 * - VAL002: Parámetros requeridos faltantes
 * 
 * HTTP (HTTP):
 * - HTTP001: Método HTTP no soportado
 * - HTTP002: Recurso no encontrado
 * 
 * Sistema (SYS):
 * - SYS001: Error interno del servidor
 * - SYS002: Servicio no disponible
 */
```

**Tabla de excepciones y códigos de error:**

| Código | Excepción | HTTP Status | Descripción | Acción del Cliente |
|--------|-----------|-------------|-------------|--------------------|
| AUTH001 | InvalidClientException | 401 | Cliente no encontrado o credenciales inválidas | Verificar client_id y client_secret |
| AUTH002 | InsufficientScopeException | 403 | Scopes solicitados no autorizados | Solicitar solo scopes permitidos |
| AUTH003 | InvalidGrantTypeException | 400 | Grant type no soportado | Usar client_credentials |
| AUTH004 | TokenExpiredException | 401 | Token ha expirado | Solicitar nuevo token |
| AUTH005 | JwtException | 401 | Token JWT inválido o manipulado | Solicitar nuevo token |
| SEC001 | ReplayAttackException | 403 | Nonce ya fue usado | Solicitar nuevo token |
| VAL001 | ValidationException | 400 | Request no pasa validaciones | Corregir formato del request |

**Evidencias requeridas según documento:**
- **Opc1:** Código fuente del manejo de excepciones
- **Opc2:** Configuración en tablas donde se vean las excepciones
- **Opc3:** Capturas de Postman con diferentes tipos de errores

---

## Resumen Consolidado de Severidades

| Dominio | ID | Requisito | Estado | Severidad | Impacto |
|---------|----|-----------| -------|-----------|---------|
| **Acceso/Consumo** | 11 | Cookie SameSite | ❌ No implementado | 🔴 **ALTA** | Vulnerable a CSRF |
| **Acceso/Consumo** | 12 | Sustituir PUT/DELETE por POST | ⚠️ N/A actualmente | 🟡 **MEDIA** | Sin riesgo actual |
| **Perfilado API** | 1 | Esquema 6 pasos | ❌ No implementado | 🔴🔴 **CRÍTICA** | Sin control de acceso |
| **Sesión** | 1 | Timeout 20 minutos | ❌ No implementado | 🔴 **ALTA** | Sesiones muy largas |
| **Sesión** | 2 | Sesión 1 día + nonce | ⚠️ Parcial | 🔴 **ALTA** | Vulnerable a replay |
| **Sesión** | 3 | Manejo excepciones | ❌ No implementado | 🔴 **ALTA** | Errores sin estructura |

## Prioridad de Corrección

### 🔴🔴 **CRÍTICAS - Corregir INMEDIATAMENTE**
1. **Perfilado ID 1:** Implementar esquema completo de 6 pasos
   - Validación de credenciales (Paso 1-2)
   - Validación de token (Paso 3-4)
   - Validación de scopes (Paso 5)
   - Procesamiento autorizado (Paso 6)

### 🔴 **ALTAS - Bloquean producción**
2. **Sesión ID 1:** Implementar timeout de 20 minutos para baja transaccionalidad
3. **Sesión ID 2:** Implementar nonce y validación de replay para alta transaccionalidad
4. **Sesión ID 3:** Crear manejo centralizado de excepciones con códigos de error
5. **Acceso ID 11:** Configurar cookie SameSite (si se usa autenticación con sesión)

### 🟡 **MEDIAS - Completar antes de producción**
6. **Acceso ID 12:** Documentar restricción de métodos HTTP

**Estado Global: CRÍTICO - NO APTO PARA PRODUCCIÓN** ⛔

**Compliance: 0/6 requisitos cumplidos (0%)**

---




















## Análisis Detallado de Requisitos de Seguridad (Administración de API y Respuesta del Servidor)

---

## ADMINISTRACIÓN DE API

### ID 1: Las APIs deben ser consumidas únicamente a través del API Gateway/servidor de autorización
**⚠️ NO VERIFICABLE / REQUIERE ARQUITECTURA**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Las APIs solo deben ser accesibles a través del API Gateway. Ambientes de test deben tener su propio gateway separado.

**Ubicación verificada:**
- **Archivo:** `application.properties`
- **Archivo:** `AuthorizationServerApplication.java`
- **Configuración de red:** No visible en código

**Análisis actual:**
```properties
# application.properties
spring.application.name=ServidorOauth
server.port=9054

# Eureka - Se registra en service discovery
eureka.client.serviceUrl.defaultZone=https://localhost:9100/eureka/
eureka.instance.secure-port=9054
eureka.instance.non-secure-port-enabled=false

# ⚠️ FALTA: Configuración de API Gateway
# ⚠️ FALTA: Restricción de acceso directo
# ⚠️ FALTA: Configuración de ambientes separados
```

```java
// AuthorizationServerApplication.java
@SpringBootApplication
@EnableDiscoveryClient  // ✅ Se registra en Eureka
public class AuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}

// ⚠️ No hay validación de origen de requests
// ⚠️ No hay verificación de que requests vengan del gateway
```

**Problemas identificados:**
1. No hay evidencia de API Gateway en el código
2. No hay validación de que requests provengan del gateway
3. No hay restricción de acceso directo al servidor OAuth2
4. No hay configuración de ambientes separados (dev/test/prod)
5. Falta documentación de arquitectura de red

**Solución requerida:**

```java
// 1. Crear filtro para validar origen desde API Gateway
@Component
@Order(0)
public class ApiGatewayValidationFilter extends OncePerRequestFilter {
    
    @Value("${api.gateway.secret-header:X-Gateway-Secret}")
    private String gatewaySecretHeaderName;
    
    @Value("${api.gateway.secret-value}")
    private String expectedGatewaySecret;
    
    @Value("${api.gateway.enabled:true}")
    private boolean gatewayValidationEnabled;
    
    @Value("${api.gateway.allowed-ips}")
    private Set<String> allowedGatewayIps;
    
    private static final Set<String> BYPASS_PATHS = Set.of(
        "/actuator/health",
        "/error"
    );
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        String requestPath = request.getRequestURI();
        
        // Permitir ciertos paths sin validación
        if (BYPASS_PATHS.contains(requestPath)) {
            chain.doFilter(request, response);
            return;
        }
        
        if (gatewayValidationEnabled) {
            
            // ✅ Validación 1: Header secreto del gateway
            String gatewaySecret = request.getHeader(gatewaySecretHeaderName);
            
            if (gatewaySecret == null || !gatewaySecret.equals(expectedGatewaySecret)) {
                log.warn("Request sin header de gateway válido desde: {}", 
                        request.getRemoteAddr());
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write(
                    "{\"error\":\"direct_access_forbidden\"," +
                    "\"message\":\"Las APIs solo pueden ser consumidas a través del API Gateway\"}"
                );
                return;
            }
            
            // ✅ Validación 2: IP del gateway
            String clientIp = getClientIP(request);
            
            if (!allowedGatewayIps.contains(clientIp)) {
                log.error("Request desde IP no autorizada: {} (esperadas: {})", 
                         clientIp, allowedGatewayIps);
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write(
                    "{\"error\":\"ip_not_authorized\"," +
                    "\"message\":\"IP no autorizada para acceso directo\"}"
                );
                return;
            }
            
            // ✅ Validación 3: Header X-Forwarded-For presente (indica proxy)
            String forwardedFor = request.getHeader("X-Forwarded-For");
            if (forwardedFor == null) {
                log.warn("Request sin X-Forwarded-For, posible acceso directo");
            }
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

// 2. Configurar en application.properties por ambiente
# application-dev.properties
api.gateway.enabled=false
api.gateway.validation.strict=false
environment.name=DEVELOPMENT
api.gateway.url=https://gateway-dev.empresa.com

# application-test.properties
api.gateway.enabled=true
api.gateway.validation.strict=true
api.gateway.secret-value=${GATEWAY_SECRET_TEST}
api.gateway.allowed-ips=10.0.1.100,10.0.1.101
environment.name=TEST
api.gateway.url=https://gateway-test.empresa.com

# application-prod.properties
api.gateway.enabled=true
api.gateway.validation.strict=true
api.gateway.secret-value=${GATEWAY_SECRET_PROD}
api.gateway.allowed-ips=10.0.2.100,10.0.2.101,10.0.2.102
environment.name=PRODUCTION
api.gateway.url=https://gateway.empresa.com

# 3. Configurar Security para bloquear acceso directo
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health").permitAll()
            .requestMatchers("/error").permitAll()
            // Todos los demás endpoints requieren header de gateway
            .anyRequest().authenticated())
        
        // ✅ Agregar filtro de validación de gateway
        .addFilterBefore(
            apiGatewayValidationFilter(), 
            UsernamePasswordAuthenticationFilter.class
        );
    
    return http.build();
}

// 4. Crear servicio para verificar ambiente
@Service
public class EnvironmentService {
    
    @Value("${environment.name:UNKNOWN}")
    private String environmentName;
    
    @Value("${api.gateway.url}")
    private String gatewayUrl;
    
    public boolean isProduction() {
        return "PRODUCTION".equals(environmentName);
    }
    
    public boolean isTest() {
        return "TEST".equals(environmentName);
    }
    
    public boolean isDevelopment() {
        return "DEVELOPMENT".equals(environmentName);
    }
    
    public String getGatewayUrl() {
        return gatewayUrl;
    }
    
    public String getEnvironmentName() {
        return environmentName;
    }
}

// 5. Configurar firewall a nivel de red (documentar en arquitectura)
/**
 * CONFIGURACIÓN DE RED REQUERIDA:
 * 
 * PRODUCCIÓN:
 * - OAuth2 Server: 10.0.2.50:9054
 * - API Gateway: 10.0.2.100-102:443
 * - Firewall: Solo permitir tráfico desde IPs del Gateway
 * 
 * TEST:
 * - OAuth2 Server: 10.0.1.50:9054
 * - API Gateway: 10.0.1.100-101:443
 * - Firewall: Solo permitir tráfico desde IPs del Gateway
 * 
 * DESARROLLO:
 * - OAuth2 Server: localhost:9054
 * - Sin API Gateway (acceso directo permitido)
 * 
 * REGLAS DE FIREWALL:
 * iptables -A INPUT -p tcp --dport 9054 -s 10.0.2.100 -j ACCEPT
 * iptables -A INPUT -p tcp --dport 9054 -s 10.0.2.101 -j ACCEPT
 * iptables -A INPUT -p tcp --dport 9054 -s 10.0.2.102 -j ACCEPT
 * iptables -A INPUT -p tcp --dport 9054 -j DROP
 */

// 6. Documentar en Swagger la arquitectura
@Configuration
public class OpenApiConfig {
    
    @Value("${environment.name}")
    private String environment;
    
    @Value("${api.gateway.url}")
    private String gatewayUrl;
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("OAuth2 Authorization Server")
                .version("1.0.0")
                .description(String.format(
                    "**Ambiente:** %s\n\n" +
                    "**⚠️ IMPORTANTE:** Esta API solo debe ser consumida a través del API Gateway\n\n" +
                    "**API Gateway URL:** %s\n\n" +
                    "**Acceso Directo:** Bloqueado en ambientes de TEST y PRODUCCIÓN\n\n" +
                    "Todas las peticiones deben incluir el header secreto del gateway.",
                    environment, gatewayUrl
                ))
            )
            .servers(List.of(
                new Server()
                    .url(gatewayUrl)
                    .description("API Gateway - " + environment)
            ))
            .addSecurityItem(new SecurityRequirement().addList("gateway-secret"))
            .components(new Components()
                .addSecuritySchemes("gateway-secret", 
                    new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER)
                        .name("X-Gateway-Secret")
                )
            );
    }
}
```

**Diagrama de arquitectura requerido:**

```
┌─────────────┐
│   Cliente   │
│(Aplicación) │
└──────┬──────┘
       │
       │ HTTPS
       │
       ▼
┌──────────────────────────────────────────┐
│         API GATEWAY                       │
│  (Spring Cloud Gateway / Kong / Nginx)   │
│                                           │
│  - Rate Limiting                          │
│  - Autenticación                          │
│  - Logging                                │
│  - Agregación de respuestas              │
│  - Inyecta: X-Gateway-Secret             │
└──────────────┬───────────────────────────┘
               │
               │ HTTPS + Header Secreto
               │ X-Gateway-Secret: xxx
               │
        ┌──────┴───────┐
        │              │
        ▼              ▼
┌──────────────┐  ┌──────────────┐
│OAuth2 Server │  │   Resource   │
│   (9054)     │  │   Servers    │
│              │  │              │
│ ✅ Valida    │  │ ✅ Valida    │
│ header       │  │ header       │
│ secreto      │  │ secreto      │
└──────────────┘  └──────────────┘

AMBIENTES SEPARADOS:
- DEV:  Sin gateway, acceso directo permitido
- TEST: Gateway obligatorio (gateway-test.empresa.com)
- PROD: Gateway obligatorio (gateway.empresa.com)
```

**Evidencias requeridas según documento:**
- **Opc1:** Diagrama mostrando API Gateway
- **Opc2:** Captura de Postman o configuración mostrando que se usa gateway
- **Opc3:** Correo indicando si se ocupa o no

**Notas importantes:**
- Este requisito requiere coordinación con infraestructura y arquitectura
- Debe documentarse en diseño técnico y arquitectura de solución
- Firewall de red es crítico como segunda capa de protección

---

### ID 2: La definición de cada API (entradas y salidas) deberá ser documentada en un catálogo para auditorías posteriores
**⚠️ PARCIALMENTE IMPLEMENTADO**
**🟡 SEVERIDAD MEDIA**

**Descripción del requisito:**
Documentar todas las APIs con sus entradas, salidas, métodos, headers, y códigos de error en un catálogo auditable.

**Ubicación verificada:**
- **Archivo:** `pom.xml` (línea 43-47)
- **Swagger configurado pero sin personalización**

**Análisis actual:**
```xml
<!-- pom.xml - Swagger/OpenAPI configurado -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.6.0</version>
</dependency>
```

```java
// OauthTokenRequest.java - Con anotaciones @Schema básicas
@Data
public class OauthTokenRequest {
    @Schema(description="ClientId que se utiliza en la boveda de Cyberark")
    private String clientId;
    
    @Schema(description="Secret guardado en la boveda de Cyberark")
    private String clientSecret;
    
    @Schema(description="Scopes del ClientId")
    private List<String> scopes;
}

// ⚠️ FALTA: Ejemplos de valores
// ⚠️ FALTA: Documentación de errores
// ⚠️ FALTA: Documentación completa de endpoints
```

**Problemas identificados:**
1. Swagger instalado pero sin configuración personalizada
2. No hay documentación completa de errores
3. No hay ejemplos de requests/responses
4. No hay documentación de headers requeridos
5. No hay versionamiento de API documentado
6. Falta catálogo centralizado para auditoría

**Solución requerida:**

```java
// 1. Configurar OpenAPI con información completa
@Configuration
public class OpenApiConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("OAuth2 Authorization Server API")
                .version("v1.0.0")
                .description(buildDescription())
                .contact(new Contact()
                    .name("Equipo de Desarrollo")
                    .email("desarrollo@empresa.com")
                )
                .license(new License()
                    .name("Interno - Uso Empresarial")
                )
            )
            .servers(List.of(
                new Server().url("https://localhost:9054").description("Local"),
                new Server().url("https://oauth-test.empresa.com").description("TEST"),
                new Server().url("https://oauth.empresa.com").description("PRODUCCIÓN")
            ))
            .components(new Components()
                .addSchemas("ErrorResponse", createErrorResponseSchema())
                .addSecuritySchemes("client_credentials", createOAuth2Scheme())
            );
    }
    
    private String buildDescription() {
        return """
            # OAuth2 Authorization Server
            
            ## Descripción
            Servidor de autorización OAuth 2.0 que emite tokens de acceso JWT para autenticación 
            y autorización de clientes.
            
            ## Flujo de Autenticación
            1. Cliente solicita token con credenciales (client_id, client_secret)
            2. Servidor valida credenciales y scopes
            3. Servidor emite JWT con duración configurada
            4. Cliente usa JWT en header Authorization para acceder a recursos
            
            ## Grant Types Soportados
            - `client_credentials`: Para aplicaciones server-to-server
            
            ## Transaccionalidad
            - **Baja (LOW)**: Token válido por 20 minutos
            - **Alta (HIGH)**: Token válido por 1 día + nonce obligatorio
            
            ## Seguridad
            - TLS 1.3/1.2 obligatorio
            - Validación de scopes por endpoint
            - Rate limiting habilitado
            - Replay attack protection con nonce
            
            ## Ambientes
            - **Desarrollo**: Acceso directo permitido
            - **Test/Producción**: Solo a través de API Gateway
            """;
    }
    
    private Schema<?> createErrorResponseSchema() {
        return new Schema<>()
            .type("object")
            .description("Estructura estándar de errores")
            .addProperty("error", new Schema<>().type("string").description("Código de error"))
            .addProperty("errorDescription", new Schema<>().type("string").description("Descripción del error"))
            .addProperty("errorCode", new Schema<>().type("string").description("Código interno"))
            .addProperty("timestamp", new Schema<>().type("string").format("date-time"))
            .addProperty("path", new Schema<>().type("string").description("Path del request"))
            .addProperty("status", new Schema<>().type("integer").description("HTTP status code"));
    }
    
    private SecurityScheme createOAuth2Scheme() {
        return new SecurityScheme()
            .type(SecurityScheme.Type.OAUTH2)
            .description("OAuth2 Client Credentials Flow")
            .flows(new OAuthFlows()
                .clientCredentials(new OAuthFlow()
                    .tokenUrl("https://localhost:9054/api/token")
                    .scopes(new Scopes()
                        .addString("client:read", "Leer información de clientes")
                        .addString("client:create", "Crear clientes")
                        .addString("client:update", "Actualizar clientes")
                        .addString("client:delete", "Eliminar clientes")
                        .addString("admin:manage", "Gestión administrativa")
                    )
                )
            );
    }
}

// 2. Documentar endpoint de token completamente
@RestController
@RequestMapping("/api")
@Tag(
    name = "Autenticación", 
    description = "Endpoints de autenticación OAuth2"
)
public class TokenController {
    
    @Operation(
        summary = "Solicitar token de acceso",
        description = """
            Genera un token JWT de acceso usando client credentials.
            
            **Flujo:**
            1. Validar client_id y client_secret
            2. Validar scopes solicitados
            3. Validar grant_type
            4. Generar JWT con claims necesarios
            5. Retornar token con metadata
            
            **Duración del token:**
            - Baja transaccionalidad: 20 minutos
            - Alta transaccionalidad: 1 día
            
            **Rate Limit:** 100 requests/minuto por client_id
            """,
        tags = {"Autenticación"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Token generado exitosamente",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponse.class),
                examples = @ExampleObject(
                    name = "Token exitoso",
                    value = """
                        {
                          "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                          "token_type": "Bearer",
                          "expires_in": 1200,
                          "scope": "client:read client:create",
                          "transaction_type": "LOW"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Request inválido - Validación fallida",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = ErrorResponse.class),
                examples = @ExampleObject(
                    name = "Validación fallida",
                    value = """
                        {
                          "error": "invalid_request",
                          "errorDescription": "Validación fallida",
                          "errorCode": "VAL001",
                          "timestamp": "2025-11-14T10:30:00Z",
                          "path": "/api/token",
                          "status": 400,
                          "details": {
                            "clientId": "Client ID es requerido",
                            "grantType": "Grant type es requerido"
                          }
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Credenciales inválidas",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = ErrorResponse.class),
                examples = @ExampleObject(
                    name = "Credenciales incorrectas",
                    value = """
                        {
                          "error": "invalid_client",
                          "errorDescription": "Cliente no encontrado o credenciales inválidas",
                          "errorCode": "AUTH001",
                          "timestamp": "2025-11-14T10:30:00Z",
                          "path": "/api/token",
                          "status": 401
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Scopes insuficientes",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    value = """
                        {
                          "error": "insufficient_scope",
                          "errorDescription": "Scope no autorizado: admin:manage",
                          "errorCode": "AUTH002",
                          "status": 403
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "429",
            description = "Rate limit excedido",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    value = """
                        {
                          "error": "rate_limit_exceeded",
                          "errorDescription": "Límite de peticiones excedido",
                          "status": 429
                        }
                        """
                )
            )
        )
    })
    @PostMapping("/token")
    public ResponseEntity<?> getToken(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Credenciales del cliente y configuración del token",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = OauthTokenRequest.class),
                examples = {
                    @ExampleObject(
                        name = "Baja transaccionalidad",
                        value = """
                            {
                              "clientId": "app-mobile-v1",
                              "clientSecret": "secret123456789",
                              "grantType": "client_credentials",
                              "scopes": ["client:read", "client:create"],
                              "transactionType": "low"
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Alta transaccionalidad",
                        value = """
                            {
                              "clientId": "integration-service",
                              "clientSecret": "secret987654321",
                              "grantType": "client_credentials",
                              "scopes": ["admin:manage"],
                              "transactionType": "high"
                            }
                            """
                    )
                }
            )
        )
        @Valid @RequestBody OauthTokenRequest request
    ) {
        // Implementación...
    }
}

// 3. Enriquecer DTOs con ejemplos
@Data
@Schema(description = "Request para solicitar un token de acceso OAuth2")
public class OauthTokenRequest {
    
    @Schema(
        description = "Identificador del cliente registrado en CyberArk",
        example = "app-mobile-v1",
        required = true,
        minLength = 5,
        maxLength = 100
    )
    @NotBlank(message = "Client ID es requerido")
    @Size(min = 5, max = 100)
    private String clientId;
    
    @Schema(
        description = "Secret del cliente almacenado en CyberArk",
        example = "secret123456789",
        required = true,
        minLength = 32,
        maxLength = 512
    )
    @NotBlank(message = "Client secret es requerido")
    @Size(min = 32, max = 512)
    private String clientSecret;
    
    @Schema(
        description = "Tipo de grant OAuth2. Solo se soporta 'client_credentials'",
        example = "client_credentials",
        required = true,
        allowableValues = {"client_credentials"}
    )
    @NotBlank(message = "Grant type es requerido")
    @Pattern(regexp = "^client_credentials$")
    private String grantType;
    
    @Schema(
        description = "Lista de scopes solicitados. El cliente debe tener autorización para estos scopes",
        example = "[\"client:read\", \"client:create\"]",
        required = true,
        minItems = 1,
        maxItems = 10
    )
    @NotNull
    @Size(min = 1, max = 10)
    private List<String> scopes;
    
    @Schema(
        description = "Tipo de transaccionalidad: 'low' (20 min) o 'high' (1 día)",
        example = "low",
        defaultValue = "low",
        allowableValues = {"low", "high"}
    )
    @Pattern(regexp = "^(low|high)$")
    private String transactionType = "low";
}

@Data
@Schema(description = "Respuesta exitosa con token de acceso")
public class TokenResponse {
    
    @Schema(
        description = "Token JWT de acceso",
        example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcHAtbW9iaWxlLXYxIiwic2NvcGUiOiJjbGllbnQ6cmVhZCBjbGllbnQ6Y3JlYXRlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDEyMDB9..."
    )
    private String accessToken;
    
    @Schema(
        description = "Tipo de token (siempre 'Bearer')",
        example = "Bearer"
    )
    private String tokenType;
    
    @Schema(
        description = "Tiempo de expiración en segundos",
        example = "1200"
    )
    private Long expiresIn;
    
    @Schema(
        description = "Scopes incluidos en el token",
        example = "client:read client:create"
    )
    private String scope;
    
    @Schema(
        description = "Tipo de transaccionalidad del token",
        example = "LOW"
    )
    private String transactionType;
}

// 4. Crear catálogo de APIs en formato JSON/YAML
@RestController
@RequestMapping("/api/catalog")
public class ApiCatalogController {
    
    @GetMapping(produces = "application/json")
    public ResponseEntity<ApiCatalog> getApiCatalog() {
        
        ApiCatalog catalog = ApiCatalog.builder()
            .version("1.0.0")
            .lastUpdated(Instant.now())
            .environment(environmentService.getEnvironmentName())
            .apis(List.of(
                ApiDefinition.builder()
                    .name("POST /api/token")
                    .description("Generar token de acceso OAuth2")
                    .method("POST")
                    .path("/api/token")
                    .requestBody(RequestBodyDefinition.builder()
                        .contentType("application/json")
                        .required(true)
                        .schema("OauthTokenRequest")
                        .fields(List.of(
                            FieldDefinition.of("clientId", "string", true, "5-100 chars"),
                            FieldDefinition.of("clientSecret", "string", true, "32-512 chars"),
                            FieldDefinition.of("grantType", "string", true, "client_credentials"),
                            FieldDefinition.of("scopes", "array", true, "1-10 items"),
                            FieldDefinition.of("transactionType", "string", false, "low/high")
                        ))
                        .build())
                    .responses(List.of(
                        ResponseDefinition.of(200, "Success", "TokenResponse"),
                        ResponseDefinition.of(400, "Validation Error", "ErrorResponse"),
                        ResponseDefinition.of(401, "Invalid Credentials", "ErrorResponse"),
                        ResponseDefinition.of(403, "Insufficient Scope", "ErrorResponse"),
                        ResponseDefinition.of(429, "Rate Limit", "ErrorResponse")
                    ))
                    .headers(List.of(
                        HeaderDefinition.of("Content-Type", "application/json", true),
                        HeaderDefinition.of("X-Gateway-Secret", "string", true, "En PROD/TEST")
                    ))
                    .errorCodes(List.of(
                        "AUTH001 - Cliente inválido",
                        "AUTH002 - Scopes insuficientes",
                        "AUTH003 - Grant type inválido",
                        "VAL001 - Validación fallida"
                    ))
                    .rateLimit("100 requests/minuto por client_id")
                    .authentication("None (endpoint público)")
                    .build()
            ))
            .build();
        
        return ResponseEntity.ok(catalog);
    }
    
    @GetMapping(value = "/export", produces = "text/csv")
    public ResponseEntity<String> exportCatalogCsv() {
        // Exportar catálogo en CSV para auditoría
        String csv = generateCatalogCsv();
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=api-catalog.csv")
            .body(csv);
    }
}

// 5. Habilitar Swagger UI en ambientes no productivos
@Configuration
public class SwaggerConfig {
    
    @Value("${springdoc.swagger-ui.enabled:true}")
    private boolean swaggerEnabled;
    
    @Value("${environment.name}")
    private String environment;
    
    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
            .group("oauth2-api")
            .pathsToMatch("/api/**")
            .build();
    }
    
    @PostConstruct
    public void logSwaggerStatus() {
        if (swaggerEnabled) {
            log.info("Swagger UI habilitado en ambiente: {}", environment);
            log.info("Swagger UI disponible en: /swagger-ui.html");
            log.info("OpenAPI JSON disponible en: /v3/api-docs");
        }
    }
}

// application-prod.properties
# Deshabilitar Swagger en producción
springdoc.swagger-ui.enabled=false
springdoc.api-docs.enabled=false

// application-test.properties
# Habilitar Swagger en test (protegido)
springdoc.swagger-ui.enabled=true
springdoc.swagger-ui.path=/swagger-ui.html
```

**Estructura del catálogo de APIs:**

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| **Método** | HTTP method | POST |
| **Path** | Ruta del endpoint | /api/token |
| **Headers** | Headers requeridos | Content-Type, X-Gateway-Secret |
| **Request** | Estructura del body | OauthTokenRequest |
| **Response 2xx** | Respuesta exitosa | TokenResponse |
| **Response 4xx** | Errores del cliente | ErrorResponse |
| **Response 5xx** | Errores del servidor | ErrorResponse |
| **Códigos de Error** | Lista de códigos | AUTH001, AUTH002, VAL001 |
| **Rate Limit** | Límite de peticiones | 100/min |
| **Autenticación** | Requerimientos | None / OAuth2 / API Key |
| **Ambiente** | Disponibilidad | DEV, TEST, PROD |

**Evidencias requeridas según documento:**
- Swagger publicado con documentación completa
- Especificaciones de entradas y salidas
- Tabla de códigos de error por endpoint
- Exportación CSV del catálogo para auditoría

---

### ID 3: Versiones obsoletas de una API no deben ser publicadas a internet
**⚠️ NO APLICA ACTUALMENTE / REQUIERE PROCESO**
**🟡 SEVERIDAD MEDIA**

**Descripción del requisito:**
Las versiones antiguas de APIs no deben estar accesibles en internet. Proceso de deprecación controlado.

**Ubicación verificada:**
- **Archivo:** `pom.xml` - Version 0.0.1-SNAPSHOT
- **No hay versionamiento de API visible**

**Análisis actual:**
```xml
<!-- pom.xml -->
<artifactId>ServidorOauth2</artifactId>
<version>0.0.1-SNAPSHOT</version>

<!-- ⚠️ No hay versionamiento en URLs de API -->
<!-- ⚠️ No hay estrategia de deprecación -->
```

```java
// TokenController.java - Sin versión en path
@RestController
@RequestMapping("/api")  // ⚠️ Sin /v1/ o /v2/
public class TokenController {
    @PostMapping("/token")
    public ResponseEntity<?> getToken(...) { }
}
```

**Problemas identificados:**
1. No hay versionamiento en URLs de API
2. No hay estrategia de deprecación documentada
3. No hay headers de deprecación
4. No existe proceso de notificación a consumidores
5. Sin control de acceso por versión

**Solución requerida:**

```java
// 1. Implementar versionamiento en URLs
@RestController
@RequestMapping("/api/v1")  // ✅ Versión en path
public class TokenControllerV1 {
    
    @PostMapping("/token")
    @Operation(
        summary = "Solicitar token (v1)",
        description = "**Versión:** 1.0.0\n**Estado:** ESTABLE\n**Deprecación:** N/A"
    )
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        // Implementación v1
    }
}

// 2. Si hay versión v2, marcar v1 como deprecated
@RestController
@RequestMapping("/api/v1")
@Deprecated  // ✅ Marcar como deprecated
public class TokenControllerV1 {
    
    @PostMapping("/token")
    @Operation(
        summary = "Solicitar token (v1) - DEPRECATED",
        description = """
            ⚠️ **DEPRECATED**: Esta versión será removida el 2026-06-01
            
            Por favor migrar a [/api/v2/token](#/Autenticación/getToken_v2)
            
            **Razón de deprecación:** Mejoras de seguridad en v2
            **Fecha de deprecación:** 2025-12-01
            **Fecha de remoción:** 2026-06-01
            """,
        deprecated = true
    )
    public ResponseEntity<?> getToken(@Valid @RequestBody OauthTokenRequest request) {
        
        // Agregar headers de deprecación
        return ResponseEntity.ok()
            .header("Deprecation", "true")
            .header("Sunset", "Sat, 01 Jun 2026 00:00:00 GMT")
            .header("Link", "</api/v2/token>; rel=\"successor-version\"")
            .body(tokenResponse);
    }
}

// 3. Crear servicio de gestión de versiones
@Service
public class ApiVersionService {
    
    private final Map<String, ApiVersion> versions = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initializeVersions() {
        versions.put("v1", ApiVersion.builder()
            .version("v1")
            .status(VersionStatus.DEPRECATED)
            .deprecatedSince(LocalDate.of(2025, 12, 1))
            .sunsetDate(LocalDate.of(2026, 6, 1))
            .reason("Mejoras de seguridad en v2")
            .migrationGuide("https://docs.empresa.com/oauth2/migration-v1-to-v2")
            .build());
        
        versions.put("v2", ApiVersion.builder()
            .version("v2")
            .status(VersionStatus.STABLE)
            .releaseDate(LocalDate.of(2025, 11, 1))
            .build());
    }
    
    public boolean isVersionDeprecated(String version) {
        ApiVersion apiVersion = versions.get(version);
        return apiVersion != null && apiVersion.getStatus() == VersionStatus.DEPRECATED;
    }
    
    public boolean isVersionSunset(String version) {
        ApiVersion apiVersion = versions.get(version);
        if (apiVersion == null || apiVersion.getSunsetDate() == null) {
            return false;
        }
        return LocalDate.now().isAfter(apiVersion.getSunsetDate());
    }
    
    public Optional<LocalDate> getSunsetDate(String version) {
        ApiVersion apiVersion = versions.get(version);
        return apiVersion != null 
            ? Optional.ofNullable(apiVersion.getSunsetDate()) 
            : Optional.empty();
    }
}

@Data
@Builder
class ApiVersion {
    private String version;
    private VersionStatus status;
    private LocalDate releaseDate;
    private LocalDate deprecatedSince;
    private LocalDate sunsetDate;
    private String reason;
    private String migrationGuide;
}

enum VersionStatus {
    BETA,
    STABLE,
    DEPRECATED,
    SUNSET
}

// 4. Crear filtro para bloquear versiones obsoletas
@Component
@Order(1)
public class ApiVersionFilter extends OncePerRequestFilter {
    
    @Autowired
    private ApiVersionService versionService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        String path = request.getRequestURI();
        String version = extractVersion(path);
        
        if (version != null) {
            
            // ✅ Bloquear versiones sunset
            if (versionService.isVersionSunset(version)) {
                log.warn("Request a versión SUNSET: {} desde {}", 
                        version, request.getRemoteAddr());
                
                response.setStatus(HttpStatus.GONE.value());
                response.setHeader("Deprecation", "true");
                response.getWriter().write(String.format(
                    "{\"error\":\"version_sunset\"," +
                    "\"message\":\"La versión %s ya no está disponible\"," +
                    "\"current_version\":\"v2\"," +
                    "\"migration_guide\":\"https://docs.empresa.com/migration\"}",
                    version
                ));
                return;
            }
            
            // ✅ Advertir sobre versiones deprecated
            if (versionService.isVersionDeprecated(version)) {
                Optional<LocalDate> sunsetDate = versionService.getSunsetDate(version);
                
                response.setHeader("Deprecation", "true");
                sunsetDate.ifPresent(date -> 
                    response.setHeader("Sunset", date.toString())
                );
                response.setHeader("Link", "</api/v2/token>; rel=\"successor-version\"");
                
                log.warn("Request a versión DEPRECATED: {} desde {}", 
                        version, request.getRemoteAddr());
            }
        }
        
        chain.doFilter(request, response);
    }
    
    private String extractVersion(String path) {
        // Extraer versión del path: /api/v1/token -> v1
        Pattern pattern = Pattern.compile("/api/(v\\d+)/");
        Matcher matcher = pattern.matcher(path);
        return matcher.find() ? matcher.group(1) : null;
    }
}

// 5. Endpoint para consultar versiones disponibles
@RestController
@RequestMapping("/api")
public class VersionController {
    
    @Autowired
    private ApiVersionService versionService;
    
    @GetMapping("/versions")
    @Operation(
        summary = "Listar versiones de API disponibles",
        description = "Obtener información sobre todas las versiones de la API"
    )
    public ResponseEntity<List<ApiVersion>> getVersions() {
        return ResponseEntity.ok(versionService.getAllVersions());
    }
    
    @GetMapping("/version/current")
    @Operation(
        summary = "Obtener versión actual recomendada",
        description = "Retorna la versión estable más reciente"
    )
    public ResponseEntity<Map<String, String>> getCurrentVersion() {
        return ResponseEntity.ok(Map.of(
            "current_version", "v2",
            "api_url", "/api/v2/token",
            "status", "STABLE"
        ));
    }
}

// 6. Documentar proceso de deprecación
/**
 * PROCESO DE DEPRECACIÓN DE VERSIONES DE API
 * 
 * FASE 1: ANUNCIO (T-6 meses)
 * - Notificar a consumidores vía email
 * - Actualizar documentación
 * - Marcar versión como DEPRECATED en código
 * - Agregar headers Deprecation y Sunset
 * 
 * FASE 2: DEPRECACIÓN (T-3 meses)
 * - Versión marcada oficialmente como deprecated
 * - Guía de migración publicada
 * - Soporte limitado (solo bugs críticos)
 * - Logs de uso para identificar clientes
 * 
 * FASE 3: SUNSET (T-0)
 * - Versión bloqueada completamente
 * - HTTP 410 Gone para todas las peticiones
 * - Redirección a documentación de migración
 * 
 * FASE 4: REMOCIÓN (T+1 mes)
 * - Código removido del repositorio
 * - Documentación archivada
 * 
 * NOTIFICACIONES:
 * 1. Email a consumidores registrados (T-6, T-3, T-1 meses)
 * 2. Banner en Swagger UI (T-6 meses)
 * 3. Headers HTTP en responses (T-3 meses)
 * 4. Logs de advertencia (T-1 mes)
 */

// 7. Configurar en application.properties
api.versioning.enabled=true
api.versioning.current=v2
api.versioning.default=v2

# Control de acceso por versión en producción
api.versioning.v1.enabled=false  # Deshabilitar v1 en prod
api.versioning.v2.enabled=true

// 8. Agregar en README.md y documentación
/**
 * VERSIONAMIENTO DE API
 * 
 * Esta API usa versionamiento en la URL.
 * 
 * VERSIONES DISPONIBLES:
 * - v1: ⚠️ DEPRECATED - Será removida el 2026-06-01
 * - v2: ✅ STABLE - Versión actual recomendada
 * 
 * BREAKING CHANGES EN V2:
 * - Nonce obligatorio para alta transaccionalidad
 * - Validación estricta de grant_type
 * - Nuevos códigos de error estructurados
 * 
 * GUÍA DE MIGRACIÓN: https://docs.empresa.com/oauth2/migration
 */
```

**Evidencias requeridas según documento:**
- Indicar que es API nueva y no es pública en internet
- Describir cómo se accede (a través de gateway)
- Captura del versionador (Git)
- Texto donde se indique que en caso de nueva versión se notificará a seguridad

**Proceso de notificación para nueva versión:**
```
CHECKLIST - NUEVA VERSIÓN DE API:

□ Actualizar versión en pom.xml
□ Crear nuevo controller con path versionado (/api/v{N}/)
□ Actualizar documentación Swagger
□ Crear guía de migración
□ Notificar a equipo de Seguridad (SDI)
□ Notificar a consumidores registrados
□ Actualizar catálogo de APIs
□ Publicar release notes
□ Marcar versión anterior como deprecated (si aplica)
```

---

### ID 4: Ciclo de vida de la API
**❌ NO DOCUMENTADO**
**🟡 SEVERIDAD MEDIA**

**Descripción del requisito:**
Documentar y gestionar el ciclo de vida completo de la API: desarrollo, versionamiento, deprecación, monitoreo y decomiso.

**Problemas identificados:**
1. No hay proceso documentado de ciclo de vida
2. No hay versionamiento en código
3. No existe estrategia de decomiso
4. Sin plan de monitoreo post-deprecación
5. Falta identificación de componentes dependientes

**Solución requerida:**

```markdown
# CICLO DE VIDA DE API - OAuth2 Authorization Server

## 1. DESARROLLO Y LANZAMIENTO

### 1.1 Planificación
- Identificar necesidad y casos de uso
- Definir SLA y requisitos de performance
- Documentar dependencias y componentes
- Aprobar diseño con Arquitectura y Seguridad

### 1.2 Desarrollo
```java
// Agregar versión al código
@RestController
@RequestMapping("/api/v1")
public class TokenControllerV1 {
    
    private static final String API_VERSION = "1.0.0";
    private static final LocalDate RELEASE_DATE = LocalDate.of(2025, 11, 14);
    
    @GetMapping("/version")
    public ResponseEntity<ApiVersionInfo> getVersionInfo() {
        return ResponseEntity.ok(ApiVersionInfo.builder()
            .version(API_VERSION)
            .releaseDate(RELEASE_DATE)
            .status("STABLE")
            .build());
    }
}
```

### 1.3 Testing
- Tests unitarios (>80% coverage)
- Tests de integración
- Tests de seguridad (OWASP, penetration testing)
- Performance testing (load, stress)

### 1.4 Documentación
- Swagger/OpenAPI completo
- Guías de integración
- Ejemplos de uso (Postman collections)
- Códigos de error documentados

### 1.5 Deployment
- Desplegar en DEV → TEST → PROD
- Smoke tests post-deployment
- Notificar a consumidores
- Actualizar inventario de APIs

## 2. OPERACIÓN Y MANTENIMIENTO

### 2.1 Monitoreo
```java
@Component
public class ApiHealthMonitor {
    
    @Scheduled(fixedRate = 60000) // Cada minuto
    public void monitorApiHealth() {
        ApiMetrics metrics = ApiMetrics.builder()
            .timestamp(Instant.now())
            .requestsPerMinute(metricsService.getRequestRate())
            .errorRate(metricsService.getErrorRate())
            .avgResponseTime(metricsService.getAvgResponseTime())
            .activeClients(metricsService.getActiveClients())
            .build();
        
        if (metrics.getErrorRate() > 5.0) {
            alertService.sendAlert("Error rate alto: " + metrics.getErrorRate() + "%");
        }
        
        metricsRepository.save(metrics);
    }
}
```

### 2.2 Métricas Clave
- Requests por minuto (RPM)
- Tasa de error (%)
- Latencia (p50, p95, p99)
- Disponibilidad (uptime %)
- Clientes activos

### 2.3 SLA
- Disponibilidad: 99.9% uptime
- Latencia: p95 < 200ms
- Tasa de error: < 1%

## 3. VERSIONAMIENTO

### 3.1 Estrategia de Versiones
```
v1.0.0 (MAJOR.MINOR.PATCH)

MAJOR: Breaking changes (incompatible con versión anterior)
MINOR: Nuevas funcionalidades (compatible con versión anterior)
PATCH: Bug fixes (compatible con versión anterior)
```

### 3.2 Ejemplo de Versionamiento
```java
// v1.0.0 - Release inicial
@PostMapping("/api/v1/token")
public ResponseEntity<TokenResponse> getToken() { }

// v1.1.0 - Agregar soporte para refresh token (compatible)
@PostMapping("/api/v1/token/refresh")
public ResponseEntity<TokenResponse> refreshToken() { }

// v2.0.0 - Cambios incompatibles (nueva versión mayor)
@PostMapping("/api/v2/token")
public ResponseEntity<TokenResponseV2> getToken() {
    // Nueva estructura de response
}
```

## 4. DEPRECACIÓN

### 4.1 Proceso de Deprecación (6 meses)

#### Mes 1-2: ANUNCIO
```java
@PostMapping("/api/v1/token")
@Deprecated
@Operation(deprecated = true, description = "DEPRECATED: Migrar a v2")
public ResponseEntity<?> getToken() {
    return ResponseEntity.ok()
        .header("Deprecation", "true")
        .header("Sunset", "2026-06-01")
        .header("Link", "</api/v2/token>; rel=\"successor-version\"")
        .body(response);
}
```

**Acciones:**
- [ ] Email a consumidores notificando deprecación
- [ ] Banner en Swagger UI
- [ ] Actualizar documentación
- [ ] Publicar guía de migración

#### Mes 3-4: DEPRECACIÓN ACTIVA
- Agregar logs de advertencia
- Monitorear uso de versión deprecated
- Contactar clientes que aún usan v1
- Ofrecer soporte para migración

#### Mes 5: ÚLTIMAS ADVERTENCIAS
- Email final a consumidores restantes
- Incrementar nivel de logs a WARNING
- Preparar documentación de sunset

#### Mes 6: SUNSET
```java
@PostMapping("/api/v1/token")
public ResponseEntity<?> getToken() {
    // Versión sunset - Bloqueada
    return ResponseEntity.status(HttpStatus.GONE)
        .header("Deprecation", "true")
        .body(Map.of(
            "error", "version_sunset",
            "message", "Esta versión ya no está disponible",
            "migration_guide", "https://docs.empresa.com/migration"
        ));
}
```

### 4.2 Identificar Componentes Dependientes
```java
@Service
public class DependencyTracker {
    
    public List<ApiConsumer> getConsumersOfVersion(String version) {
        // Obtener de logs, monitoreo o base de datos
        return consumerRepository.findByApiVersion(version);
    }
    
    public void notifyConsumers(String version, String message) {
        List<ApiConsumer> consumers = getConsumersOfVersion(version);
        
        consumers.forEach(consumer -> {
            emailService.sendDeprecationNotice(
                consumer.getEmail(),
                version,
                message
            );
        });
    }
}
```

## 5. MONITOREO POST-DEPRECACIÓN (1-3 meses)

### 5.1 Métricas a Monitorear
```java
@Service
public class DeprecationMonitoringService {
    
    @Scheduled(cron = "0 0 9 * * *") // Diario a las 9am
    public void generateDeprecationReport() {
        
        DeprecationMetrics metrics = DeprecationMetrics.builder()
            .date(LocalDate.now())
            .v1Requests(metricsService.getRequestCountV1())
            .v1UniqueClients(metricsService.getUniqueClientsV1())
            .v1ErrorRate(metricsService.getErrorRateV1())
            .build();
        
        if (metrics.getV1Requests() > 0) {
            log.warn("⚠️ Versión v1 deprecated aún recibe {} requests", 
                    metrics.getV1Requests());
            
            // Notificar al equipo
            alertService.sendDeprecationAlert(metrics);
        }
        
        // Guardar para análisis de tendencia
        metricsRepository.save(metrics);
    }
}
```

### 5.2 Dashboard de Monitoreo
- Requests por versión (v1 vs v2)
- Clientes únicos por versión
- Tasa de migración (%)
- Tiempo hasta sunset

## 6. DECOMISO EN PRODUCCIÓN

### 6.1 Checklist de Decomiso
```
□ Confirmar 0 requests a versión deprecated en últimos 30 días
□ Notificación final a stakeholders
□ Backup de código y documentación
□ Remover código de versión deprecated
□ Actualizar load balancers / API Gateway
□ Remover endpoints de monitoreo
□ Actualizar documentación
□ Actualizar inventario de APIs
□ Archivar documentación histórica
□ Post-mortem y lecciones aprendidas
```

### 6.2 Código de Decomiso
```java
// Remover completamente el controller deprecated
// ANTES DEL DECOMISO, ARCHIVAR:
// - Código fuente (Git tag)
// - Documentación
// - Logs de uso
// - Lista de consumidores históricos

// Actualizar routing
@Configuration
public class ApiRoutingConfig {
    
    @Bean
    public RouterFunction<ServerResponse> apiRoutes() {
        return route()
            // v1 removida - redirigir a v2
            .GET("/api/v1/**", request -> 
                ServerResponse.permanentRedirect(
                    URI.create("/api/v2" + request.path().substring(7))
                ).build()
            )
            .build();
    }
}
```

### 6.3 Post-Decomiso
- Monitorear errores 404 en paths de v1
- Documentar lecciones aprendidas
- Actualizar proceso para futuras versiones

## 7. INVENTARIO DE APIs

### 7.1 Registro de API
```java
@Entity
public class ApiInventoryRecord {
    
    @Id
    private String apiId;
    
    private String name;
    private String version;
    private String environment; // DEV, TEST, PROD
    private String accessType; // INTERNET, MPLS, INTERNAL
    private List<String> consumers; // ["app-mobile", "integration-service"]
    private VersionStatus status; // BETA, STABLE, DEPRECATED, SUNSET
    private LocalDate releaseDate;
    private LocalDate deprecationDate;
    private LocalDate sunsetDate;
    private String owner;
    private String contactEmail;
    private String documentation;
    private String repository;
}
```

### 7.2 Mantener Inventario Actualizado
```java
@Service
public class ApiInventoryService {
    
    @Scheduled(cron = "0 0 0 * * SUN") // Cada domingo
    public void updateInventory() {
        
        ApiInventoryRecord record = ApiInventoryRecord.builder()
            .apiId("oauth2-server")
            .name("OAuth2 Authorization Server")
            .version("v2.0.0")
            .environment("PRODUCTION")
            .accessType("INTERNAL") // Solo a través de API Gateway
            .consumers(Arrays.asList(
                "api-gateway",
                "mobile-app-ios",
                "mobile-app-android",
                "integration-platform"
            ))
            .status(VersionStatus.STABLE)
            .releaseDate(LocalDate.of(2025, 11, 14))
            .owner("Equipo de Seguridad")
            .contactEmail("desarrollo@empresa.com")
            .documentation("https://docs.empresa.com/oauth2")
            .repository("https://github.com/empresa/oauth2-server")
            .build();
        
        inventoryRepository.save(record);
    }
    
    @GetMapping("/api/inventory")
    public ResponseEntity<List<ApiInventoryRecord>> getInventory() {
        return ResponseEntity.ok(inventoryRepository.findAll());
    }
}
```

## 8. DIAGRAMA DE CICLO DE VIDA

```
┌─────────────┐
│ PLANIFICACIÓN│
│  - Diseño   │
│  - Aprobación│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ DESARROLLO  │
│  - Código   │
│  - Tests    │
│  - Docs     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ LANZAMIENTO │
│  v1.0.0     │
│  (STABLE)   │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│  OPERACIÓN  │────>│ VERSIONADO  │
│  - Monitoreo│     │  v1.1.0     │
│  - Métricas │     │  v1.2.0     │
│  - SLA      │     │  v2.0.0     │
└──────┬──────┘     └──────┬──────┘
       │                   │
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│ MANTENIMIENTO│    │ DEPRECACIÓN │
│  - Bug fixes│     │ (6 meses)   │
│  - Updates  │     │ - Anuncio   │
└─────────────┘     │ - Migración │
                    │ - Sunset    │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  MONITOREO  │
                    │ (1-3 meses) │
                    │ - Métricas  │
                    │ - Alertas   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  DECOMISO   │
                    │ - Remover   │
                    │ - Archivar  │
                    └─────────────┘
```

## 9. RESPONSABILIDADES

| Fase | Responsable | Actividades |
|------|-------------|-------------|
| Planificación | Arquitectura + PM | Diseño, requisitos, aprobación |
| Desarrollo | Desarrollo | Código, tests, documentación |
| Lanzamiento | DevOps + Desarrollo | Deploy, smoke tests |
| Operación | DevOps + SRE | Monitoreo, incidentes, SLA |
| Versionamiento | Desarrollo + Arquitectura | Nuevas versiones, breaking changes |
| Deprecación | Desarrollo + PM | Notificaciones, soporte a migración |
| Decomiso | DevOps + Desarrollo | Remover código, actualizar infra |

## 10. MÉTRICAS DE ÉXITO

- Time to Market: < 3 meses para nueva versión
- Uptime: > 99.9%
- Migración exitosa: > 95% clientes migrados antes de sunset
- Tiempo de deprecación: 6 meses estándar
- Incidentes post-decomiso: 0

**Evidencias requeridas según documento:**
- Documento interno indicando ciclo de vida
- Matriz de gestión de APIs (creación, cambios, actualizaciones, deshabilitación)
```

---

### ID 5: Se debe realizar un inventario de todas las API
**❌ NO IMPLEMENTADO**
**🟡 SEVERIDAD MEDIA**

**Descripción del requisito:**
Mantener inventario actualizado de todas las APIs con información de: ambiente, acceso, consumidores, versión, vulnerabilidades.

**Problemas identificados:**
1. No existe inventario centralizado
2. No hay registro de consumidores
3. No hay tracking de versiones
4. Sin información de ambientes
5. Falta análisis de vulnerabilidades

**Solución requerida:**

```java
// 1. Crear modelo de inventario
@Entity
@Table(name = "api_inventory")
@Data
@Builder
public class ApiInventoryEntry {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    // Identificación
    private String apiName;
    private String apiId;
    private String version;
    private String description;
    
    // Ambiente
    @Enumerated(EnumType.STRING)
    private Environment environment; // DEV, TEST, UAT, PROD
    
    // Acceso
    @Enumerated(EnumType.STRING)
    private AccessType accessType; // INTERNET, MPLS, INTERNAL, VPN
    
    private String gatewayUrl;
    private String directUrl;
    private boolean publicInternet; // ¿Expuesta a internet?
    
    // Consumidores
    @ElementCollection
    private List<String> consumers; // ["app-mobile", "erp-system"]
    
    @ElementCollection
    private List<String> consumerEmails; // Contactos
    
    // Versión y Estado
    @Enumerated(EnumType.STRING)
    private VersionStatus versionStatus; // BETA, STABLE, DEPRECATED, SUNSET
    
    private LocalDate releaseDate;
    private LocalDate deprecationDate;
    private LocalDate sunsetDate;
    
    // Seguridad y Vulnerabilidades
    @ElementCollection
    private List<String> vulnerabilities; // ["CVE-2024-1234"]
    
    private LocalDate lastSecurityScan;
    private String securityScanResult; // PASS, FAIL, WARNING
    
    @ElementCollection
    private List<String> securityControls; // ["OAuth2", "Rate Limiting", "HTTPS"]
    
    // Propietario
    private String ownerTeam;
    private String ownerEmail;
    private String technicalContact;
    
    // Documentación
    private String swaggerUrl;
    private String documentationUrl;
    private String repositoryUrl;
    
    // Métricas
    private Long averageRequestsPerDay;
    private Double averageResponseTimeMs;
    private Double uptimePercentage;
    
    // Auditoría
    private Instant createdAt;
    private Instant lastUpdatedAt;
    private String lastUpdatedBy;
}

enum Environment {
    DEVELOPMENT("DEV"),
    TEST("TEST"),
    UAT("UAT"),
    PRODUCTION("PROD");
    
    private final String code;
    Environment(String code) { this.code = code; }
}

enum AccessType {
    INTERNET("Internet público"),
    MPLS("Red MPLS privada"),
    INTERNAL("Red interna"),
    VPN("VPN corporativa");
    
    private final String description;
    AccessType(String description) { this.description = description; }
}

// 2. Servicio de gestión de inventario
@Service
public class ApiInventoryService {
    
    @Autowired
    private ApiInventoryRepository repository;
    
    @Autowired
    private SecurityScannerService scannerService;
    
    /**
     * Registrar nueva API en inventario
     */
    public ApiInventoryEntry registerApi(ApiRegistrationRequest request) {
        
        ApiInventoryEntry entry = ApiInventoryEntry.builder()
            .apiName(request.getApiName())
            .apiId(generateApiId(request.getApiName()))
            .version(request.getVersion())
            .description(request.getDescription())
            .environment(request.getEnvironment())
            .accessType(request.getAccessType())
            .gatewayUrl(request.getGatewayUrl())
            .consumers(request.getConsumers())
            .consumerEmails(request.getConsumerEmails())
            .versionStatus(VersionStatus.BETA)
            .releaseDate(LocalDate.now())
            .ownerTeam(request.getOwnerTeam())
            .ownerEmail(request.getOwnerEmail())
            .swaggerUrl(request.getSwaggerUrl())
            .repositoryUrl(request.getRepositoryUrl())
            .createdAt(Instant.now())
            .lastUpdatedAt(Instant.now())
            .lastUpdatedBy(request.getRegisteredBy())
            .build();
        
        return repository.save(entry);
    }
    
    /**
     * Actualizar información de API
     */
    public ApiInventoryEntry updateApi(UUID id, ApiUpdateRequest request) {
        ApiInventoryEntry entry = repository.findById(id)
            .orElseThrow(() -> new NotFoundException("API no encontrada"));
        
        entry.setVersion(request.getVersion());
        entry.setVersionStatus(request.getVersionStatus());
        entry.setConsumers(request.getConsumers());
        entry.setLastUpdatedAt(Instant.now());
        entry.setLastUpdatedBy(request.getUpdatedBy());
        
        return repository.save(entry);
    }
    
    /**
     * Actualizar escaneo de seguridad
     */
    public void updateSecurityScan(UUID id) {
        ApiInventoryEntry entry = repository.findById(id)
            .orElseThrow();
        
        SecurityScanResult scanResult = scannerService.scan(entry.getDirectUrl());
        
        entry.setLastSecurityScan(LocalDate.now());
        entry.setSecurityScanResult(scanResult.getStatus());
        entry.setVulnerabilities(scanResult.getVulnerabilities());
        
        repository.save(entry);
        
        // Alertar si hay vulnerabilidades críticas
        if (!scanResult.getCriticalVulnerabilities().isEmpty()) {
            alertService.sendCriticalVulnerabilityAlert(entry, scanResult);
        }
    }
    
    /**
     * Obtener inventario filtrado
     */
    public List<ApiInventoryEntry> getInventory(InventoryFilter filter) {
        return repository.findAll().stream()
            .filter(entry -> matchesFilter(entry, filter))
            .collect(Collectors.toList());
    }
    
    /**
     * Exportar inventario a CSV para auditoría
     */
    public String exportInventoryCsv() {
        List<ApiInventoryEntry> entries = repository.findAll();
        
        StringBuilder csv = new StringBuilder();
        csv.append("API ID,Nombre,Versión,Ambiente,Acceso,Consumidores,Estado,Vulnerabilidades,Owner\n");
        
        entries.forEach(entry -> {
            csv.append(String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
                entry.getApiId(),
                entry.getApiName(),
                entry.getVersion(),
                entry.getEnvironment(),
                entry.getAccessType(),
                String.join(";", entry.getConsumers()),
                entry.getVersionStatus(),
                entry.getVulnerabilities().size(),
                entry.getOwnerEmail()
            ));
        });
        
        return csv.toString();
    }
    
    private String generateApiId(String apiName) {
        return apiName.toLowerCase()
            .replaceAll("[^a-z0-9]", "-")
            .replaceAll("-+", "-");
    }
}

// 3. Controller para gestión de inventario
@RestController
@RequestMapping("/api/admin/inventory")
@PreAuthorize("hasRole('ADMIN')")
public class ApiInventoryController {
    
    @Autowired
    private ApiInventoryService inventoryService;
    
    @PostMapping
    @Operation(summary = "Registrar nueva API en inventario")
    public ResponseEntity<ApiInventoryEntry> registerApi(
            @Valid @RequestBody ApiRegistrationRequest request) {
        return ResponseEntity.ok(inventoryService.registerApi(request));
    }
    
    @GetMapping
    @Operation(summary = "Obtener inventario completo")
    public ResponseEntity<List<ApiInventoryEntry>> getInventory(
            @RequestParam(required = false) Environment environment,
            @RequestParam(required = false) VersionStatus status) {
        
        InventoryFilter filter = InventoryFilter.builder()
            .environment(environment)
            .status(status)
            .build();
        
        return ResponseEntity.ok(inventoryService.getInventory(filter));
    }
    
    @GetMapping("/export")
    @Operation(summary = "Exportar inventario a CSV")
    public ResponseEntity<String> exportInventory() {
        String csv = inventoryService.exportInventoryCsv();
        
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=api-inventory.csv")
            .header("Content-Type", "text/csv")
            .body(csv);
    }
    
    @GetMapping("/{id}/vulnerabilities")
    @Operation(summary = "Obtener vulnerabilidades de una API")
    public ResponseEntity<List<String>> getVulnerabilities(@PathVariable UUID id) {
        return ResponseEntity.ok(inventoryService.getVulnerabilities(id));
    }
    
    @PostMapping("/{id}/scan")
    @Operation(summary = "Ejecutar escaneo de seguridad")
    public ResponseEntity<Void> scanSecurity(@PathVariable UUID id) {
        inventoryService.updateSecurityScan(id);
        return ResponseEntity.ok().build();
    }
}

// 4. Job para actualizar inventario automáticamente
@Component
public class InventoryMaintenanceJob {
    
    @Autowired
    private ApiInventoryService inventoryService;
    
    @Scheduled(cron = "0 0 2 * * *") // Diario a las 2am
    public void updateInventory() {
        log.info("Ejecutando mantenimiento de inventario");
        
        // Actualizar métricas de uso
        inventoryService.updateUsageMetrics();
        
        // Escanear vulnerabilidades
        inventoryService.scanAllApis();
        
        // Verificar APIs deprecated que deben ser sunset
        inventoryService.checkDeprecatedApis();
        
        // Generar reporte
        inventoryService.generateInventoryReport();
    }
}

// 5. Ejemplo de entrada en inventario para OAuth2 Server
@PostConstruct
public void registerOAuth2ServerInInventory() {
    
    ApiRegistrationRequest request = ApiRegistrationRequest.builder()
        .apiName("OAuth2 Authorization Server")
        .version("v2.0.0")
        .description("Servidor de autorización OAuth 2.0 para autenticación de clientes")
        .environment(Environment.PRODUCTION)
        .accessType(AccessType.INTERNAL)
        .gatewayUrl("https://gateway.empresa.com/oauth2")
        .directUrl("https://oauth2.empresa.com")
        .publicInternet(false) // NO expuesta directamente
        .consumers(Arrays.asList(
            "api-gateway",
            "mobile-app-ios-v2",
            "mobile-app-android-v2",
            "erp-integration-service",
            "reporting-dashboard"
        ))
        .consumerEmails(Arrays.asList(
            "mobile-team@empresa.com",
            "integration-team@empresa.com"
        ))
        .ownerTeam("Equipo de Seguridad")
        .ownerEmail("desarrollo@empresa.com")
        .technicalContact("tech-lead@empresa.com")
        .swaggerUrl("https://oauth2.empresa.com/swagger-ui.html")
        .documentationUrl("https://docs.empresa.com/oauth2")
        .repositoryUrl("https://github.com/empresa/oauth2-server")
        .securityControls(Arrays.asList(
            "OAuth 2.0",
            "JWT",
            "TLS 1.3",
            "Rate Limiting",
            "IP Whitelist",
            "Nonce (replay protection)"
        ))
        .registeredBy("admin@empresa.com")
        .build();
    
    inventoryService.registerApi(request);
}
```

**Tabla de inventario:**

| Campo | Valor | Descripción |
|-------|-------|-------------|
| **API ID** | oauth2-authorization-server | Identificador único |
| **Nombre** | OAuth2 Authorization Server | Nombre descriptivo |
| **Versión** | v2.0.0 | Versión actual |
| **Ambiente** | PRODUCTION | DEV, TEST, PROD |
| **Acceso** | INTERNAL | Solo red interna/gateway |
| **Internet Público** | NO | No expuesta directamente |
| **Consumers** | api-gateway, mobile-apps, erp | Lista de consumidores |
| **Estado** | STABLE | BETA, STABLE, DEPRECATED |
| **Vulnerabilidades** | 0 | CVEs detectados |
| **Último Scan** | 2025-11-14 | Fecha de escaneo |
| **Owner** | Equipo de Seguridad | Responsable |
| **Contacto** | desarrollo@empresa.com | Email de contacto |

**Evidencias requeridas según documento:**
- Concentrado/inventario indicando versión de APIs
- Documentado en diseño técnico
- Captura de correo mostrando registro en inventario de Juan Carlos (PMO)

---

### ID 6: El framework de programación para APIs validado por seguridad es SPRING
**✅ CUMPLE**
**🟢 SIN RIESGO**

**Descripción del requisito:**
Usar Spring Framework para desarrollo de APIs. Si se usa otro framework, informar a Seguridad.

**Análisis actual:**
```xml
<!-- pom.xml - Usa Spring Boot -->
<parent>
    <groupId>com.eglobal.sicarem.sicarem_api</groupId>
    <artifactId>seguridad</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</parent>

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

```java
// AuthorizationServerApplication.java - Spring Boot Application
@SpringBootApplication
@EnableDiscoveryClient
public class AuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}
```

**Estado:**
✅ **CUMPLE** - El proyecto usa Spring Boot 3.x con Java 21

**Framework y versiones:**
- **Framework:** Spring Boot
- **Versión Spring:** (heredada del parent POM)
- **Java Version:** 21
- **Spring Security OAuth2:** Authorization Server

**Evidencias requeridas según documento:**
- Informar el framework usado
- Captura donde se identifique que se usa Spring Framework

**Documentación requerida:**

```markdown
# DECLARACIÓN DE FRAMEWORK

## Framework Utilizado
- **Framework Principal:** Spring Boot 3.x
- **Lenguaje:** Java 21
- **Build Tool:** Maven

## Componentes de Spring Utilizados
- Spring Boot Starter Web
- Spring Boot Starter OAuth2 Authorization Server
- Spring Boot Actuator
- Spring Security
- Spring Cloud Discovery Client (Eureka)

## Justificación
Spring Framework es el framework validado por Seguridad para desarrollo de APIs 
en la empresa por las siguientes razones:

1. **Seguridad Robusta:** Spring Security es líder en la industria
2. **Soporte Largo Plazo:** LTS con actualizaciones regulares
3. **Cumplimiento:** Fácil implementación de estándares OAuth2, JWT, HTTPS
4. **Comunidad:** Gran comunidad y documentación
5. **Auditoría:** Ampliamente usado y auditado

## Aprobación
✅ Framework aprobado por Seguridad de la Información
```

---

## RESPUESTA DEL SERVIDOR

### ID 1: Enviar la cabecera X-Content-Type-Options: nosniff
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Descripción del requisito:**
Agregar header X-Content-Type-Options: nosniff para prevenir MIME type sniffing.

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java`

**Problema específico:**
```java
// SecurityConfig.java - Sin configuración de headers de seguridad
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(/* ... */)
        .csrf(AbstractHttpConfigurer::disable);
    // ⚠️ FALTA: Configuración de headers de seguridad
    return http.build();
}
```

**Solución requerida:**

```java
@Bean
@Order(2)
public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(/* ... */)
        
        // ✅ Configurar headers de seguridad
        .headers(headers -> headers
            // ID 1: X-Content-Type-Options
            .contentTypeOptions(Customizer.withDefaults()) // nosniff
        );
    
    return http.build();
}
```

**Evidencias requeridas:** Captura de Postman mostrando el header en la respuesta

---

### ID 2: Enviar la cabecera X-Frame-Options: deny
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Solución requerida:**

```java
.headers(headers -> headers
    // ID 2: X-Frame-Options
    .frameOptions(frame -> frame.deny()) // DENY
)
```

**Evidencias requeridas:** Captura de Postman mostrando el header

---

### ID 3: Enviar la cabecera Content-Security-Policy: default-src 'none'
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Solución requerida:**

```java
.headers(headers -> headers
    // ID 3: Content-Security-Policy
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'none'; " +
                         "form-action 'self'; " +
                         "upgrade-insecure-requests")
    )
)
```

**Evidencias requeridas:** Captura de Postman mostrando el header

---

### ID 4: Remover todas las cabeceras que permitan identificar las tecnologías que usa el servidor
**❌ NO IMPLEMENTADO**
**🔴 SEVERIDAD ALTA**

**Problema:**
Headers como `Server`, `X-Powered-By`, `X-AspNet-Version` exponen información del servidor.

**Solución requerida:**

```java
// 1. Configurar en SecurityConfig
.headers(headers -> headers
    // Remover header Server
    .httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true)
        .maxAgeInSeconds(31536000)
    )
)

// 2. Configurar en application.properties
server.server-header= 
# Dejar vacío para no enviar header Server

// 3. Crear filtro para remover headers adicionales
@Component
public class ServerHeaderRemovalFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        // Remover headers que exponen tecnología
        HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
            @Override
            public void setHeader(String name, String value) {
                if (shouldRemoveHeader(name)) {
                    return; // No agregar el header
                }
                super.setHeader(name, value);
            }
            
            @Override
            public void addHeader(String name, String value) {
                if (shouldRemoveHeader(name)) {
                    return;
                }
                super.addHeader(name, value);
            }
        };
        
        chain.doFilter(request, wrapper);
    }
    
    private boolean shouldRemoveHeader(String name) {
        return name.equalsIgnoreCase("Server") ||
               name.equalsIgnoreCase("X-Powered-By") ||
               name.equalsIgnoreCase("X-AspNet-Version") ||
               name.equalsIgnoreCase("X-AspNetMvc-Version") ||
               name.equalsIgnoreCase("X-Application-Context");
    }
}
```

**Configuración completa de headers de seguridad:**

```java
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
        
        // ✅ HEADERS DE SEGURIDAD COMPLETOS
        .headers(headers -> headers
            // ID 1: X-Content-Type-Options: nosniff
            .contentTypeOptions(Customizer.withDefaults())
            
            // ID 2: X-Frame-Options: DENY
            .frameOptions(frame -> frame.deny())
            
            // ID 3: Content-Security-Policy
            .contentSecurityPolicy(csp -> csp
                .policyDirectives(
                    "default-src 'none'; " +
                    "script-src 'self'; " +
                    "connect-src 'self'; " +
                    "img-src 'self'; " +
                    "style-src 'self'; " +
                    "frame-ancestors 'none'; " +
                    "form-action 'self'; " +
                    "upgrade-insecure-requests"
                )
            )
            
            // Headers adicionales de seguridad
            .xssProtection(xss -> xss
                .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
            )
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000)
                .preload(true)
            )
            .referrerPolicy(referrer -> referrer
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            )
            .permissionsPolicy(permissions -> permissions
                .policy("geolocation=(), microphone=(), camera=()")
            )
        )
        
        .requiresChannel(channel -> channel
            .anyRequest().requiresSecure()
        );

    return http.build();
}
```

**Evidencias requeridas:** Captura de Postman mostrando todos los headers de seguridad y ausencia de headers de tecnología

---

## Resumen Consolidado de Severidades

| Dominio | ID | Requisito | Estado | Severidad | Impacto |
|---------|----|-----------| -------|-----------|---------|
| **Administración** | 1 | Solo a través de Gateway | ⚠️ No verificable | 🔴 **ALTA** | Acceso directo posible |
| **Administración** | 2 | Documentar en catálogo | ⚠️ Parcial | 🟡 **MEDIA** | Swagger básico |
| **Administración** | 3 | No publicar versiones obsoletas | ⚠️ N/A | 🟡 **MEDIA** | API nueva |
| **Administración** | 4 | Ciclo de vida documentado | ❌ No documentado | 🟡 **MEDIA** | Falta proceso |
| **Administración** | 5 | Inventario de APIs | ❌ No implementado | 🟡 **MEDIA** | Sin registro |
| **Administración** | 6 | Framework Spring | ✅ Cumple | 🟢 **OK** | - |
| **Respuesta Servidor** | 1 | X-Content-Type-Options | ❌ No implementado | 🔴 **ALTA** | MIME sniffing |
| **Respuesta Servidor** | 2 | X-Frame-Options | ❌ No implementado | 🔴 **ALTA** | Clickjacking |
| **Respuesta Servidor** | 3 | Content-Security-Policy | ❌ No implementado | 🔴 **ALTA** | XSS, injection |
| **Respuesta Servidor** | 4 | Remover headers tecnología | ❌ No implementado | 🔴 **ALTA** | Info disclosure |

## Prioridad de Corrección

### 🔴 **ALTAS - Implementar INMEDIATAMENTE**
1. **Respuesta Servidor IDs 1-4:** Configurar todos los headers de seguridad
2. **Administración ID 1:** Validar que requests vienen del gateway

### 🟡 **MEDIAS - Antes de producción**
3. **Administración ID 2:** Completar documentación Swagger con ejemplos
4. **Administración ID 4:** Documentar ciclo de vida de API
5. **Administración ID 5:** Implementar inventario de APIs

**Estado Global: CRÍTICO - Headers de seguridad faltantes** ⛔

**Compliance: 1/10 requisitos cumplidos (10%)**

---

## Checklist de Implementación

### Fase 1 - Críticos:
- [ ] Configurar headers de seguridad en SecurityConfig
- [ ] Crear filtro para remover headers de tecnología
- [ ] Implementar validación de gateway
- [ ] Configurar HSTS completo

### Fase 2 - Documentación:
- [ ] Completar documentación Swagger/OpenAPI
- [ ] Crear catálogo de APIs exportable
- [ ] Documentar ciclo de vida
- [ ] Implementar sistema de inventario

### Fase 3 - Versionamiento:
- [ ] Implementar versionamiento en URLs
- [ ] Crear proceso de deprecación
- [ ] Sistema de notificaciones a consumidores

**Tiempo estimado: 1-2 sprints**
