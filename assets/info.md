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