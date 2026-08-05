# Capacity Security

Starter Spring Boot fournissant un mécanisme d'autorisation par **capacités** (capability-based security), avec support JWT et Macaroons, révocation via Redis, audit de sécurité par AOP, et point d'extension OAuth2 pour fournisseurs tiers.

---

## Sommaire

- [Architecture du projet](#architecture-du-projet)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration (properties)](#configuration-properties)
- [Fonctionnement interne](#fonctionnement-interne)
- [Points d'extension obligatoires](#points-dextension-obligatoires)
- [Points d'extension optionnels](#points-dextension-optionnels)
- [Annotations disponibles](#annotations-disponibles)
- [Personnaliser la SecurityFilterChain](#personnaliser-la-securityfilterchain)
- [Audit et rapport de vulnérabilités](#audit-et-rapport-de-vulnérabilités)
- [Révocation de tokens](#révocation-de-tokens)
- [Limitations connues / feuille de route](#limitations-connues--feuille-de-route)

---

## Architecture du projet

Le dépôt est un projet Maven multi-module, suivant la convention standard des starters Spring Boot :

```
capacity-security/
├── pom.xml                                 (parent, packaging pom)
├── capacity-security-autoconfigure/        (tout le code Java du starter)
│   └── src/main/java/com/github/ndytar/capacity/
│       ├── autoconfigure/                  classes @AutoConfiguration principales
│       ├── config/                         configuration Spring Security (DSL, WebSecurityCustomizer, PasswordEncoder)
│       ├── auth/                           CapacityAuthManager, CapacityAuth, Deduiction
│       ├── chaine/                         CapacityFilter (filtre JWT/Macaroon)
│       ├── jwt_macaroons/                  JwtService, MacaroonService, RefreshTokenService, UuidService
│       ├── register/                       TokenRedisService (persistance Redis)
│       ├── services/                       interfaces publiques à implémenter par le développeur
│       ├── properties/                     classes @ConfigurationProperties
│       ├── aop/                            aspects d'audit, de vulnérabilité, et d'authentification OAuth tierce
│       ├── annotation/                     annotations exposées au développeur
│       ├── capacityModel/                  DTOs publics (CapacityUser, TokenResponse...)
│       └── exception/                      exceptions et handlers dédiés
└── capacity-security-spring-boot-starter/  (agrégateur de dépendances, aucun code Java)
    └── pom.xml
```

**Règle de séparation stricte** :
- `capacity-security-autoconfigure` contient l'intégralité du code.
- `capacity-security-spring-boot-starter` ne contient qu'un `pom.xml` : il déclare la dépendance vers le module autoconfigure ainsi que les dépendances tierces nécessaires (Spring Security, AOP, JJWT, jmacaroons, Redis en optionnel).

C'est ce dernier module que le développeur consommateur ajoute à son propre projet.

---

## Installation

Le starter est distribué via [JitPack](https://jitpack.io), construit automatiquement depuis ce dépôt GitHub.

**1. Ajouter le dépôt JitPack**

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

**2. Ajouter la dépendance**

```xml
<dependency>
    <groupId>com.github.ndytar-s</groupId>
    <artifactId>capacity-security-spring-starter</artifactId>
    <version>v1.0.0</version>
</dependency>
```

Remplacer `v1.0.0` par le tag Git souhaité. Consulter la page JitPack du dépôt pour vérifier l'état du build avant de figer une version en production.

---

## Démarrage rapide

Le starter s'active automatiquement dès qu'il est présent sur le classpath (mécanisme `@AutoConfiguration`, aucune annotation à ajouter côté application).

Deux implémentations sont **obligatoires** pour que l'application démarre (voir [Points d'extension obligatoires](#points-dextension-obligatoires)) :

```java
@Configuration
public class CapacityConfig {

    @Bean
    public CapacityUserService capacityUserService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(u -> new CapacityUser(u.getUsername(), u.getPassword(), u.getRoles()));
    }

    @Bean
    public CapacityPolitiqueMappingService capacityPolitiqueMappingService(PolitiqueRepository repo) {
        return new DynamicPoliticMappingService(role -> repo.findByRole(role));
    }
}
```

Sans ces deux beans, le démarrage échoue avec une erreur explicite (`NoSuchBeanDefinitionException`), c'est un comportement voulu : ces composants dépendent entièrement du modèle de données de l'application consommatrice.

---

## Configuration (properties)

### `capacity.jwt.*`

| Propriété | Défaut | Description |
|---|---|---|
| `duration` | `900000` | Durée de validité du token d'accès (ms) |
| `refduration` | `604800000` | Durée de validité du refresh token (ms) |
| `headername` | `X-Capacity-Token` | En-tête HTTP portant le token d'accès |
| `headerrefname` | `X-CapacityRef-Token` | En-tête HTTP portant le refresh token |
| `keysecret` | *(à définir)* | Clé secrète Base64 utilisée pour signer les JWT (HMAC) |

### `capacity.macaroon.*`

| Propriété | Défaut | Description |
|---|---|---|
| `location` | `http://localhost:8080` | Identifiant de localisation du Macaroon |
| `stric` | `true` | Mode strict de vérification des caveats |
| `redis` | `false` | Active la persistance et la révocation via Redis |
| `keySecret` | *(à définir)* | Clé secrète de signature des Macaroons |

### `capacity.security.*`

| Propriété | Défaut | Description |
|---|---|---|
| `allowedapi` | *(vide)* | Restriction d'API autorisée |
| `mtls` | *(vide)* | Configuration mTLS |

### `capacity.security.oauth.*`

| Propriété | Défaut | Description |
|---|---|---|
| `headername` | `Authorization` | En-tête portant le jeton du fournisseur OAuth tiers |
| `prefix` | `Bearer ` | Préfixe à retirer avant extraction du jeton brut |

---

## Fonctionnement interne

1. `CapacityFilter` intercepte chaque requête et lit l'en-tête configuré (`capacity.jwt.headername`).
2. Si un JWT valide est trouvé, ses claims (`scope`, `actions`, `one_time`, `allowed_ip`, `uuid`) sont extraits et injectés dans le `SecurityContext` sous la forme d'un `CapacityAuth`.
3. Si ce n'est pas un JWT valide, le filtre tente une désérialisation en tant que Macaroon, avec la même logique d'extraction via les caveats.
4. `CapacityAuthManager` (un `AuthorizationManager`) évalue ensuite chaque requête : résolution du handler, vérification d'IP, déduction du scope requis (`@RequestMapping` sur le contrôleur), déduction de l'action requise (`@RequiresCapacity` ou verbe HTTP), et vérification que le token couvre bien ce scope et cette action.

---

## Points d'extension obligatoires

Ces interfaces n'ont **aucune implémentation par défaut**. Le démarrage échoue si elles ne sont pas fournies.

### `CapacityUserService`

```java
public interface CapacityUserService {
    Optional<CapacityUser> findByUsername(String username);
}
```

### `CapacityPolitiqueMappingService`

```java
public interface CapacityPolitiqueMappingService {
    Map<String, Set<String>> getPolitiqueForRole(String role);
}
```

Une implémentation générique `DynamicPoliticMappingService` est fournie par le starter ; elle prend en paramètre une fonction de résolution des données (`Function<String, Collection<? extends MappingScopeActions>>`) à définir par le développeur, en s'appuyant sur l'interface `MappingScopeActions` :

```java
public interface MappingScopeActions {
    String getScopeName();
    Set<String> getActionsSet();
}
```

---

## Points d'extension optionnels

Ces composants ont une implémentation par défaut, ou une fonctionnalité qui reste simplement inactive tant qu'ils ne sont pas fournis.

### `ExternalOauthVerifier` (authentification via un fournisseur OAuth tiers)

```java
public interface ExternalOauthVerifier {
    OauthUserInfo verify(String rawToken);
}
```

Fournir un bean de ce type active automatiquement `CapacityOauthAspect` (aucune property `enabled` à activer, la présence du bean suffit). L'aspect intercepte les méthodes annotées `@CapacityOauth`, extrait le jeton tiers de l'en-tête configuré, appelle `verify(...)`, puis injecte le résultat dans les capacités générées.

### `SecurityAuditReporter` / `SucurityVulnerabilityReport`

Implémentations par défaut fournies (`SpringSecurityAuditRepoerter`, `SpringSecurityVulnerabilityReporter`), qui publient des `ApplicationEvent` Spring. Remplaçables par un bean personnalisé (via `@ConditionalOnMissingBean`) pour, par exemple, journaliser en base de données.

### `PasswordEncoder`

Encodeur par défaut fourni via `PasswordEncoderFactories.createDelegatingPasswordEncoder()`. Remplaçable par tout bean `PasswordEncoder` personnalisé.

---

## Annotations disponibles

| Annotation | Portée | Rôle |
|---|---|---|
| `@RequiresCapacity(actions = {...})` | Méthode de contrôleur | Définit explicitement l'action requise, sinon déduite du verbe HTTP |
| `@AllowedIp("...")` | Méthode de contrôleur | Restreint l'accès à un pattern d'adresse IP |
| `@OneTimeAccess` | Méthode de contrôleur | Exige un token à usage unique |
| `@CapacityOauth` | Méthode de contrôleur | Déclenche `CapacityOauthAspect` pour l'authentification tierce |

---

## Personnaliser la SecurityFilterChain

Le starter fournit une `SecurityFilterChain` par défaut, désactivée automatiquement si le développeur en déclare une lui-même (`@ConditionalOnMissingBean`).

Pour réutiliser la brique de sécurité du starter (filtre, gestion des exceptions, mode stateless) tout en ajoutant ses propres règles :

```java
@Bean
public SecurityFilterChain myFilterChain(HttpSecurity http) throws Exception {
    CapacitySecurityConfigurer configurer = CapacitySecurityConfigurer.capacitySecurity();

    http.with(configurer, Customizer.withDefaults())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/public/**").permitAll()
            .anyRequest().access(configurer.authManager()));

    return http.build();
}
```

`configurer.authManager()` retourne un `AuthorizationManager` à résolution différée (pattern *lazy*), garantissant que `CapacityAuthManager` est bien résolu avant toute évaluation d'autorisation, quel que soit l'ordre d'exécution des `SecurityConfigurer`.

---

## Audit et rapport de vulnérabilités

Deux aspects AOP journalisent automatiquement les événements de sécurité, sans configuration nécessaire :

- `SecurityAuditAspect` : intercepte les appels à `SecurityAuditReporter.report(...)` et journalise chaque événement (type, utilisateur, ressource, actions, horodatage).
- `SecurityVulnerabilityAspect` : intercepte les appels à `SucurityVulnerabilityReport.report(...)` et journalise les incidents détectés (mot de passe en clair, encodeur faible, configuration non sûre, etc.).

Ces aspects nécessitent la présence d'AspectJ sur le classpath (`spring-boot-starter-aop`), déjà déclaré par le starter.

---

## Révocation de tokens

- `JwtService.revoker(token)` / `revokeAll(tokens)` : révocation via suppression de l'entrée Redis associée à l'UUID du token.
- `MacaroonService.revokerMac(macaroon)` / `revokerMacWithToken(token)` : révocation individuelle ou en masse de tous les Macaroons attenués depuis un même JWT.

La révocation nécessite `capacity.macaroon.redis=true` (voir [Limitations connues](#limitations-connues--feuille-de-route)).

---

## Limitations connues / feuille de route

- **Dépendance Redis actuellement obligatoire au démarrage.** Bien que la logique métier soit conçue pour fonctionner avec ou sans Redis (via le flag `capacity.macaroon.redis`), le graphe de beans actuel exige un `StringRedisTemplate` disponible même lorsque ce flag est à `false`. Le passage à une dépendance réellement conditionnelle (`@ConditionalOnBean(StringRedisTemplate.class)` sur `TokenRedisService`, `UuidService`, et gestion `Optional` dans `JwtService`/`MacaroonService`/`CapacityFilter`/`RefreshTokenService`) est en cours.
- **Forward `/error`** : ignoré via `WebSecurityCustomizer`, correction du problème de forward interne identifié en phase de conception.
- **404 vs 403** : `CapacityAuthManager` distingue déjà l'absence de endpoint (`NoHandlerFoundException`) de l'accès refusé, à valider en test d'intégration.

---

## Licence

*(à compléter selon la licence choisie pour le dépôt)*
