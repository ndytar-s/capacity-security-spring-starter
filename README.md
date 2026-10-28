# Capacity Security

Starter Spring Boot qui met en place un **modèle de capacités** (capability-based security) au niveau de l'API, et non dans le code applicatif. Il combine des JWT (capacités natives) et des Macaroons (capacités déléguées et atténuées), avec révocation via Redis, DPoP optionnel, audit AOP, authentification par fournisseur OAuth et filtrage des outils d'agents IA.

> **Statut** : le starter est encore en phase de test dans sa forme générale et sa profondeur. Distribué via JitPack.

## Sommaire

1. [Installation](#1-installation)
2. [Principe en bref](#2-principe-en-bref)
3. [Configuration de la sécurité](#3-configuration-de-la-sécurité)
4. [Modèle de données : la politique scope/actions](#4-modèle-de-données--la-politique-scopeactions)
5. [Récupération des utilisateurs](#5-récupération-des-utilisateurs)
6. [Authentification](#6-authentification)
7. [Protéger les endpoints](#7-protéger-les-endpoints)
8. [Délégation et révocation (Macaroons)](#8-délégation-et-révocation-macaroons)
9. [Agents IA](#9-agents-ia)
10. [Propriétés](#10-propriétés)
11. [Architecture du projet](#11-architecture-du-projet)
12. [Points d'extension optionnels](#12-points-dextension-optionnels)
13. [Limitations connues](#13-limitations-connues)

## 1. Installation

**Dépôt JitPack**

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

**Dépendance**

```xml
<dependency>
    <groupId>com.github.ndytar-s</groupId>
    <artifactId>capacity-security-spring-starter</artifactId>
    <version>v1.0.0</version>
</dependency>
```

Le starter s'active seul grâce à `@AutoConfiguration`, aucune annotation à ajouter.

## 2. Principe en bref

Une **capacité** est un jeton qui porte ce que son détenteur a le droit de faire : un **scope** (la ressource, par exemple `/comptes/**`) et des **actions** (`READ`, `WRITE`, `APPROVE`...).

À chaque requête :

1. `CapacityFilter` lit l'en-tête `X-Capacity-Token` et reconstruit la capacité (JWT, sinon Macaroon).
2. `CapacityAuthManager` déduit le scope et l'action requis par l'endpoint.
3. L'accès est accordé seulement si la capacité couvre ce scope et cette action.

Au login, le rôle de l'utilisateur est traduit en capacités grâce à une **politique de mapping** (rôle vers scope/actions).

## 3. Configuration de la sécurité

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain configure(HttpSecurity http, CapacityAuthManager capacity) throws Exception {
        http.with(capacitySecurity(), Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()   // exemple : routes publiques
                .requestMatchers("/error").permitAll()     // voir la note ci-dessous
                .anyRequest().access(capacity));
        return http.build();
    }
}
```

`/auth/**` n'est qu'un exemple : adaptez les routes publiques à votre application.

**À propos de `/error`** : il est recommandé de ne pas l'ignorer côté sécurité. Il était auparavant désactivé pour éviter le forward interne, ce qui n'est plus le cas. Laissez-le passer (`permitAll`) pour que Spring puisse afficher les vraies erreurs au lieu de les masquer derrière un 401/403.

Le starter fournit une `SecurityFilterChain` par défaut, désactivée dès que vous en déclarez une (`@ConditionalOnMissingBean`).

## 4. Modèle de données : la politique scope/actions

Le système repose sur une politique qui associe, pour un **rôle**, des **actions** autorisées sur un **scope**. Vous n'êtes pas obligé d'implémenter la persistance de cette façon, mais la structure de données attendue doit être respectée.

### Exemple de politique

| Scope | Rôles | Actions |
|---|---|---|
| `/comptes/**` | `MANAGER` | `READ`, `WRITE` |
| `/comptes/**` | `CAISSIER`, `CLIENT` | `READ` |
| `/virements/**` | `MANAGER` | `READ`, `APPROVE` |
| `/virements/**` | `JOKER` | `*` (toutes les actions) |

En code :

```java
List.of(
    new MapingPolitic("/comptes/**",   Set.of("MANAGER"),            Set.of("READ", "WRITE")),
    new MapingPolitic("/comptes/**",   Set.of("CAISSIER", "CLIENT"), Set.of("READ")),
    new MapingPolitic("/virements/**", Set.of("MANAGER"),            Set.of("READ", "APPROVE")),
    new MapingPolitic("/virements/**", Set.of("JOKER"),              Set.of("*"))
);
```

### Entité de politique

```java
@Entity
public class MapingPolitic extends AbstractPoliticMapping {
    public MapingPolitic() {}
    public MapingPolitic(String scope, Set<String> role, Set<String> actions) {
        super(scope, role, actions);
    }
}
```

### Entité utilisateur (facultative)

Une entité `User` avec : identifiant, nom d'utilisateur ou e-mail, mot de passe, et un `Set` de rôles. Elle n'est **pas obligatoire** : il est possible de construire un système sans compte utilisateur.

### Fournir la politique au starter

```java
@Configuration
public class ConfigPoliticMapping {

    @Autowired
    private PolitiqueRepository politiqueRepository;

    @Bean
    public CapacityPolitiqueMappingService capacityPolitiqueService() {
        return new DynamicPoliticMappingService(role -> politiqueRepository.findByRole(role));
    }
}
```

On donne un rôle, on récupère une `List<MapingPolitic>`. Les données peuvent venir de n'importe quelle source (base, fichier, service distant).

Avec JPA, `PoliticMappingRepository` étend déjà `JpaRepository` :

```java
public interface PolitiqueRepository extends PoliticMappingRepository<MapingPolitic> {
    List<MapingPolitic> findByRole(String role);
}
```

## 5. Récupération des utilisateurs

Au point d'ancrage, implémentez `CapacityUserService` pour retrouver les informations de l'utilisateur (identifiant, rôles). Ces rôles servent ensuite au mapping scope/actions. Valable pour un accès par login/mot de passe comme par un fournisseur externe.

```java
@Service
public class UserService implements CapacityUserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Optional<CapacityUser> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(u -> new CapacityUser(u.getUsername(), u.getPassword(), u.getRole(), u.getId()));
    }
}
```

Sans bean `CapacityUserService` ni `CapacityPolitiqueMappingService`, le démarrage échoue (`NoSuchBeanDefinitionException`). C'est voulu : ces composants dépendent entièrement de votre modèle de données.

## 6. Authentification

### Par login et mot de passe

```java
@Autowired private IAuthService authService;
@Autowired private ObjectMapper objectMapper;

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) throws JsonProcessingException {
    return ResponseEntity.ok(authService.login(
            request.getUsername(),
            request.getPassword(),
            objectMapper.writeValueAsString(request.getJwk())   // preuve DPoP
    ));
}
```

`request.getJwk()` sert à la preuve de possession (DPoP). Si vous n'utilisez pas la preuve, le champ reste dans le type de la requête et vous pouvez passer `null`.

### Par fournisseur OAuth

```java
@GetMapping("/loginOauth")
@CapacityOauth
public ResponseEntity<?> logOAuth(TokenResponse token) {
    return ResponseEntity.ok(token);
}
```

`@CapacityOauth` injecte le `TokenResponse` généré. Il faut en plus fournir un vérificateur qui extrait les informations de l'utilisateur à partir du jeton du fournisseur :

```java
@Component
public class GoogleVerifier implements ExternalOauthVerifier {
    @Override
    public OauthUserInfo verify(String rawToken) {
        // Utiliser les outils natifs de Spring Boot pour valider le jeton
        // et extraire les informations de l'utilisateur.
        return new OauthUserInfo("publicKey", "loginUser");
    }
}
```

La présence du bean active automatiquement `CapacityOauthAspect`. L'en-tête lu est configurable (`capacity.security.oauth.headername`, par défaut `Authorization`).

## 7. Protéger les endpoints

```java
@RestController
@RequestMapping("/documents")
public class DocumentController {

    @GetMapping("/rapport")
    // scope déduit : /documents/**, action déduite : READ
    public String rapport(@AuthenticationPrincipal String token) {
        return "rapport accessible avec Token: " + token;
    }

    @PostMapping("/approuver")
    @RequiresCapacity(actions = "APPROVE")          // action métier explicite
    public String approuver() {
        return "document approuvé";
    }

    @GetMapping("/exporter")
    @RequiresCapacity(actions = "EXPORT")
    @OneTimeAccess                                  // capacité révoquée après usage
    public String exporter() {
        return "document exporté";
    }

    @PostMapping("/compte")
    @AllowedIp                                      // IP limitées par propriété
    public String creerCompte() {
        return "Compte créé";
    }

    @GetMapping("/solde")
    public String monSolde(@SubjectId Long compteId) {   // ressource personnelle
        return "solde " + compteId;
    }
}
```

### Règles de déduction

| Élément | Déduit par défaut | Pour personnaliser |
|---|---|---|
| **Action** | Verbe HTTP : `GET` donne `READ`, `POST` donne `CREATE`, `PUT` donne `UPDATE`, `DELETE` donne `DELETE` | `@RequiresCapacity(actions = "...")` |
| **Scope** | `@RequestMapping` de la classe (`/documents` donne `/documents/**`) | `@RequiresCapacity(actions = "EXPORT", resourcePattern = "/documents")` |

### Annotations

| Annotation | Rôle |
|---|---|
| `@RequiresCapacity` | Précise l'action métier et/ou le pattern de ressource |
| `@OneTimeAccess` | La capacité est révoquée une fois utilisée (cas fréquent des capacités déléguées) |
| `@AllowedIp` | Restreint l'endpoint aux IP déclarées dans `capacity.security.allowed-ips` |
| `@SubjectId` | Injecte l'identifiant du sujet, obligatoire pour les ressources à usage personnel |
| `@CapacityOauth` | Active l'authentification par fournisseur tiers |
| `@InjectAgentContext` | Injecte le contexte de l'agent (voir section 9) |

Exemple de restriction par IP :

```properties
capacity.security.allowed-ips=127.0.0.1,::1,192.168.1.8,10.0.0.0/24
```

## 8. Délégation et révocation (Macaroons)

Pour déléguer, il faut posséder une capacité native (JWT), que l'on convertit en Macaroon avec une personnalisation.

### Générer un Macaroon

```java
@GetMapping("/macaroon/generer")
public ResponseEntity<?> genererMacaroon(
        @RequestParam String ressource,
        @RequestParam List<String> actions,
        @RequestParam(defaultValue = "false") boolean oneTime,
        @RequestHeader("X-Capacity-Token") String jwtToken) {
    String macaroon = macaroonService.creer(jwtToken, ressource, new HashSet<>(actions), oneTime);
    return ResponseEntity.ok(macaroon);
}
```

Dans cette version, la durée n'est pas redéfinie : le Macaroon reprend celle du token parent.

### Atténuer un Macaroon

Pour restreindre davantage (par exemple donner une durée, au format ISO) :

```java
@GetMapping("/macaroon/attenuate")
public ResponseEntity<?> attenuate(@RequestParam String token, @RequestParam String... caveats) {
    String macaroon = macaroonService.attenuate(token, caveats);
    if (macaroon == null) return ResponseEntity.status(401).body("Macaroon non valide");
    return ResponseEntity.ok(macaroon);
}
```

Caveats pris en compte : `expire=PT10M`, `actions=READ`. Une atténuation ne peut que **réduire** les droits du parent. Exemple : si la capacité principale autorise `UPDATE` pendant 24 h, un Macaroon dérivé pourra n'autoriser que `READ` pendant 10 minutes, jamais plus que `UPDATE` ni plus de 24 h.

### Révocation

Trois types de révocation existent pour le moment :

| Type | Effet |
|---|---|
| Un Macaroon | Révoque uniquement ce Macaroon |
| Par capacité mère | Révoque le JWT et tous ses Macaroons |
| Tout | Révocation globale |

```java
@DeleteMapping("/macaroon/revoquer")
public ResponseEntity<?> revoquerMacaroon(@RequestParam String macaroon) {
    return ResponseEntity.ok(macaroonService.revokeMacaroon(macaroon));
}

@DeleteMapping("/macaroon/revoquerAll")
public ResponseEntity<?> revoquerAllMacaroonWithJwt(@RequestHeader("X-Capacity-Token") String jwtToken) {
    return ResponseEntity.ok(macaroonService.revokeMacaroonsByJwt(jwtToken));
}
```

La révocation nécessite Redis : `capacity.macaroon.redis=true`.

## 9. Agents IA

Un agent IA reçoit des **outils** (tools) dont chacun est protégé par une capacité. L'agent ne voit et n'appelle que les outils couverts par les capacités fournies dans la requête.

### Déclarer les outils d'un agent

Un agent est toujours annoté `@AgentToolsSource`, car le système prévoit plusieurs agents.

```java
@Configuration
public class AgentConfig {

    @Bean
    @AgentToolsSource
    public Map<String, List<ToolCallback>> toolsParAgent1(CapacityToolWrappingFactory factory, BanqueData data) {
        return Map.of("manager", factory.wrapper(
                new CompteTools(data),
                new VirementTools(data),
                new RapportsTools(data),
                new PresoCompte(data)));
    }
}
```

Avec deux agents :

```java
@Bean
@AgentToolsSource
public Map<String, List<ToolCallback>> toolsParAgent2(CapacityToolWrappingFactory factory, BanqueData data) {
    return Map.of("caissier", factory.wrapper(
            new CompteTools(data),
            new Retrait(data),
            new PresoCompte(data)));
}
```

Le nom de l'agent (`manager`, `caissier`) s'utilise dans paramètre **`X-Agent`**. Avec un seul agent, `X-Agent` peut rester vide et l'agent n'a pas besoin d'être nommé.

### Contrôleur

`@InjectAgentContext` fournit le contexte qui filtre les outils selon les capacités :

```java
@RestController
@RequestMapping("/agent")
public class AgentController {

    private final ChatClient agent;

    public AgentController(ChatClient agent) {
        this.agent = agent;
    }

    @PostMapping("/chat")
    public String chat(@InjectAgentContext AgentContext ctx, @RequestBody String userInput) {
        return agent.prompt()
                .user(userInput)
                .tools(ctx.toolsVisibles())
                .toolContext(ctx.toolContext())
                .call()
                .content();
    }
}
```

### Définir un outil

Chaque outil porte `@Tool` (description pour le modèle) et `@RequiresCapacity` (ressource et action, **les deux paramètres sont obligatoires**). Ils reflètent exactement les données de la politique scope/actions de la section 4. Le `/**` peut être précisé par un sous-scope grâce aux regex.

```java
public class CompteTools {

    private final BanqueData data;

    public CompteTools(BanqueData data) { this.data = data; }

    @Tool(description = "Donne uniquement le solde d'un compte à partir de son identifiant (ex. C-001)")
    @RequiresCapacity(actions = "READ", resourcePattern = "/comptes/**")
    public String consulterSolde(String compteId) { return data.solde(compteId); }

    @Tool(description = "Liste tous les comptes avec leur solde")
    @RequiresCapacity(actions = "READ", resourcePattern = "/comptes/**")
    public String listerComptes() { return data.listerComptes(); }

    @Tool(description = "Pénaliser un compte d'un montant à renseigner")
    @RequiresCapacity(actions = "WRITE", resourcePattern = "/comptes/**")
    public String penaliser(String source, BigDecimal montant) { return data.penaliser(source, montant); }
}
```

### Recommandations d'usage

- Passez **toutes les capacités émises**, séparées par des virgules, dans l'en-tête : l'agent exploite alors les ressources de chacune.
- Avec **DPoP**, chaque requête doit être signée. Pour un agent, on signe la **première** capacité dans l'ordre d'ajout à l'en-tête. La première capacité doit être signée par la preuve.
- Dans cette version, l'agent exécute **une tâche par requête** : la conversation n'est pas enchaînée.

## 10. Propriétés

```properties
# Redis
spring.data.redis.host=localhost
spring.data.redis.port=6379

# JWT
capacity.jwt.duration=604800000
capacity.jwt.refreche=false
capacity.jwt.refduration=604800000
capacity.jwt.headername=X-Capacity-Token
capacity.jwt.headerrefname=X-CapacityRef-Token
capacity.jwt.keysecret=**********

# Macaroon
capacity.macaroon.redis=false
capacity.macaroon.keySecret=**********
# caveat inconnu : true refuse, false ignore
capacity.macaroon.stric=true
capacity.macaroon.location=http://localhost:8080

# Sécurité
capacity.security.oauth.headername=X-My-OAuth-Token
capacity.security.oauth.prefix=oauth
capacity.security.allowed-ips=127.0.0.1,::1,192.168.1.8,10.0.0.0/24
capacity.security.logAudit=true

# DPoP
capacity.dpop.algorithms=ES256,EdDSA
capacity.dpop.active=false
```

| Propriété | Description |
|---|---|
| `capacity.jwt.duration` | Durée de validité du token d'accès (ms) |
| `capacity.jwt.refreche` | Active le refresh token |
| `capacity.jwt.refduration` | Durée de validité du refresh token (ms) |
| `capacity.jwt.headername` / `headerrefname` | En-têtes HTTP du token d'accès et du refresh token |
| `capacity.jwt.keysecret` | Clé secrète (Base64) de signature des JWT |
| `capacity.macaroon.redis` | Active la persistance et la révocation via Redis |
| `capacity.macaroon.keySecret` | Clé secrète de signature des Macaroons |
| `capacity.macaroon.stric` | Caveat inconnu : `true` refuse, `false` ignore |
| `capacity.macaroon.location` | Identifiant de localisation du Macaroon |
| `capacity.security.oauth.headername` | En-tête du jeton du fournisseur (défaut `Authorization`) |
| `capacity.security.oauth.prefix` | Préfixe à retirer avant extraction du jeton |
| `capacity.security.allowed-ips` | IP ou CIDR autorisés pour les endpoints `@AllowedIp` |
| `capacity.security.logAudit` | Active la journalisation d'audit |
| `capacity.dpop.active` | Active la preuve de possession DPoP |
| `capacity.dpop.algorithms` | Algorithmes de signature acceptés |

Gardez les clés secrètes hors du dépôt (variables d'environnement ou gestionnaire de secrets).

## 11. Architecture du projet

Projet Maven multi-module, selon la convention des starters Spring Boot :

```
capacity-security/
├── pom.xml                                 (parent)
├── capacity-security-autoconfigure/        (tout le code Java)
│   └── src/main/java/com/github/ndytar/capacity/
│       ├── autoconfigure/                  classes @AutoConfiguration
│       ├── config/                         DSL Spring Security, PasswordEncoder
│       ├── auth/                           CapacityAuthManager, CapacityAuth
│       ├── chaine/                         CapacityFilter (JWT/Macaroon)
│       ├── jwt_macaroons/                  JwtService, MacaroonService, RefreshTokenService
│       ├── register/                       TokenRedisService
│       ├── services/                       interfaces à implémenter
│       ├── properties/                     @ConfigurationProperties
│       ├── aop/                            audit, vulnérabilités, OAuth tiers
│       ├── annotation/                     annotations publiques
│       ├── capacityModel/                  DTOs (CapacityUser, TokenResponse...)
│       └── exception/                      exceptions et handlers
└── capacity-security-spring-boot-starter/  (agrégateur de dépendances, aucun code)
```

Le module `autoconfigure` contient tout le code. Le module `starter` ne contient qu'un `pom.xml` : c'est lui que l'on ajoute à son projet.

## 12. Points d'extension optionnels

| Composant | Comportement |
|---|---|
| `ExternalOauthVerifier` | Un bean active l'authentification par fournisseur tiers |
| `SecurityAuditReporter` / `SucurityVulnerabilityReport` | Implémentations par défaut qui publient des `ApplicationEvent`, remplaçables (par exemple journalisation en base) |
| `PasswordEncoder` | `DelegatingPasswordEncoder` par défaut, remplaçable par tout bean `PasswordEncoder` |

Deux aspects AOP (`SecurityAuditAspect`, `SecurityVulnerabilityAspect`) journalisent les événements sans configuration, via `spring-boot-starter-aop` déjà déclaré.

## 13. Limitations connues

- **Redis** : la dépendance reste requise au démarrage même avec `capacity.macaroon.redis=false`. Le passage à une dépendance réellement conditionnelle est en cours.
- **Agents** : une tâche par requête, pas de conversation enchaînée.
- **Délégation** : la durée d'un Macaroon n'est pas redéfinie à la génération, elle reprend celle du parent (atténuable ensuite via `expire`).
- **404 vs 403** : la distinction est en place, à valider par des tests d'intégration.
- **Maturité** : le starter est encore à tester dans sa forme générale et sa profondeur.

## Licence

Distribué sous licence [Apache 2.0](LICENSE).
