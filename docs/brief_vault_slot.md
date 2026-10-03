# Coffre de secrets comme slot

Date : 3 octobre 2026
Base : `@cyanmycelium/mcp-broker` 1.6.1, `@cyanmycelium/mcp-broker-provider` 0.4.1, `@cyanmycelium/mcp-core` 1.4.1, `@cyanmycelium/mcp-uns` 0.1.0
Modèle : [mcp-history](https://github.com/pandaGaume/mcp-history/blob/main/docs/brief_history_slot.md) (contrat à deux formes, slot qui ne décide rien, suite de conformité)

## Besoin

Un endroit où les slots partagent des clés et des fichiers de configuration. Exemple : le slot scada configure l'accès au broker MQTT (hôte, identifiants, certificat) et le donne à tous les slots qui publient ou écoutent sur MQTT.

Contrainte : **tout ce qui circule est chiffré jusqu'à sa cible.** Ni le broker, ni les transports, ni les journaux, ni le contexte d'un agent ne voient un secret en clair.

## Décisions prises

| Sujet | Décision |
|---|---|
| Backend | OpenBao, moteur KV version 2, par son API HTTP, sans bibliothèque cliente. Compatible HashiCorp Vault |
| Paquet | un seul, `@cyanmycelium/mcp-vault` : contrat, chiffrement, store mémoire, store OpenBao, slot, conformité en sous-chemin `/conformance` |
| Chiffrement | de bout en bout, à clé publique : X25519, HKDF-SHA256, AES-256-GCM, contexte en données associées. `node:crypto` seulement |
| Partage | par **audiences** : le propriétaire choisit les audiences d'un secret, la policy du broker dit qui appartient à chacune |
| Contenu | `keys` (objet JSON) ou `file` (nom, type MIME, `utf8` ou `base64`) |
| Versions | celles de KV, avec check-and-set (`cas`) |
| Suppression | définitive (toutes les versions), réservée à `vault.admin` |

## Principe

Comme `history.v1`, le contrat `vault.v1` a deux formes qui disent la même chose :

1. `ISecretStore`, l'interface qu'implémente un backend (mémoire, OpenBao) ;
2. les outils MCP `vault.*`, produits par `VaultBehavior` à partir de n'importe quel store.

`VaultSlotStore` fait le chemin inverse : il présente le slot comme un `ISecretStore`, en scellant et en ouvrant de son côté. La suite de conformité passe à l'identique sur un store direct et à travers le slot.

Différence avec l'historique : le store garde du clair, mais le slot n'en laisse jamais sortir. Le chiffrement est le travail du slot et de `VaultSlotStore`, jamais celui du store.

## Chiffrement de bout en bout

Chaque extrémité a une paire de clés X25519.

- **Le slot vault** a une paire stable, chargée depuis sa configuration (`VaultKeyPair.fromPrivateKey`). Il publie sa clé publique et son empreinte `kid` dans `vault.capabilities`.
- **Un écrivain** (scada) scelle le contenu pour la clé du slot, lié au chemin (`purpose: "write"`). Il épingle le `kid` du slot (`vaultKid`) : si le broker, ou quiconque sur le chemin, substitue une autre clé, l'écriture est refusée (`untrusted_key`) avant que rien ne parte.
- **Un lecteur** envoie sa clé publique dans `vault.read`. Le slot scelle le contenu pour elle, lié au chemin et à la version (`purpose: "read"`). Le lecteur peut générer une paire par processus : rien de ce qu'il lit ne lui survit.

Enveloppe : `{ alg, kid, epk, iv, ct }`. Une paire éphémère par message, un secret partagé par ECDH, une clé AES-256 dérivée par HKDF-SHA256, AES-256-GCM avec le contexte en données associées. Une enveloppe ne s'ouvre ni pour une autre clé, ni pour un autre chemin, une autre version ou l'autre sens. Un octet modifié la rend illisible (`invalid_envelope`).

Restent en clair, par nécessité : le chemin, la version, les dates, le type (`keys` ou `file`) et les audiences. C'est ce que le broker et la policy doivent voir. Le nom d'un fichier, lui, voyage chiffré.

Entre le slot et OpenBao : HTTPS. `OpenBaoVaultStore` refuse le HTTP en clair, sauf vers une adresse de loopback ou avec `allowInsecureHttp` sur un banc. Au repos, la barrière d'OpenBao chiffre.

Ce qui est vérifié par les tests : un secret canari ne figure dans aucun message qui traverse MCP, ni à travers un vrai broker (`tests/broker.test.ts`), ni à travers un slot direct (`tests/conformance.test.ts`).

## Autorisation (broker)

Le broker ne lit jamais les arguments des outils, et sa policy est figée au démarrage : aucun slot ne peut donner un droit à un autre. Le partage passe donc par des ressources que la policy connaît déjà.

Espace de ressources, sous le namespace déclaré (ex. `/site1/vault`) :

- `<namespace>/secrets/<chemin>` : un secret, ex. `/site1/vault/secrets/scada/mqtt` ;
- `<namespace>/audiences/<nom>` : une audience, ex. `/site1/vault/audiences/mqtt`.

| Outil | Capability | Ressource vérifiée | Résultat rapporté |
|---|---|---|---|
| `vault.capabilities` | aucune | aucune | non |
| `vault.list`, `vault.describe` | `vault.read` | le secret, ou l'une de ses audiences (filtrage) | non |
| `vault.read` | `vault.read` | le secret, ou l'une de ses audiences | non |
| `vault.write` | `vault.write` | le secret | oui |
| `vault.share` | `vault.share` | le secret, et chaque audience ajoutée | oui |
| `vault.delete` | `vault.admin` | le secret | oui |

- **Partage en deux temps.** scada, propriétaire de `scada/**`, partage `scada/mqtt` avec `mqtt`. La policy donne `vault.read` sur `/site1/vault/audiences/mqtt` au groupe `mqtt-clients`. Ajouter un slot MQTT, c'est l'ajouter au groupe ; révoquer le partage, c'est retirer l'audience.
- **Publier vers une audience se mérite aussi** : il faut `vault.share` sur l'audience. Sinon, n'importe quel propriétaire pourrait pousser un secret vers n'importe quel groupe.
- **Pas de sondage des noms** : un appelant sans droit reçoit `policy_denied`, que le secret existe ou non. `not_found` ne répond qu'à qui aurait eu le droit.
- **Déclaration** (`buildVaultDeclaration`) : domaine `vault`, quatre capabilities, `resultsRequired: ["vault.write", "vault.share", "vault.admin"]`. Aucun rôle ni aucune assignation.
- **`IAccessGuard`** de mcp-uns, réutilisé tel quel : `BrokerAccessGuard(transport.broker)` en production, `openGuard()` sur un banc.

## Backend OpenBao

| Contrat | OpenBao KV v2 |
|---|---|
| secret | une entrée, sous un préfixe propre au slot (ex. `mcp-vault/site1`) |
| `keys` | les données de l'entrée, telles quelles : `bao kv get` les lit nativement |
| `file` | ses champs, plus le marqueur réservé `@mcp-vault/kind: "file"` : chaque version dit ce qu'elle est |
| version, `cas` | version KV, check-and-set KV |
| audiences, type | métadonnées personnalisées `mcp-vault.audiences` (liste séparée par des virgules) et `mcp-vault.kind` ; les autres clés sont préservées |
| `delete` | `DELETE metadata` : toutes les versions |
| `list` | parcours récursif de `LIST metadata`, borné à 10 000 entrées |

Une version supprimée en douceur hors du slot (`bao kv delete`) est traitée comme absente.

Le jeton du slot reçoit une policy OpenBao limitée à son préfixe (voir le README). Il peut venir d'une fonction (AppRole, Kubernetes) et n'apparaît jamais dans une erreur.

## Phasage

1. **Fait** : contrat, chiffrement, `MemoryVaultStore`, `OpenBaoVaultStore`, `VaultBehavior`, `VaultSlotStore`, déclaration, conformité. 85 tests, dont 11 contre un vrai broker et la conformité contre une imitation de l'API KV v2.
2. **Fait** : la conformité passe contre un vrai OpenBao 2.7.1 (`npm run test:live`). Elle a révélé qu'OpenBao refuse une métadonnée personnalisée vide (1 à 512 caractères) : sans audience, la clé est retirée.
3. **Ensuite** : notification de rotation (`resources/subscribe` sur un secret, pour qu'un slot MQTT recharge ses identifiants), secrets dynamiques OpenBao (identifiants de base de données à durée de vie).

## Questions ouvertes

- **Clé privée du slot vault** : variable d'environnement aujourd'hui. La garder dans OpenBao (moteur Transit) éviterait qu'elle vive en clair dans la configuration du slot.
- **Rejeu d'une écriture** : une enveloppe d'écriture capturée peut être rejouée sur le même chemin. `cas` le neutralise quand l'écrivain l'utilise ; faut-il lier `cas` au contexte de l'enveloppe ?
- **Rotation de la clé du slot** : publier deux clés pendant la transition, ou s'appuyer sur la ré-épingle des écrivains ?
