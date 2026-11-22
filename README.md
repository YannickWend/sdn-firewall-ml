# Firewall SDN dynamique avec Machine Learning

Mini-projet de sécurité réseau : un réseau d'entreprise émulé sous **Mininet**, piloté par un contrôleur **Ryu** (OpenFlow 1.3), protégé par un firewall dont les règles s'adaptent automatiquement grâce à un modèle de **Machine Learning**.

| Partie | Responsable | État |
|---|---|---|
| Infrastructure SDN : topologie, L2/STP, L3/routage, EtherChannel |  🟢 L2 et L3 terminés, EtherChannel en cours |
| Firewall (ACL statiques + blocage dynamique) et Machine Learning |  ⚪ À venir |

---

## Topologie

Architecture hiérarchique (cœur / distribution / accès) segmentée en VLAN.

```
                 Internet
                    │
                  nat0 (10.1.0.254)
                    │ port 4 (transit non tagué)
   att1 ───────── S-Coeur (L3, racine STP)
  VLAN 99   port 3  │ 1           │ 2
                    │             │
                 S-DIST1 ═════ S-DIST2        ═══ : double lien po1 (EtherChannel / secours STP)
                    │ 4    2,3    │ 4    │ 5
                    │           srv1    srv2   (VLAN 50)
                  S-ACC
     ┌──────┬───────┼───────┬───────┬──────┐
   tel1   tel2    inv1    inv2    emp1   emp2
   VLAN 20 (voix)  VLAN 30 (invités)  VLAN 40 (employés)
```

| Switch | DPID | Rôle | Priorité STP |
|---|---|---|---|
| `coeur` | `0000000000000001` | L3 : passerelles, routage, sortie NAT | 4096 (racine) |
| `dist1` | `0000000000000002` | L2 : distribution vers l'accès | 8192 |
| `dist2` | `0000000000000003` | L2 : distribution vers les serveurs | 12288 |
| `acc` | `0000000000000004` | L2 : accès des VLAN 20, 30, 40 | 32768 |

### Plan d'adressage et politique de sécurité

Réseau global : `10.1.0.0/16`. Le 3ᵉ octet correspond au numéro du VLAN.

| VLAN | Nom | Réseau | Passerelle | Peut joindre | Interdit |
|:---:|---|---|---|---|---|
| 20 | Voix | `10.1.20.0/24` | `10.1.20.254` | Autres téléphones, serveur VoIP | Employés, invités |
| 30 | Invités | `10.1.30.0/24` | `10.1.30.254` | Internet uniquement | Tous les VLAN internes |
| 40 | Employés | `10.1.40.0/24` | `10.1.40.254` | Serveurs, Internet | Voix |
| 50 | Serveurs | `10.1.50.0/24` | `10.1.50.254` | Répond aux employés | Initier vers les autres VLAN |
| 99 | Externe (Internet simulé) | `10.1.99.0/24` | `10.1.99.254` | Serveur web (port 80) uniquement | Tout le reste |
| — | Transit vers `nat0` | `10.1.0.0/24` | `10.1.0.1` (S-Coeur) | Sortie Internet | — |

> **Règles statiques** : ce tableau, appliqué par le firewall au démarrage.
> **Règles dynamiques** : ajoutées par le modèle ML lorsqu'un comportement malveillant est détecté, y compris pour un hôte autorisé par les règles statiques.

| Hôte | VLAN | IP | Port | Rôle |
|---|:---:|---|---|---|
| tel1, tel2 | 20 | 10.1.20.1, .2 | acc:2, acc:3 | Téléphones IP |
| inv1, inv2 | 30 | 10.1.30.1, .2 | acc:4, acc:5 | Invités (inv2 = attaquant interne) |
| emp1, emp2 | 40 | 10.1.40.1, .2 | acc:6, acc:7 | Employés |
| srv1 | 50 | 10.1.50.1 | dist2:4 | Serveur web (HTTP) |
| srv2 | 50 | 10.1.50.2 | dist2:5 | Serveur DNS (dnsmasq → 8.8.8.8) |
| att1 | 99 | 10.1.99.1 | coeur:3 | Attaquant externe |
| test1 | 20 | 10.1.20.99 | dist2:6 | Hôte de test (temporaire) |

---

## Structure du dépôt

```
SDN/
├── control/                 # Applications Ryu
│   ├── config_reseau.py     # Lecture centralisée de reseau.json
│   ├── L2.py                # Switch L2 : STP + apprentissage MAC par VLAN
│   └── L3.py                # Switch L3 (S-Coeur) : routage inter-VLAN + NAT
├── topology/
│   ├── topologie.py         # Construction du réseau Mininet
│   └── reseau.json          # Description complète du réseau (source unique)
└── README.md
```

**`reseau.json` est la seule source de vérité** : switches, DPID, ports, VLAN, hôtes, agrégation et NAT y sont décrits. Le script Mininet et les applications Ryu lisent ce même fichier. Pour modifier le réseau, on modifie le JSON, jamais le code.

---

## Installation

Testé sur Kali Linux (VM), Python 3.10, Ryu 4.34.

```bash
# Mininet, Open vSwitch et outils
sudo apt install mininet openvswitch-switch dnsmasq-base

# Environnement Python avec uv
uv venv .env -p 3.10
source .env/bin/activate

# Ryu ne s'installe pas avec les versions récentes de setuptools : correctif obligatoire
uv pip install pip
python -m pip install "setuptools==67.6.1" wheel pbr
python -m pip install --no-build-isolation ryu==4.34 eventlet==0.30.2
ryu-manager --version          # doit afficher : ryu-manager 4.34
```

---

## Lancement

Si `reseau.json` n'est pas trouvé automatiquement, indiquer son chemin :

```bash
export RESEAU_CONFIG=~/SDN/topology/reseau.json
```

**Terminal 1 : contrôleur Ryu** (à lancer en premier)
```bash
cd ~/SDN/control
ryu-manager L2.py L3.py
```

**Terminal 2 : réseau Mininet**
```bash
sudo mn -c                             # nettoyage d'une éventuelle session précédente
cd ~/SDN/topology
python3 topologie.py --verifier        # vérifie le JSON sans rien lancer
sudo python3 topologie.py              # construit le réseau et ouvre la CLI
```

Attendre que les logs Ryu affichent les ports en `FORWARD` (convergence STP) avant de tester.

| Option de `topologie.py` | Effet |
|---|---|
| `--verifier` | Vérifie la configuration et affiche le plan, sans Mininet |
| `--sans-nat` | Pas de passerelle Internet |
| `--sans-services` | Ne démarre pas les serveurs web et DNS |
| `--config chemin` | Utilise un autre fichier de configuration |

> **Temporisations STP** : la section `stp` de `reseau.json` permet d'accélérer la convergence pendant le développement (`fwd_delay: 4`, `max_age: 6`, environ 8 s). Remettre les valeurs standard (`fwd_delay: 15`, `max_age: 20`) pour la démonstration.

---

## Pipeline OpenFlow

Chaque switch utilise deux tables. Chaque application n'écrit que dans **ses** tables, ce qui permet de les lancer ensemble sans conflit.

```
Paquet ──► Table 0 : SÉCURITÉ ──► Table 1 : ACHEMINEMENT ──► Port / Groupe po1
           (firewall)              (L2.py / L3.py)
```

| Table | Priorité | Règle | Écrite par | Cookie |
|:---:|:---:|---|---|:---:|
| 0 | 65535 | BPDU → contrôleur | stplib | — |
| 0 | 65534 | Port STP non actif → drop | stplib | — |
| 0 | 60000 | Blocage dynamique d'une IP (ML) | firewall | `0x10` |
| 0 | 50000 | Anti VLAN hopping | firewall | `0x10` |
| 0 | 30000–40000 | ACL statiques (drop ou `goto_table:1`) | firewall | `0x10` |
| 0 | 0 | Défaut → table 1 | L2 / L3 | `0x20` |
| 1 | 1000 | MAC passerelle + IP dst → routage | L3 (S-Coeur) | `0x31` |
| 1 | 100 | (VLAN, MAC dst) → port | L2 / L3 | `0x21` |
| 1 | 0 | Inconnu → contrôleur | L2 / L3 | `0x20` |

### Règles d'intégration pour le firewall

- La **table 0** appartient au firewall ; la **table 1** à l'infrastructure (ne pas y écrire).
- Un paquet autorisé doit faire `goto_table:1`, **pas** `OUTPUT:NORMAL` comme dans le `rest_firewall` du RyuBook.
- Priorités du firewall : strictement entre **1** et **65533**.
- Utiliser le cookie **`0x10`** et ne supprimer que les règles portant ce cookie.
- Réutiliser `config_reseau.py` (VLAN par port, adresses, rôles des switches) : rien en dur.
- Lancement commun : `ryu-manager L2.py L3.py firewall.py`

---

## Tests de validation

À exécuter dans la CLI `mininet>`.

| Commande | Résultat attendu | État |
|---|---|:---:|
| `tel1 ping -c 3 tel2` | Réponse (même VLAN, même switch) | ✅ |
| `tel1 ping -c 3 10.1.20.99` | Réponse (même VLAN, plusieurs switches) | ✅ |
| `tel1 ping -c 3 10.1.20.254` | La passerelle répond, `ttl=64` | ✅ |
| `emp1 ping -c 3 srv1` | Routage VLAN 40 → 50, `ttl=63` | ✅ |
| `att1 ping -c 3 srv1` | Routage VLAN 99 → 50 | ✅ |
| `tel1 ping -c 3 emp1` | Routage 20 → 40 (demi-tour sur le même port) | ✅ |
| `emp1 curl http://10.1.50.1` | Page du serveur web | ✅ |
| `emp1 ping -c 3 8.8.8.8` | Internet via le NAT | ✅ |
| `emp1 dig @10.1.50.2 google.com` | Résolution DNS par srv2 | ✅ |
| `link dist1 coeur down` puis `emp1 ping srv1` | Le trafic bascule sur po1 après reconvergence STP | ✅ |
| `sh ovs-ofctl -O OpenFlow13 dump-flows coeur table=1` | Règles `cookie=0x31` avec `set_field` et `dec_ttl` | ✅ |

> Sans firewall, `inv1 ping tel1` passe : c'est normal, la sécurité sera ajoutée en table 0.

---

## Feuille de route

- [x] Topologie Mininet pilotée par `reseau.json`
- [x] `config_reseau.py` : configuration centralisée
- [x] `L2.py` : STP, apprentissage MAC par VLAN, inondation limitée au VLAN
- [x] `L3.py` : passerelles, routage inter-VLAN, NAT
- [ ] `etherchannel.py` : agrégation de po1 (groupe OpenFlow SELECT, bascule instantanée)
- [ ] `firewall.py` : ACL statiques, anti VLAN hopping, API de blocage *(associé)*
- [ ] `moniteur.py` : statistiques des flux pour le ML
- [ ] `detection_ml.py` : classification du trafic et blocage dynamique *(associé)*
- [ ] Automatisation du déploiement
- [ ] Supervision (Prometheus / Grafana)

## Références

- *RYU SDN Framework* (RyuBook) : ch. 3 (monitor), ch. 5 (link aggregation), ch. 6 (spanning tree), ch. 10 (firewall), ch. 11 (router)
- Spécification OpenFlow 1.3
