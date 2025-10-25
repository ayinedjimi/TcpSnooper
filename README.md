# 🚀 TcpSnooper


**WinToolsSuite – Security Tools for Network & Pentest**
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training

---

## 📋 Description

**TcpSnooper** liste toutes les connexions TCP et UDP actives sur la machine locale. Pour chaque connexion, l'outil affiche le protocole, les adresses locale/distante, l'état de la connexion, le PID et le nom du processus propriétaire. Permet la détection rapide de connexions suspectes ou non autorisées.

### Fonctionnalités principales

- **Énumération TCP** : toutes connexions TCP avec états (LISTEN, ESTABLISHED, etc.)
- **Énumération UDP** : toutes sockets UDP ouvertes
- **Association processus** : affiche PID et nom complet du processus
- **Rafraîchissement** : manuel ou automatique (intervalle 2 secondes)
- **Export CSV** : sauvegarde des connexions pour analyse
- **Interface temps réel** : ListView mis à jour dynamiquement

- --


## 📌 Prérequis

- Windows 10 / Windows Server 2016+ (x64)
- Visual Studio 2017+ avec outils C++
- Droits normaux (élévation recommandée pour accès à tous les processus)

- --


## Compilation

Ouvrez **x64 Native Tools Command Prompt for VS** :

```bat
cd WinToolsSuite\TcpSnooper
go.bat
```

L'exécutable `TcpSnooper.exe` sera créé.

- --


# 🚀 Lister connexions avec netstat (comparaison)

# 🚀 Créer listener test (PowerShell)

# 🚀 Puis vérifier dans TcpSnooper

## 🚀 Utilisation

1. **Lancer** : double-cliquer sur `TcpSnooper.exe`
2. **Visualiser** : connexions affichées automatiquement au démarrage
3. **Rafraîchir** : bouton "Rafraîchir" ou cocher "Auto-rafraîchir"
4. **Exporter** : bouton "Exporter CSV"

### Interface

- **Colonnes** :
  - Protocole : TCP ou UDP
  - Adresse locale : IP:port local
  - Adresse distante : IP:port distant (ou *:* pour UDP)
  - État : état connexion TCP (LISTEN, ESTABLISHED, etc.)
  - PID : Process ID
  - Processus : nom de l'exécutable

- **Boutons** :
  - Rafraîchir : mise à jour manuelle
  - Exporter CSV : sauvegarde résultats
  - Auto-rafraîchir : rafraîchissement automatique toutes les 2 secondes

- --


## Détection de Connexions Suspectes

Rechercher :
- **Connexions sortantes inattendues** : processus système se connectant à IPs externes
- **Ports inhabituels** : écoute sur ports non standard
- **Processus inconnus** : noms de processus suspects ou chemins non-Microsoft
- **Connexions ESTABLISHED multiples** : vers même IP externe (C2, exfiltration)

- --


## Environnement LAB-CONTROLLED

### Scénarios de test

1. **Connexions normales** : navigateur web, clients mail
2. **Serveurs locaux** : IIS, SQL Server, services RDP
3. **Simuler backdoor** : créer listener netcat simple (nc -l -p 4444)
4. **Observer** : TcpSnooper détectera le processus nc.exe en LISTEN

### Commandes de test

```powershell
netstat -ano

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 9999)
$listener.Start()
```

- --


## Logs

Fichier : `%TEMP%\WinTools_TcpSnooper_log.txt`

Contient :
- Horodatages rafraîchissements
- Exports CSV
- Activations/désactivations auto-refresh

- --


## Limitations

- **Processus système** : certains processus protégés peuvent afficher "<Accès refusé>"
- **IPv6** : version actuelle supporte IPv4 uniquement (TODO)
- **Performance** : auto-refresh avec milliers de connexions peut ralentir UI

- --


## 🔒 Sécurité & Éthique

⚠️ **Utilisation locale uniquement** : cet outil liste les connexions de la machine locale.

- Ne nécessite pas de droits réseau
- Respecter vie privée des utilisateurs
- Usage audit/forensics autorisé uniquement

- --


## Support

**Ayi NEDJIMI Consultants**
Expert en Cybersécurité
https://www.ayinedjimi-consultants.fr

- --


## 📄 Licence

MIT License - Voir `LICENSE.txt` à la racine.


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>