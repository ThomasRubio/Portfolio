# 💻 SAE 5.01 – Concevoir, réaliser et présenter une solution technique

**Traçage de véhicule par GNSS**

Bienvenue dans ce dossier dédiée à la **SAE 5.01**, un projet orienté électronique mêlant l'environnement Pycom à travers le réseau LoRaWan.

## 🎯 Objectifs

- **Objectif principal** :
Utiliser l’environnement Pycom pour transmettre les données GNSS d’un véhicule via le réseau LoRaWan de The Things Network (TTN) et visualiser sa position sur une carte via un serveur.

- **Objectif final** :
L’idée est de concevoir un système embarqué autonome sur batterie. Ce système ne doit consommer de l’énergie que lorsque c’est nécessaire (ex. : déplacement du véhicule).
Il doit donc fonctionner en mode basse consommation, en utilisant les modes sleep des cartes et modules. Lorsque le véhicule se déplace, le GNSS et la connexion LoRaWan sont activés grâce à un accéléromètre.
Le système peut également être réveillé à distance par un message depuis une page web.

## 📍 Contexte

- Projet en groupe de 4 ou 5 étudiants.

- **Temps global** : **44,5 heures**, réparties comme suit :
    - **Temps encadré** :
      - CM : 1,5h
      - TD : 4h + 1,5h = 6h
      - TP encadré : 7h
      - **Total encadré : 14,5h**
  - **Temps autonome** :
      - TP : 11 x 3,5h + 1,5h = **40h**

## 🧰 Environnement matériel

- Une carte FiPy avec un module FiPy ou LoPy4 (dans le véhicule, sert de nœud ou d’End Device).

- Une carte Expansion 3.0 avec un module FiPy ou LoPy (Gateway LoRaWan partagée par 2 groupes).

- Une antenne LoRa par module.

- Un Raspberry Pi (RPi) pour le serveur.

- Un Raspberry Pi configuré comme point d’accès Wi-Fi pour la Gateway TTIG.

## 💻 Environnement logiciel

- ATOM ou VS Code avec le package / extension Pymakr.

- Node-RED à installer sur le Raspberry Pi pour le serveur web avec cartographie.

- The Things Network (TTN) : https://www.thethingsnetwork.org

## ✅ Validations

**Validation 1** :

Envoyer des coordonnées en MQTT et les visualiser sur une carte via une page web (hors TTN).

  - **Étape 1** : Envoi des coordonnées de géolocalisation via Wi-Fi depuis l’End Device vers MQTT.
  
  - **Étape 2** : Visualisation de la position du véhicule via un lien http (Node-RED).

**Validation 2** :

Créer sur TTN une Application et une Gateway.

**Validation 3** :

- Créer une Application liée à l’End Device.

- Voir les messages circuler via une Gateway (TTIG).

- Respecter les règles de transmission (ex : Airtime calculator).

- **Étape 4** : Créer une Gateway et voir les messages dans l’Application TTN.

**Validation 4** :

- **Étape 5** : Récupérer le Payload sur TTN, le formater en JSON (*uplink* → *Payload formatters*).

**Validation 5** :

- **Étape 6** : Utiliser le broker MQTT TTN dans *Integrations*.

- **Étape 7** : Intégrer les messages MQTT dans Node-RED pour afficher la position.

**Validation 6** :

Connexion GNSS et LoRaWan au démarrage du véhicule.

- Par défaut, le Node est en basse consommation.

- **Étape 8** : L’accéléromètre active les modules et envoie les données via LoRa.

**Validation 7** :

Arrêt du suivi sur demande utilisateur (depuis la page web) et retour en mode basse consommation.

- **Étape 10** : Réception d’un message *downlink* (TTN → Payload formatter).

- **Étape 11** : Traitement de la demande dans le Node.
