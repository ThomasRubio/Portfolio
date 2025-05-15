#!/bin/bash

# Rendre le script exécutable si ce n'est pas déjà le cas
[ -x "$0" ] || chmod +x "$0"

# Stocke le chemin actuel dans la variable cheminActuel
cheminActuel=$(pwd)

# Liste des paquets nécessaires à installer via le gestionnaire de paquets
paquets=("docker-compose")

# Liste des dépendances spécifiques pour le projet Python
paquetsPython=("default-mysql-client" \
         "libegl1" \
         "libgl1-mesa-glx" \
         "libglib2.0-0" \
         "libxkbcommon0" \
         "libfontconfig1" \
         "libice6" \
         "libsm6" \
         "libxext6" \
         "libxrender1" \
         "libdbus-1-3" \
         "libxcb1" \
         "libx11-xcb1" \
         "libxcb-render0" \
         "libxcb-shape0" \
         "libxcb-xfixes0" \
         "libxcb-shm0" \
         "libxcb-cursor0" \
         "xcb" \
         "qtbase5-dev" \
         "qtbase5-dev-tools" \
         "libxkbcommon-x11-0" \
         "libqt5gui5" \
         "libqt5widgets5" \
         "libqt5core5a" \
         "libxkbcommon-x11-0" \
         "x11-apps" \
         "libatomic1" \
         "libpulse0" \
         "libnss3" \
         "libasound2" \
         "alsa-utils" \
         "espeak-ng" \
         "python3-pyqt6" )
# Détection du gestionnaire de paquets disponible sur le système
if command -v apt &> /dev/null; then
    gestionnaireDePaquets="apt"
    updateCommand="apt-get update"
    installCommand="apt-get install -y"
elif command -v dnf &> /dev/null; then
    gestionnaireDePaquets="dnf"
    updateCommand="dnf check-update || true"
    installCommand="dnf install -y"
elif command -v pacman &> /dev/null; then
    gestionnaireDePaquets="pacman"
    updateCommand="pacman -Syu --noconfirm"
    installCommand="pacman -S --noconfirm"
elif command -v zypper &> /dev/null; then
    gestionnaireDePaquets="zypper"
    updateCommand="zypper refresh"
    installCommand="zypper install -y"
elif command -v snap &> /dev/null; then
    gestionnaireDePaquets="snap"
    updateCommand="snap refresh"
    installCommand="snap install"
elif command -v flatpak &> /dev/null; then
    gestionnaireDePaquets="flatpak"
    updateCommand="flatpak update"
    installCommand="flatpak install -y"
else
    echo "Aucun gestionnaire de paquets trouvé"
    exit 1
fi

# Mise à jour des dépôts et installation des paquets nécessaires
$updateCommand
$installCommand "${paquets[@]}"

# Création du fichier .desktop pour l'application
cat <<EOF > "todoux.desktop"
[Desktop Entry]
Type=Application
Name=To Doux
Comment=a
Exec=bash $cheminActuel/todoux.sh
Icon=$cheminActuel/logo.png
EOF

# Création d'un script pour lancer l'application Docker
cat <<EOF > "todoux.sh"
docker-compose -f $cheminActuel/docker-compose.yml up -d
EOF

# Création du fichier docker-compose.yml pour définir le service Docker
cat <<EOF > "docker-compose.yml"
version: "3"

services:
 python-app:
    build:
      context: $cheminActuel/
      dockerfile: Dockerfile.txt
    container_name: python-app
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix
      - $cheminActuel:$cheminActuel
    environment:
      - DISPLAY=:0
    privileged: true  
    working_dir: $cheminActuel/

 mysql-db:
   image: mysql:8.0
   container_name: mysql-db
   environment:
     MYSQL_ROOT_PASSWORD: root
     MYSQL_USER: todoux_user
     MYSQL_PASSWORD: root
     MYSQL_DATABASE: todolist_db
   ports:
     - "3306:3306"
   volumes:
     - mysql_data:/var/lib/mysql
     - ./init.sql:/docker-entrypoint-initdb.d/init.sql

volumes:
  mysql_data:
EOF

# Création du fichier init.sql pour initialiser la base de données
cat <<EOF > "init.sql"
CREATE TABLE USER (
    id_user INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(40) NOT NULL,
    prenom VARCHAR(40) NOT NULL,
    mail VARCHAR(120) NOT NULL,
    username VARCHAR(40) NOT NULL,
    mdp VARCHAR(120),
    otp_enabled TINYINT(1) DEFAULT 0,
    otp_secret VARCHAR(32)
);

CREATE TABLE GROUPE (
    id_groupe INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(60) NOT NULL,
    synchro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    id_user INT,
    date_creation DATETIME DEFAULT CURRENT_TIMESTAMP,
    permissions INT DEFAULT 0,
    FOREIGN KEY (id_user) REFERENCES USER(id_user)
);

CREATE TABLE DOSSIER (
    id_dossier INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(60) NOT NULL,
    id_groupe INT,
    FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE
);

CREATE TABLE TACHES (
    id_tache INT AUTO_INCREMENT PRIMARY KEY,
    titre VARCHAR(60) NOT NULL,
    sous_titre VARCHAR(60),
    texte VARCHAR(200),
    commentaire VARCHAR(200),
    date_debut TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_fin TIMESTAMP,
    priorite INT,
    statut INT DEFAULT 0,
    id_dossier INT,
    id_user INT,
    FOREIGN KEY (id_dossier) REFERENCES DOSSIER(id_dossier) ON DELETE CASCADE,
    FOREIGN KEY (id_user) REFERENCES USER(id_user)
);

CREATE TABLE DROIT (
    id_droit INT AUTO_INCREMENT PRIMARY KEY,
    id_user INT,
    id_tache INT,
    droit INT NOT NULL,
    FOREIGN KEY (id_user) REFERENCES USER(id_user),
    FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache)
);

CREATE TABLE ETIQUETTES (
    id_etiquettes INT AUTO_INCREMENT PRIMARY KEY,
    description VARCHAR(300) NOT NULL
);

CREATE TABLE TACHE_ETIQUETTE (
    id_tache INT,
    id_etiquettes INT,
    PRIMARY KEY (id_tache, id_etiquettes),
    FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
    FOREIGN KEY (id_etiquettes) REFERENCES ETIQUETTES(id_etiquettes) ON DELETE CASCADE
);

CREATE TABLE INVITATION (
    id_invitation INT AUTO_INCREMENT PRIMARY KEY,
    id_groupe INT,
    id_user INT,
    statut VARCHAR(20) DEFAULT 'En attente',
    FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE,
    FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
);

CREATE TABLE MEMBRE (
    id_membre INT AUTO_INCREMENT PRIMARY KEY,
    id_groupe INT,
    id_user INT,
    role ENUM('admin', 'lecture', 'éditeur') DEFAULT 'lecture',
    FOREIGN KEY (id_groupe) REFERENCES GROUPE(id_groupe) ON DELETE CASCADE,
    FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
);

CREATE TABLE HISTORIQUE (
    id_historique INT AUTO_INCREMENT PRIMARY KEY,
    id_tache INT,
    id_user INT,
    action VARCHAR(255),
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache),
    FOREIGN KEY (id_user) REFERENCES USER(id_user)
);

CREATE TABLE SOUS_TACHES (
    id_sous_tache INT AUTO_INCREMENT PRIMARY KEY,
    id_tache INT,
    titre VARCHAR(255),
    priorite INT,
    date_fin DATE,
    statut INT,
    FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE
);

CREATE TABLE COMMENTAIRES (
    id_commentaire INT AUTO_INCREMENT PRIMARY KEY,
    id_tache INT,
    id_user INT,
    commentaire TEXT,
    date_commentaire TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_tache) REFERENCES TACHES(id_tache) ON DELETE CASCADE,
    FOREIGN KEY (id_user) REFERENCES USER(id_user) ON DELETE CASCADE
);

CREATE TABLE GOOGLE_AGENDA (
    id_gagenda INT AUTO_INCREMENT PRIMARY KEY,
    google_id_cal VARCHAR(100),
    local_id_cal INT,
    FOREIGN KEY (local_id_cal) REFERENCES DOSSIER(id_dossier) ON DELETE CASCADE
);

CREATE TABLE GOOGLE_TACHE (
    id_gtache INT AUTO_INCREMENT PRIMARY KEY,
    google_id_event VARCHAR(100),
    local_id_event INT,
    FOREIGN KEY (local_id_event) REFERENCES TACHES(id_tache) ON DELETE CASCADE
);

CREATE TABLE TACHE_USER (
    id_tache INT NOT NULL,
    id_user INT NOT NULL,
    PRIMARY KEY (id_tache, id_user)
);
EOF

# Création du fichier Dockerfile pour configurer l'image Docker
cat <<EOF > "Dockerfile.txt"
# Utiliser une image Python 3.12
FROM python:3.12
FROM continuumio/miniconda3

# Installation des dépendances système nécessaires au projet
RUN $updateCommand && $installCommand \\
$(printf '    %s \\\n' "${paquetsPython[@]}" | sed '$s/ \\//')

# Création d'un environnement conda avec Python 3.9 et PyQt
RUN conda create -n myenv python=3.9 pyqt

# Installation des dépendances Python
SHELL ["conda", "run", "-n", "myenv", "/bin/bash", "-c"]
WORKDIR /home/toto/Documents
COPY requirement.txt ./
RUN pip install --no-cache-dir -r requirement.txt

# Copie du fichier source de l'application
COPY todoux.py ./

# Ajout d'un fichier de configuration ALSA dans le conteneur
RUN echo "pcm.!default { type hw card 0 }" > /etc/asound.conf && \
    echo "ctl.!default { type hw card 0 }" >> /etc/asound.conf

# Configuration pour l'affichage graphique via X11
ENV DISPLAY=:0

# Commande par défaut pour démarrer l'application
CMD ["conda", "run", "-n", "myenv", "python3", "todoux.py"]
EOF

# Création du fichier requirements.txt pour les dépendances Python
cat <<EOF > "requirement.txt"
PyQt6-WebEngine
google-api-python-client
google_auth_oauthlib
replication
PyQt6
bcrypt
pymysql
sshtunnel
captcha
Pillow
pyotp
qrcode
numpy
matplotlib
scikit-learn
reportlab
pyttsx3
EOF

# Modification des permissions et déplacement des fichiers nécessaires
chmod +x todoux.sh
chmod +x todoux.desktop
chown toto:toto todoux.desktop
mv todoux.desktop /usr/share/applications/
chown toto:toto todoux.sh
chown toto:toto docker-compose.yml
chown toto:toto Dockerfile.txt

# Autorisation pour l'utilisateur "toto" d'utiliser Docker
chown root:toto /var/run/docker.sock

# Autorisation d'accès local à X11 pour l'affichage graphique
xhost +local:
