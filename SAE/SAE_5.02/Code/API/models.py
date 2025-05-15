from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'USER'
    id_user = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nom = db.Column(db.String(40), nullable=False)
    prenom = db.Column(db.String(40), nullable=False)
    mail = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(40), nullable=False)
    mdp = db.Column(db.String(120), nullable=False)
    otp_enabled = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32))

    # Relations
    groupes = db.relationship('Groupe', backref='user', lazy=True)
    taches = db.relationship('Tache', backref='user', lazy=True)
    droits = db.relationship('Droit', backref='user', lazy=True)
    membres = db.relationship('Membre', backref='user', lazy=True)
    invitations = db.relationship('Invitation', backref='user', lazy=True)
    commentaires = db.relationship('Commentaire', backref='user', lazy=True)
    historiques = db.relationship('Historique', backref='user', lazy=True)

class Groupe(db.Model):
    __tablename__ = 'GROUPE'
    id_groupe = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nom = db.Column(db.String(60), nullable=False)
    synchro = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    permissions = db.Column(db.Integer, default=0)

    # Relations
    dossiers = db.relationship('Dossier', backref='groupe', lazy=True, cascade="all, delete-orphan")
    membres = db.relationship('Membre', backref='groupe', lazy=True, cascade="all, delete-orphan")
    invitations = db.relationship('Invitation', backref='groupe', lazy=True, cascade="all, delete-orphan")

class Dossier(db.Model):
    __tablename__ = 'DOSSIER'
    id_dossier = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nom = db.Column(db.String(300), nullable=False)  # Modifié à 300
    id_groupe = db.Column(db.Integer, db.ForeignKey('GROUPE.id_groupe'))

    # Relations
    taches = db.relationship('Tache', backref='dossier', lazy=True, cascade="all, delete-orphan")
    google_agendas = db.relationship('GoogleAgenda', backref='dossier', lazy=True, cascade="all, delete-orphan")

class Tache(db.Model):
    __tablename__ = 'TACHES'
    id_tache = db.Column(db.Integer, primary_key=True, autoincrement=True)
    titre = db.Column(db.String(100), nullable=False)  # Modifié à 100
    sous_titre = db.Column(db.String(60))
    texte = db.Column(db.String(200))
    commentaire = db.Column(db.String(200))
    date_debut = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    date_fin = db.Column(db.TIMESTAMP)
    priorite = db.Column(db.Integer)
    statut = db.Column(db.Integer, default=0)
    id_dossier = db.Column(db.Integer, db.ForeignKey('DOSSIER.id_dossier'))
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))

    # Relations
    droits = db.relationship('Droit', backref='tache', lazy=True, cascade="all, delete-orphan")
    etiquettes = db.relationship('Etiquette', secondary='TACHE_ETIQUETTE', backref='taches')
    sous_taches = db.relationship('SousTache', backref='tache', lazy=True, cascade="all, delete-orphan")
    commentaires = db.relationship('Commentaire', backref='tache', lazy=True, cascade="all, delete-orphan")
    historiques = db.relationship('Historique', backref='tache', lazy=True)
    google_taches = db.relationship('GoogleTache', backref='tache', lazy=True, cascade="all, delete-orphan")
    users = db.relationship('User', secondary='tache_user', backref=db.backref('taches_assignees', lazy='dynamic'))

class Droit(db.Model):
    __tablename__ = 'DROIT'
    id_droit = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache'))
    droit = db.Column(db.Integer, nullable=False)

class Etiquette(db.Model):
    __tablename__ = 'ETIQUETTES'
    id_etiquettes = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String(300), nullable=False)

class TacheEtiquette(db.Model):
    __tablename__ = 'TACHE_ETIQUETTE'
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache', ondelete='CASCADE'), primary_key=True)
    id_etiquettes = db.Column(db.Integer, db.ForeignKey('ETIQUETTES.id_etiquettes', ondelete='CASCADE'), primary_key=True)

class Invitation(db.Model):
    __tablename__ = 'INVITATION'
    id_invitation = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_groupe = db.Column(db.Integer, db.ForeignKey('GROUPE.id_groupe'))
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    statut = db.Column(db.String(20), default='En attente')

class Membre(db.Model):
    __tablename__ = 'MEMBRE'
    id_membre = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_groupe = db.Column(db.Integer, db.ForeignKey('GROUPE.id_groupe'))
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    role = db.Column(db.Enum('admin', 'lecture', 'éditeur'), default='lecture')

class Historique(db.Model):
    __tablename__ = 'HISTORIQUE'
    id_historique = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache'))
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    action = db.Column(db.String(255))
    date = db.Column(db.TIMESTAMP, default=datetime.utcnow)

class SousTache(db.Model):
    __tablename__ = 'SOUS_TACHES'
    id_sous_tache = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache'))
    titre = db.Column(db.String(255))
    priorite = db.Column(db.Integer)
    date_fin = db.Column(db.Date)
    statut = db.Column(db.Integer)

class Commentaire(db.Model):
    __tablename__ = 'COMMENTAIRES'
    id_commentaire = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache'))
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user'))
    commentaire = db.Column(db.Text)
    date_commentaire = db.Column(db.TIMESTAMP, default=datetime.utcnow)

class TacheUser(db.Model):
    __tablename__ = 'tache_user'
    id_tache = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache', ondelete='CASCADE'), primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey('USER.id_user', ondelete='CASCADE'), primary_key=True)

class GoogleAgenda(db.Model):
    __tablename__ = 'GOOGLE_AGENDA'
    id_gagenda = db.Column(db.Integer, primary_key=True, autoincrement=True)
    google_id_cal = db.Column(db.String(100))  # Modifié à 100
    local_id_cal = db.Column(db.Integer, db.ForeignKey('DOSSIER.id_dossier'))

class GoogleTache(db.Model):
    __tablename__ = 'GOOGLE_TACHE'
    id_gtache = db.Column(db.Integer, primary_key=True, autoincrement=True)
    google_id_event = db.Column(db.String(100))  # Modifié à 100
    local_id_event = db.Column(db.Integer, db.ForeignKey('TACHES.id_tache'))