from flask_marshmallow import Marshmallow
from marshmallow import fields
from models import (
    User, Groupe, Dossier, Tache, Droit, Etiquette,
    Invitation, Membre, Historique, SousTache, Commentaire,
    GoogleAgenda, GoogleTache, TacheUser
)

ma = Marshmallow()

# Schémas de base
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        exclude = ('mdp',)

    groupes_count = fields.Function(lambda obj: len(obj.groupes))
    taches_count = fields.Function(lambda obj: len(obj.taches))

class GroupeSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Groupe
        load_instance = True
        include_fk = True

    membres_count = fields.Function(lambda obj: len(obj.membres))
    dossiers_count = fields.Function(lambda obj: len(obj.dossiers))
    owner = fields.Nested('UserSchema', only=('id_user', 'username'))

class DossierSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Dossier

    id_dossier = ma.auto_field()
    nom = ma.auto_field()
    id_groupe = ma.auto_field()
    groupe = ma.Nested(GroupeSchema, only=('id_groupe', 'nom'))
    taches_count = ma.Function(lambda obj: Tache.query.filter_by(id_dossier=obj.id_dossier).count())

class TacheSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Tache
        load_instance = True
        include_fk = True

    etiquettes = ma.Nested('EtiquetteSchema', many=True)
    sous_taches_count = fields.Function(lambda obj: len(obj.sous_taches))
    commentaires_count = fields.Function(lambda obj: len(obj.commentaires))
    assigned_users = fields.Nested('UserSchema', many=True, only=('id_user', 'username'))
    created_by = fields.Nested('UserSchema', only=('id_user', 'username'))

class DroitSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Droit
        load_instance = True
        include_fk = True

    user = fields.Nested('UserSchema', only=('id_user', 'username'))
    tache = fields.Nested('TacheSchema', only=('id_tache', 'titre'))

class EtiquetteSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Etiquette
        load_instance = True

    taches_count = fields.Function(lambda obj: len(obj.taches))

class InvitationSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Invitation
        include_fk = True

    # Remplacer fields.auto_field() par ma.auto_field()
    id_invitation = ma.auto_field()
    id_groupe = ma.auto_field()
    id_user = ma.auto_field()
    statut = ma.auto_field()

    # Utiliser ma.Nested au lieu de fields.Nested
    groupe = ma.Nested('GroupeSchema', only=('id_groupe', 'nom'))
    user = ma.Nested('UserSchema', only=('id_user', 'username'))

class MembreSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Membre
        load_instance = True
        include_fk = True

    user = fields.Nested('UserSchema', only=('id_user', 'username', 'nom', 'prenom'))
    groupe = fields.Nested('GroupeSchema', only=('id_groupe', 'nom'))

class HistoriqueSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Historique
        load_instance = True
        include_fk = True

    user = fields.Nested('UserSchema', only=('id_user', 'username'))
    tache = fields.Nested('TacheSchema', only=('id_tache', 'titre'))
    date_formatted = fields.Function(lambda obj: obj.date.strftime("%Y-%m-%d %H:%M:%S"))

class SousTacheSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = SousTache
        load_instance = True
        include_fk = True

    tache = fields.Nested('TacheSchema', only=('id_tache', 'titre'))
    date_fin_formatted = fields.Function(lambda obj: obj.date_fin.strftime("%Y-%m-%d") if obj.date_fin else None)

class CommentaireSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Commentaire
        include_fk = True

    id_commentaire = ma.auto_field()
    id_tache = ma.auto_field()
    id_user = ma.auto_field()
    commentaire = ma.auto_field()
    date_commentaire = ma.auto_field()
    date_formatted = ma.Function(lambda obj: obj.date_commentaire.strftime("%Y-%m-%d %H:%M:%S"))

    # Relations
    user = ma.Nested('UserSchema', only=('id_user', 'username'))
    tache = ma.Nested('TacheSchema', only=('id_tache', 'titre'))

class GoogleAgendaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = GoogleAgenda
        load_instance = True
        include_fk = True

    dossier = fields.Nested('DossierSchema', only=('id_dossier', 'nom'))

class GoogleTacheSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = GoogleTache
        load_instance = True
        include_fk = True

    tache = fields.Nested('TacheSchema', only=('id_tache', 'titre'))

class TacheUserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = TacheUser
        load_instance = True
        include_fk = True

    user = fields.Nested('UserSchema', only=('id_user', 'username'))
    tache = fields.Nested('TacheSchema', only=('id_tache', 'titre'))

# Initialisation des schémas
# Schémas simples
user_schema = UserSchema()
users_schema = UserSchema(many=True)

groupe_schema = GroupeSchema()
groupes_schema = GroupeSchema(many=True)

dossier_schema = DossierSchema()
dossiers_schema = DossierSchema(many=True)

tache_schema = TacheSchema()
taches_schema = TacheSchema(many=True)

droit_schema = DroitSchema()
droits_schema = DroitSchema(many=True)

etiquette_schema = EtiquetteSchema()
etiquettes_schema = EtiquetteSchema(many=True)

invitation_schema = InvitationSchema()
invitations_schema = InvitationSchema(many=True)

membre_schema = MembreSchema()
membres_schema = MembreSchema(many=True)

historique_schema = HistoriqueSchema()
historiques_schema = HistoriqueSchema(many=True)

sous_tache_schema = SousTacheSchema()
sous_taches_schema = SousTacheSchema(many=True)

commentaire_schema = CommentaireSchema()
commentaires_schema = CommentaireSchema(many=True)

google_agenda_schema = GoogleAgendaSchema()
google_agendas_schema = GoogleAgendaSchema(many=True)

google_tache_schema = GoogleTacheSchema()
google_taches_schema = GoogleTacheSchema(many=True)

tache_user_schema = TacheUserSchema()
tache_users_schema = TacheUserSchema(many=True)