import pymysql
from create_calendars import createCalendar
from create_events import createEvent


def exportCal(connection, id_user, nom_cal=""):
    if not nom_cal:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT DOSSIER.id_dossier,DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user={id_user}")
            calendars = cursor.fetchall()
            for calendar in calendars:
                created_cal = createCalendar(calendar[1])
                nom_cal = created_cal['summary']
                cursor.execute(f"INSERT INTO GOOGLE_AGENDA (google_id_cal, local_id_cal) VALUES ('{created_cal['id']}', '{calendar[0]}')")

                cursor.execute(f"SELECT id_tache, titre, date_debut, date_fin FROM TACHES INNER JOIN DOSSIER ON TACHES.id_dossier=DOSSIER.id_dossier WHERE DOSSIER.nom='{nom_cal}'")
                events = cursor.fetchall()
                for event in events:
                    created_event = createEvent(created_cal['id'], event[1], event[2], event[3])
                    cursor.execute(f"INSERT INTO GOOGLE_TACHE (google_id_event, local_id_event) VALUES ('{created_event['id']}', '{event[0]}')")

    elif nom_cal:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT DOSSIER.id_dossier,DOSSIER.nom FROM DOSSIER INNER JOIN GROUPE ON DOSSIER.id_groupe=GROUPE.id_groupe INNER JOIN USER ON GROUPE.id_user=USER.id_user WHERE USER.id_user={id_user} AND DOSSIER.nom='{nom_cal}'")
            calendar = cursor.fetchone()
            created_cal = createCalendar(calendar[1])
            cursor.execute(f"INSERT INTO GOOGLE_AGENDA (google_id_cal, local_id_cal) VALUES ('{created_cal['id']}', '{calendar[0]}')")

            cursor.execute(f"SELECT id_tache, titre, date_debut, date_fin FROM TACHES INNER JOIN DOSSIER ON TACHES.id_dossier=DOSSIER.id_dossier WHERE DOSSIER.nom='{nom_cal}'")
            events = cursor.fetchall()
            for event in events:
                created_event = createEvent(created_cal['id'], event[1], event[2], event[3])
                cursor.execute(f"INSERT INTO GOOGLE_TACHE (google_id_event, local_id_event) VALUES ('{created_event['id']}', '{event[0]}')")

    connection.commit()
    connection.close()


def main():
    nom_cal = "test_script_2"
    exportCal(1)


if __name__ == "__main__":
    main()
