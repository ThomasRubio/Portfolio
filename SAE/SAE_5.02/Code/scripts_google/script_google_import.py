from datetime import date, datetime
from datetime import timezone
import pymysql
from calendars_get import getCalendars
from events_get import getEvents


def importCal(connection, id_user, id_groupe, id_cal=""):
    if not id_cal:
        calendars = getCalendars()

        for cal in calendars[2:]:
            events = getEvents(cal['id'])

            with connection.cursor() as cursor:
                cal_summary = cal['summary'].replace("'", "")[:59]
                cal_id = cal['id']

                cursor.execute(f"INSERT INTO DOSSIER (nom, id_groupe) VALUES ('{cal_summary}', {id_groupe})")
                connection.commit()
                cursor.execute("SELECT MAX(id_dossier) FROM DOSSIER")
                new_calendar = cursor.fetchone()[0]
                cursor.execute(f"INSERT INTO GOOGLE_AGENDA (google_id_cal, local_id_cal) VALUES ('{cal_id}', {new_calendar})")

                for event in events:
                    if 'date' in event['start'].keys():
                        start = datetime.combine(datetime.strptime(event['start']['date'], '%Y-%m-%d'), datetime.min.time())
                    else:
                        start = datetime.fromisoformat(event['start']['dateTime']).astimezone(timezone.utc)
                        start.strftime('%Y-%m-%d %H:%M:%S')

                    if 'date' in event['end'].keys():
                        end = datetime.combine(datetime.strptime(event['end']['date'], '%Y-%m-%d'), datetime.min.time())
                    else:
                        end = datetime.fromisoformat(event['end']['dateTime']).astimezone(timezone.utc)
                        end.strftime('%Y-%m-%d %H:%M:%S')

                    if 'summary' in event.keys():
                        ev_summary = event['summary'].replace("'", "")[:59]
                    else:
                        ev_summary = ""
                    ev_id = event['id']

                    cursor.execute(f"INSERT INTO TACHES (titre, date_debut, date_fin, id_dossier, id_user) VALUES ('{ev_summary}', '{str(start)[:-6]}', '{str(end)[:-6]}', {new_calendar}, {id_user})")
                    connection.commit()
                    cursor.execute(f"SELECT MAX(id_tache) FROM TACHES")
                    new_event = cursor.fetchone()[0]
                    cursor.execute(f"INSERT INTO GOOGLE_TACHE (google_id_event, local_id_event) VALUES ('{ev_id}', {new_event})")

    elif id_cal:
        calendar = getCalendars(id_cal)
        events = getEvents(id_cal)

        with connection.cursor() as cursor:
            cal_summary = calendar['summary'].replace("'", "")[:59]
            cal_id = calendar['id']

            cursor.execute(f"INSERT INTO DOSSIER (nom, id_groupe) VALUES ('{cal_summary}', {id_groupe})")
            connection.commit()
            cursor.execute("SELECT MAX(id_dossier) FROM DOSSIER")
            new_calendar = cursor.fetchone()[0]
            cursor.execute(f"INSERT INTO GOOGLE_AGENDA (google_id_cal, local_id_cal) VALUES ('{cal_id}', {new_calendar})")

            for event in events:
                if 'date' in event['start'].keys():
                    start = datetime.combine(datetime.strptime(event['start']['date'], '%Y-%m-%d'), datetime.min.time())
                else:
                    start = datetime.fromisoformat(event['start']['dateTime']).astimezone(timezone.utc)
                    start.strftime('%Y-%m-%d %H:%M:%S')

                if 'date' in event['end'].keys():
                    end = datetime.combine(datetime.strptime(event['end']['date'], '%Y-%m-%d'), datetime.min.time())
                else:
                    end = datetime.fromisoformat(event['end']['dateTime']).astimezone(timezone.utc)
                    end.strftime('%Y-%m-%d %H:%M:%S')

                if 'summary' in event.keys():
                    ev_summary = event['summary'].replace("'", "")[:59]
                else:
                    ev_summary = ""
                ev_id = event['id']

                cursor.execute(f"INSERT INTO TACHES (titre, date_debut, date_fin, id_dossier, id_user) VALUES ('{ev_summary}', '{str(start)[:-6]}', '{str(end)[:-6]}', {new_calendar}, {id_user})")
                connection.commit()
                cursor.execute(f"SELECT MAX(id_tache) FROM TACHES")
                new_event = cursor.fetchone()[0]
                cursor.execute(f"INSERT INTO GOOGLE_TACHE (google_id_event, local_id_event) VALUES ('{ev_id}', {new_event})")

    connection.commit()
    connection.close()


def main():
    importCal(1, 1, "test_2")


if __name__ == "__main__":
    main()
