from datetime import datetime
from cal_setup import get_calendar_service

def createEvent(cal_id, nom_event, date_debut, date_fin):
    service = get_calendar_service()

    if type(date_debut) is str:
        start = datetime.strptime(date_debut, '%Y-%m-%d %H:%M:%S').isoformat()
    else:
        start = date_debut.isoformat()

    if type(date_fin) is str:
        end = datetime.strptime(date_fin, '%Y-%m-%d %H:%M:%S').isoformat()
    else:
        end = date_fin.isoformat()

    created_event = service.events().insert(calendarId=cal_id, body={
        "summary": nom_event,
        "start": {"dateTime": start, "timeZone": "Europe/Paris"},
        "end": {"dateTime": end, "timeZone": "Europe/Paris"}
        }
    ).execute()

    return created_event

def main():
    createEvent("test_script", "2024-11-16 15:32:00", "2024-11-16 16:18:00")

if __name__ == "__main__":
    main()
