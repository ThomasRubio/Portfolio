import datetime
from cal_setup import get_calendar_service

def getEvents(cal_id):
    service = get_calendar_service()

    now = datetime.datetime.utcnow().isoformat() + "Z"
    events_result = service.events().list(calendarId=cal_id).execute()

    return events_result['items']

def main():
    events = getEvents("19kfqt3ig4rq5iepknurad64mtllu0c3@import.calendar.google.com")

    for event in events:
        print(event['summary'])

if __name__ == "__main__":
    main()
