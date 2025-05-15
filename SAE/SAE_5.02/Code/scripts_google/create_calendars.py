from cal_setup import get_calendar_service

def createCalendar(nom_cal):
    service = get_calendar_service()

    new_calendar = {
        "summary": nom_cal,
        "timeZone": "Europe/Paris"
    }

    created_calendar = service.calendars().insert(body=new_calendar).execute()

    return created_calendar

def main():
    createCalendar("test_script")

if __name__ == "__main__":
    main()
