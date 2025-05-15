from cal_setup import get_calendar_service

def getCalendars(cal_id=""):
    service = get_calendar_service()
    if cal_id:
        calendars_result = service.calendarList().get(calendarId=cal_id).execute()
    else:
        calendars_result = service.calendarList().list().execute()

    if not cal_id:
        return calendars_result['items'][1:]
    else:
        return calendars_result

def main():
   calendars = getCalendars()

   if type(calendars) == list:
      for calendar in calendars:
          print(calendar)
   else:
      print(calendars)

if __name__ == "__main__":
    main()
