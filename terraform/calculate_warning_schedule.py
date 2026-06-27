#!/usr/bin/env python3
import sys
import json
import re
from datetime import datetime, timedelta

def main():
    try:
        # Read JSON from stdin
        input_data = json.load(sys.stdin)
        schedule = input_data.get("schedule_expression", "cron(0 0 * * ? *)")
        offset_hours = int(input_data.get("warning_offset_hours", "2"))

        # Parse cron expression, e.g. cron(0 0 * * ? *)
        match = re.match(r"^cron\((.+)\)$", schedule.strip())
        if not match:
            # If it's a rate expression or invalid cron, just return it as is
            print(json.dumps({"schedule_expression": schedule}))
            return

        cron_body = match.group(1)
        fields = cron_body.split()
        
        # AWS cron has 6 fields: minutes hours day_of_month month day_of_week year
        if len(fields) >= 2:
            minute_str = fields[0]
            hour_str = fields[1]
            
            if hour_str != "*" and hour_str.isdigit() and minute_str.isdigit():
                minute = int(minute_str)
                hour = int(hour_str)
                
                # Use datetime/timedelta to handle rollover cleanly
                base_dt = datetime(2020, 1, 2, hour, minute)
                warning_dt = base_dt - timedelta(hours=offset_hours)
                
                fields[0] = str(warning_dt.minute)
                fields[1] = str(warning_dt.hour)

        new_cron_body = " ".join(fields)
        new_schedule = f"cron({new_cron_body})"
        print(json.dumps({"schedule_expression": new_schedule}))
    except Exception as e:
        # Graceful fallback to original schedule expression in case of any parsing error
        print(json.dumps({"schedule_expression": schedule}))

if __name__ == "__main__":
    main()
