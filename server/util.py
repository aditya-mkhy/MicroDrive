from datetime import datetime

def log(*args, save = True, **kwargs):
    print(f" INFO [{datetime.now().strftime('%d-%m-%Y  %H:%M:%S')}] ", *args, **kwargs)