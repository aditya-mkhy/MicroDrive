# First full stable release
import network 
from time import time, sleep, localtime as loct
import usocket as usk
import json
import os
import ntptime
import utime
import machine

class Logger:
    def __init__(self, flush_limit=2):
        self.log_dir = "/sd/log"
        self.buffer = []
        self.flush_limit = flush_limit
        self.max_file_size = 1048576 * 5 # 5 MB
        self.last_num = self._get_num_of_last_file()
        self.path = f"{self.log_dir}/log-{self.last_num}.txt"
        self.update_path()

    def _get_num_of_last_file(self):
        last_num = 1
        try:
            for file in os.listdir(self.log_dir):
                num_str = file[file.rfind("-") + 1 : file.rfind(".")]
                try:
                    num = int(num_str)
                except:
                    num = 1
                last_num = max(last_num, num)
        except:
            pass
        return last_num
        

    def update_path(self):
        try:
            size = os.stat(self.path)[6]
        except:
            size = 0

        if size  < self.max_file_size:
            return
        
        self.last_num += 1
        self.path = f"{self.log_dir}/log-{self.last_num}.txt"    
            

    def log(self, *args, sep=" ", end="\n", **kwargs):
        msg = sep.join(str(a) for a in args)
        line = f" INFO [{loct()[2]}/{loct()[1]}/{loct()[0]} {loct()[3]}:{loct()[4]}:{loct()[5]}] {msg}"
        print(line, end=end, **kwargs)

        self.buffer.append(line + end)
        if len(self.buffer) >= self.flush_limit:
            self.flush()

    def flush(self):
        self.update_path()
        try:
            with open(self.path, "a") as f:
                for line in self.buffer:
                    f.write(line)
            self.buffer = []
        except Exception as e:
            print("[LOG-ERROR]", e)

logger = Logger() # creatng a single obj to save memory
log = logger.log

  
class WiFi:
    def __init__(self):
        self.default_passwd = "wifi@246"
        network.WLAN(network.AP_IF).active(0) 
        self.station = network.WLAN(network.STA_IF)
        sleep(1)
        self.station.active(True)
        log("[Wifi] Status: ACTIVE")
        sleep(1)
        self.online = 0
        self.ssid = None
        self.passwd = None
        
    def ipconfig(self):
        print("IP : ", self.station.ifconfig()[0])
        print("Subnet : ", self.station.ifconfig()[1])
        print("Gateway : ", self.station.ifconfig()[2])
        print("DNS : ", self.station.ifconfig()[3])

    def is_online(self):
        try:
            ai = usk.getaddrinfo('darkstartech.pythonanywhere.com', 443, 0, usk.SOCK_STREAM)[0]
            s = usk.socket(ai[0], usk.SOCK_STREAM, ai[2])
            s.connect(ai[-1])
            s.close()
            self.online = True
        except:
            self.online = False

        return self.online
    
    def connect(self, ssid = None, passwd = None, timeout = 30):
        if not ssid:
            ssid = self.ssid
        if not passwd:
            passwd = self.passwd

        if not self.station.isconnected():
            status = self.connect_to(ssid, passwd, timeout)
            if not status:
                return False
                        
        if self.is_online():
            log("[Wifi] Status: ONLINE")
        else:
            log("[Wifi] Status: OFFLINE")
        
        return True
    
    def connect_to(self, ssid, passwd, timeout=30):
        try:
            self.station.disconnect()
            self.station.connect(ssid, passwd)
            start_time = time()
            log("[WiFi] Connecting.", end="")
            while self.station.status() == network.STAT_CONNECTING:
                print(".", end="")
                if (time()-start_time) > timeout:
                    log("\n[WiFi] Timeout Error", end = "")
                    break

                sleep(0.5)

            print() # new Line
            status = self.station.status()
            self.ssid = ssid

            if status==network.STAT_WRONG_PASSWORD:
                log("[WiFi] Wrong Password")

        except Exception as e:
            log(f'Error[1] : {e}')
        return self.station.isconnected()

    def scan(self): 
        wifi_list = []
        if self.station.isconnected():
            self.station.disconnect()
        try:
            scan_wifi = self.station.scan()
            for wifi_info in scan_wifi:
                name = wifi_info[0].decode()
                
                if wifi_info[4] != 0:
                    wifi_list.append(name)

            return wifi_list
        except:
            return wifi_list
        

# ---  os.path function
def join_path(base, *paths):
    # Remove trailing slash from base
    if base.endswith("/"):
        base = base[:-1]

    for p in paths:
        if p.startswith("/"):
            p = p[1:]
        base = base + "/" + p
    return base

def split_ext(filename: str):
    index = filename.rfind(".")
    if index == -1:
        return filename, None
    return filename[:index], filename[index:]
    
def get_filename(path: str) -> str | None:
    path.replace("\\", "/")
    name = path[path.rfind("/") + 1:]
    _, ext = split_ext(name)
    if not ext:
        return
    
    return name

def path_exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False
    
class DB(dict):
    def __init__(self, file: str = "db.json"):
        super().__init__()
        self.file = file

        if path_exists(self.file):
            self.__read()
            return
        
        # if file not exits
        self.__write(refresh = True)

        
    def __read(self):
        with open(self.file, "r") as ff:
            try:
                self.update(json.loads(ff.read()))
            except:
                log("ErrorInDataBase: Can't read it..")
                return self.__write(refresh = True)
            
    
    def __write(self, refresh = False) -> dict:
        if refresh:
            self.__init_data()

        with open(self.file, "w") as tf:
            tf.write(json.dumps(self))

    def __init_data(self):
        self.update({
            "ssid" : None,
            "passwd" : None,
            "default_passwd" : "12345678",
        })
    
    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.__write()
    

def update_time():
    # Set your timezone offset (seconds)
    # Example: IST = +5:30 → 5*3600 + 30*60 = 19800
    TZ_OFFSET = 5 * 3600 + 30 * 60 
    try:
        ntptime.settime()  # sync RTC to UTC via NTP
        log("NTP time updated successfully!")
        
        # get local time (apply timezone offset)
        local_time = utime.localtime(utime.time() + TZ_OFFSET)
        formatted_time = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
            local_time[0], local_time[1], local_time[2],
            local_time[3], local_time[4], local_time[5]
        )
        log("Local Time:", formatted_time)
        
        # (optional) write local time into RTC instead of UTC
        rtc = machine.RTC()
        rtc.datetime((local_time[0], local_time[1], local_time[2],
                      local_time[6], local_time[3], local_time[4],
                      local_time[5], 0))
                      
        return True
    except Exception as e:
        print("Failed to update time:", e)
        return False
    

if __name__ == "__main__":
    log("hi.. this is aditya..")