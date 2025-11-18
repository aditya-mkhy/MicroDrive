# handle SD cards
import os
import machine
from util import log, path_exists, join_path
import time


class Drive:
    def __init__(self, mount_point = "/sd", sd_slot = 1):
        self.mount_point = mount_point
        self.sd_slot = sd_slot
        self.cwd = self.mount_point

        self._dir_code = 16384
        self._file_code = 32768
        
    def _init_cwd(self):
        os.chdir(self.mount_point)

    # mount sd card 
    def mount(self, unmount = False):
        if unmount:
            try:
                os.umount(self.mount_point)
                log(f"[SD] Unmounted old SD at {self.mount_point!r}")
            except OSError as e:
                log(f"[SD] Nothing to unmount at {self.mount_point!r}")

        try:
             # will fail if not mounted
            os.listdir(self.mount_point) 
            return True
        
        except OSError:
            pass

        try:
            sd = machine.SDCard(slot=self.sd_slot, width=1)
            #mount
            os.mount(sd, self.mount_point)
            log(f"[SD] Mounted at {self.mount_point!r}")
            return True
        
        except Exception as e:
            if unmount:
                log(f"[SD] Can't mount SD due to {e}")
                return False

            log("[SD] Failed to mount SD : ", e)
            log("[SD] Trying to 'unmount' and then 'mount' to resolve error")
            self.mount(unmount=True)

        return False
    

    def _format_unix_time(self, t):
        # t = seconds since 1 Jan 1970
        y, mo, d, h, mi, s, wd, yd = time.localtime(t)
        ampm = "AM"
        h12 = h
        if h12 == 0:
            h12 = 12
        elif h12 == 12:
            ampm = "PM"
        elif h12 > 12:
            h12 -= 12
            ampm = "PM"

        return "%02d/%02d/%04d  %02d:%02d:%02d %s" % (mo, d, y, h12, mi, s, ampm)

    
    def _file_info(self, path):
        stat_info = os.stat(path)
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        mtime = self._format_unix_time(stat_info[8])
        if stat_info[0] == self._dir_code:
            # this is directory
            return [mtime, "<DIR>", path]
        return [mtime, stat_info[6], path]
    
    
    def listdir(self):
        files_list = os.listdir()

        info = []
        for file in files_list:
            info.append(self._file_info(file))

        return info
    
    def chdir(self, path: str):
        prev_cwd = os.getcwd()

        try:
            os.chdir(path)
        except:
            return
        
        if not os.getcwd().startswith(self.mount_point):
            # if trying to access other than mount point
            os.chdir(prev_cwd)

        return os.getcwd()
        
    def mkdir(self, folder):
        try:
            os.mkdir(folder)
            return True
        except:
            return
        
    def remove(self, path: str):
        if path == self.mount_point:
            return 
        try:
            os.remove(path)
            return True
        except:
            return
        
    def get_cwd(self):
        cwd = os.getcwd()
        if not cwd.startswith(self.mount_point):
            self._init_cwd()
            cwd = os.getcwd()
        return cwd
