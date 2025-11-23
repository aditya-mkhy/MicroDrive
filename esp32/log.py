import os
class Logger:
    def __init__(self, flush_limit=2):
        self.log_dir = "./log"
        self.buffer = []
        self.flush_limit = flush_limit
        self.max_file_size =  10 #1048576 * 5 # 5 MB
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
            

    def log(self, msg: str):
        print(msg)

        self.buffer.append(msg + "\n")
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


    
if __name__ == "__main__":
    logger = Logger()
    print(logger.path)
    log = logger.log
    log("hi this is Mahadev and hw the best boy")
    log("hi this is Palak and hw the best boy")
    log("hi this is Aditya and hw the best boy")
    print(logger.path)

