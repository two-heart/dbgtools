import time
from typing import Union
import os

class Logger:
    __key = object()
    __instance = None
    # TODO(liam) why did we choose bytes here and is this the best choice?
    content: bytes
    _log_count: int
    _config: dict
    used_log: bool
    _start_time: float

    def __init__(self, key: object):
        if key != self.__key:
            raise ValueError("Logger is a singletone. Use get_instance()"
                             + " instead")
        self.content = b""
        self._log_count = 0
        self._config = {"enable_file_logging": True,
                        "enable_log_write_buffering": False,
                        "file_logging_mode": "append",
                        "log_file": "gdb_script.log",
                        "log_file_update_threshold": 5000}
        self.used_log = False
        self.clear_log_file()
        self._start_time = time.time()

    @classmethod
    def get_instance(cls) -> "Logger":
        if cls.__instance is None:
            cls.__instance = Logger(cls.__key)
        return cls.__instance

    def clear_log_file(self) -> None:
        if (self._config["enable_file_logging"]
           and self._config["file_logging_mode"] == "append"
           and os.path.exists(self._config["log_file"])):
            with open(self._config["log_file"], "w") as f:
                f.write("")

    def log(self, message: bytes) -> None:
        self.used_log = True
        self.content += message
        self._log_count += 1
        self._file_logging()

    def set_enable_file_logging(self, enabled: bool):
        self._config["enable_file_logging"] = enabled

    def _file_logging(self):
        if self._config["enable_file_logging"]:
            update_th: int = self._config["log_file_update_threshold"]
            write_buf = self._config["enable_log_write_buffering"]
            if self._log_count % update_th == 0 or not write_buf:
                self.write_log_to_log_file()
                print(f"Written {self._log_count} logs to log file after"
                      + f" {time.time() - self._start_time} seconds")

    def write_log_to_log_file(self):
        # TODO(liam) Keep the file open while the logger is active
        if self._config["file_logging_mode"] == "append":
            with open(self._config["log_file"], "ab") as f:
                f.write(self.content)
            self.content = b""
        else:
            with open(self._config["log_file"], "wb") as f:
                f.write(self.content)

    def print_log(self) -> None:
        print(self.content)

    def log_line(self, message: bytes) -> None:
        self.log(message + b"\n")

    def update_config(self, config: dict[str, Union[bool, str, int]]) -> None:
        self._config = config

    def clear(self) -> None:
        self.content = b""
        self._log_count = 0
