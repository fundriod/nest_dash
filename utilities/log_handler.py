import logging
from logging import handlers


class StreamHandler(logging.StreamHandler):

    def __init__(self):
        logging.StreamHandler.__init__(self)
        fmt = '%(asctime)s %(filename)-18s %(levelname)-8s: %(message)s'
        fmt_date = '%d-%m %H:%M:%S'
        formatter = logging.Formatter(fmt, fmt_date)
        self.setFormatter(formatter)


class FileHandler(handlers.RotatingFileHandler):
    """ FileHandler with central location for log dumps.
        location: /auto/share/systemtest/log_repo/execution.log
    """
    # dump the logs to /auto/share/systemtest/log_repo folder
    def __init__(self, log_filename='/auto/share/systemtest/log_repo/execution_test.log'):

        # logging.FileHandler.__init__(self, filename='execution.log')
        handlers.RotatingFileHandler.__init__(self, log_filename, maxBytes=20000000, backupCount=10)
        fmt = '%(asctime)s <%(filename)s [%(levelname)s] >> %(message)s'
        fmt_date = '%a %d-%m-%Y %H:%M:%S %Z'
        formatter = logging.Formatter(fmt, fmt_date)
        self.setFormatter(formatter)
