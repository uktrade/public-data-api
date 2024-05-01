import sys
import tempfile
from datetime import datetime
from pathlib import Path


HEARTBEAT_FILE = Path(f'{tempfile.gettempdir()}/public_data_api_worker_heartbeat')


def heartbeat(logger, shut_down_heartbeat, thread):
    while True:
        if shut_down_heartbeat.wait(timeout=1.0):
            break

        if thread.is_alive():
            HEARTBEAT_FILE.write_text(str(datetime.now().timestamp()), encoding='utf-8')
        else:
            logger.info('Heartbeat: is not alive')

    HEARTBEAT_FILE.unlink(missing_ok=True)


def check_heartbeat():
    now = datetime.now().timestamp()

    exists = HEARTBEAT_FILE.exists()
    recent = exists and (now - float(HEARTBEAT_FILE.read_text(encoding='utf-8'))) < 60
    exit_code = 0 if recent else 1
    sys.exit(exit_code)


if __name__ == '__main__':
    check_heartbeat()
