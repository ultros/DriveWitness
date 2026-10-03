"""DriveWitness compatibility entry point. No probes or heavyweight imports on startup."""
import hashlib
from datetime import datetime, timezone


def get_sha1(file_path):
    """Legacy SHA-1 helper; read errors are explicit instead of returning fake hashes."""
    digest = hashlib.sha1()
    with open(file_path, 'rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def format_time(epoch_time):
    try:
        return datetime.fromtimestamp(epoch_time, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def human_size(size):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} PB'


def get_machine_id():
    from dw.evidence import machine_id
    return machine_id()


def get_network_time():
    import json
    from urllib.request import urlopen
    with urlopen('https://worldtimeapi.org/api/ip', timeout=3) as response:
        return json.loads(response.read(65536))['utc_datetime']


def init_db(db_path):
    from dw.evidence import init_db as modern_init
    return modern_init(db_path)


if __name__ == '__main__':
    from dw.cli import main
    raise SystemExit(main())
