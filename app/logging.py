import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone


class Formatter(logging.Formatter):
    def format(self, record):
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": record.name,
            "level": record.levelname,
            "operation": record.getMessage(),
        }
        data.update(getattr(record, "fields", {}))
        return json.dumps(data, default=str)


def configure(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    handlers = [
        logging.StreamHandler(),
        RotatingFileHandler(path / "aivi.log", maxBytes=5_000_000, backupCount=5),
    ]
    for handler in handlers:
        handler.setFormatter(Formatter())
    (path / "aivi.log").chmod(0o600)
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True)
