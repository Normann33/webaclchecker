import logging
import sys

def setup_logging(log_file="app.log", level=logging.INFO):
    # Очищаем старые хендлеры (важно для flask --debug перезагрузок)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    
    root.addHandler(logging.FileHandler(log_file, encoding="utf-8"))
    root.addHandler(logging.StreamHandler(sys.stdout))
    
    for h in root.handlers:
        h.setFormatter(fmt)