"""Chạy toàn bộ pipeline T15 theo đúng thứ tự: Collect -> Clean -> Analyze -> Model."""
import subprocess, sys
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

STEPS = [
    ("Sinh dữ liệu synthetic",      [sys.executable, "src/2. make_synthetic.py", "--n", "4000", "--seed", "42"]),
    ("Làm sạch + gán nhãn + feature", [sys.executable, "src/3.prepare.py"]),
    ("Phân tích + vẽ biểu đồ",       [sys.executable, "src/4.analyze.py"]),
    ("Baseline vs Decision Tree",    [sys.executable, "src/5. model.py"]),
]

if __name__ == "__main__":
    Path("data/raw").mkdir(parents=True, exist_ok=True)
    for i, (name, cmd) in enumerate(STEPS, 1):
        print(f"\n{'='*70}\nBƯỚC {i}/{len(STEPS)}: {name}\n{'='*70}")
        r = subprocess.run(cmd)
        if r.returncode != 0:
            sys.exit(f"Lỗi ở bước: {name}")
    print("\nHOÀN TẤT. Xem figures/ và results/report.txt")
