import json
from pathlib import Path
from datasets import load_dataset, load_from_disk

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data" / "raw" / "aegis-v2"

# DATASETS 다운로드 후 data/raw/aegis-v2 에 저장

if DATA_DIR.exists():
    print("Loading local dataset...")
    dataset = load_from_disk(str(DATA_DIR))
else:
    print("Downloading dataset...")

    dataset = load_dataset(
        "nvidia/Aegis-AI-Content-Safety-Dataset-2.0"
    )

    dataset.save_to_disk(str(DATA_DIR))
    print("Dataset saved!")

print(dataset)

# 로컬 데이터셋 불러오기
dataset = load_from_disk("data/raw/aegis-v2")

Path("data/processed").mkdir(exist_ok=True)

# Train / Validation / Test 변환
for split in ["train", "validation", "test"]:
    with open(f"data/processed/{split}.jsonl", "w", encoding="utf-8") as f:
        for row in dataset[split]:
            if row["prompt_label"] not in ["safe", "unsafe"]:
                continue

            if not row["prompt"] or row["prompt"].strip().upper() == "REDACTED":
                continue

            data = {
                "text": row["prompt"],
                "label": row["prompt_label"].capitalize()
            }

            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    print(f"{split} 저장 완료")