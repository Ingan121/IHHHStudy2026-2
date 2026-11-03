from pathlib import Path
from gliclass import GLiClassModel
from gliclass.training import Trainer, TrainingArguments
from gliclass.data_processing import GLiClassDataset, DataCollatorWithPadding, AugmentationConfig   # 버전에 맞게 인자 확인
from transformers import AutoTokenizer
import json, random, torch

# https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0/tree/main
# train_ds = json.loads(open("train.json", encoding="utf-8").read())
# #[json.loads(l) for l in open("train.json", encoding="utf-8")]
# eval_ds = json.loads(open("validation.json", encoding="utf-8").read())
# # rows -> gliclass 학습 포맷으로 변환 (text + true_labels)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "models" / "guard-en-v1"
LABELS = ["Safe", "Unsafe"]

model = GLiClassModel.from_pretrained("knowledgator/gliclass-small-v1.0")
tok = AutoTokenizer.from_pretrained("knowledgator/gliclass-small-v1.0")

def load_data(filename, limit):
    path = BASE_DIR / "data" / "processed" / filename

    with open(path, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    random.Random(42).shuffle(rows)
    rows = rows[:limit]

    return [
        {
            "text": row["text"],
            "all_labels": LABELS,
            "true_labels": [row["label"]]
        }
        for row in rows
    ]

train_data = load_data("train.jsonl", 1000)
val_data = load_data("validation.jsonl", 200)
from collections import Counter

augment = AugmentationConfig(enabled=False)

def make_dataset(data):
    return GLiClassDataset(
        data,
        tok,
        augment,
        max_length=256,
        problem_type="single_label_classification",
    )

train_ds = make_dataset(train_data)
eval_ds = make_dataset(val_data)

print("Train:", Counter(r["true_labels"][0] for r in train_data))
print("Validation:", Counter(r["true_labels"][0] for r in val_data))



args = TrainingArguments(output_dir="guard-en-v1", num_train_epochs=5,
                         per_device_train_batch_size=16, learning_rate=2e-5)
trainer = Trainer(model=model, args=args, train_dataset=train_ds, eval_dataset=eval_ds,
                  data_collator=DataCollatorWithPadding(device=torch.device("cpu")),
                  processing_class=tok)   # 실제 인자명은 gliclass 레포 train 예제 기준
trainer.train()
trainer.save_model(OUTPUT_DIR)
model.save_pretrained(OUTPUT_DIR)

print("Done")