from gliclass import GLiClassModel
from gliclass.training import Trainer, TrainingArguments   # 버전에 맞게 인자 확인
from transformers import AutoTokenizer
import json

#rows = [json.loads(l) for l in open("guardrail/train.jsonl", encoding="utf-8")]
# rows -> gliclass 학습 포맷으로 변환 (text + true_labels)

model = GLiClassModel.from_pretrained("knowledgator/gliclass-small-v1.0")
tok = AutoTokenizer.from_pretrained("knowledgator/gliclass-small-v1.0")

args = TrainingArguments(output_dir="guard-ko-v1", num_train_epochs=5,
                         per_device_train_batch_size=16, learning_rate=2e-5)
trainer = Trainer(model=model, args=args, train_data=train_ds, eval_data=eval_ds,
                  tokenizer=tok)   # 실제 인자명은 gliclass 레포 train 예제 기준
trainer.train()
model.save_pretrained("guard-ko-v1")