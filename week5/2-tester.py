from gliclass import GLiClassModel, ZeroShotClassificationPipeline
from transformers import AutoTokenizer
from pathlib import Path

#name = "knowledgator/gliclass-small-v1.0"          # 소형 인코더
path = Path(__file__).resolve().parent
name = path / "models" / "guard-en-v1"          # fine-tuned
model = GLiClassModel.from_pretrained(name)
tok = AutoTokenizer.from_pretrained(name)
pipe = ZeroShotClassificationPipeline(
    model, tok, classification_type="multi-label", device="cpu")   # CPU로 구동

labels = ["safe", "prompt_injection", "jailbreak", "system_prompt_extraction"]
while True:
    results = pipe(input(), labels, threshold=0.0)[0]
    results = sorted(results, key=lambda x: x["score"], reverse=True)
    print(results)
# 예: [[{'label': 'system_prompt_extraction', 'score': 0.8x}, ...]]