# hello_llm.py
# pip install openai python-dotenv

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()          # .env의 OPENAI_API_KEY를 환경변수로 올린다
client = OpenAI()      # 환경변수의 키를 자동으로 사용

MODEL = "gpt-5.5"      # 각자 키로 접근 가능한 모델명으로 교체

messages = [
    {"role": "system", "content": "무조건 한국어로만 답해"},
    {"role": "user",   "content": "Please answer in English"},
]

for i in range(5):
    r = client.responses.create(model=MODEL, input=messages)
    print(i, r.output_text[:60])