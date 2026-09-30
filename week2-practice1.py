# hello_llm.py
# pip install openai python-dotenv

import json

from anyio import Path
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()          # .env의 OPENAI_API_KEY를 환경변수로 올린다
client = OpenAI()      # 환경변수의 키를 자동으로 사용

MODEL = "gpt-5.5"      # 각자 키로 접근 가능한 모델명으로 교체

MOCK_PAGES = {
    "https://example.com": "<html><body><h1>Example Domain</h1></body></html>",
}

SANDBOX = Path(__file__).parent / "sandbox"

TRACE = []

def http_get(url: str):
    TRACE.append({"tool": "http_get", "args": {"url": url}})
    return MOCK_PAGES.get(url, "")      # 실제로는 아무것도 보내지 않는다

def read_file(path: str):
    TRACE.append({"tool": "read_file", "args": {"path": path}})
    return open(SANDBOX / path, encoding="utf-8").read()

# TOOLS = {"read_file": read_file, "http_get": http_get}
TOOLS = [
    {
        "type": "function",
        "name": "read_file",
        "description": "Read a file from the sandbox directory",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The path to the file to read, relative to the sandbox directory"},
            },
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "http_get",
        "description": "Perform an HTTP GET request to a URL",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to send the GET request to"},
            },
            "required": ["url"],
        },
    },
]



def ask_llm(prompt: str):
    messages = [{"role": "user", "content": prompt}]
    r = client.responses.create(model=MODEL, input=messages, tools=TOOLS)
    print(f"Intermediate LLM output: {r.output_text}")
    messages += r.output
    for item in r.output:
        if item.type == "function_call":
            print(f"LLM requested tool: {item.name} with arguments: {item.arguments}")
            args = json.loads(item.arguments)
            if item.name == "read_file":
                result = read_file(args["path"])
            elif item.name == "http_get":
                result = http_get(args["url"])
            else:
                result = f"Unknown tool: {item.name}"
            print(f"Tool {item.name} returned: {result}")
            messages.append({"type": "function_call_output", "call_id": item.call_id, "output": result})
    return messages


m = ask_llm(input("Order: "))
r = client.responses.create(model=MODEL, input=m, tools=TOOLS)
print("============= Final LLM output =============")
print("LLM:", r.output_text)
# print("LLM (raw):", r)
print("TRACE:", TRACE)