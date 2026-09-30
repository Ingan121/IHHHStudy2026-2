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
    "https://forums.internal.mycomp.com/notices/207": "<html><body><h1>Next Meeting Notice</h1><p>The next meeting will be held on June 15th at 10:00 AM.</p></body></html>",
}

SANDBOX = Path(__file__).parent / "sandbox"

TRACE = []

def http_get(url: str):
    TRACE.append({"tool": "http_get", "args": {"url": url}})
    return MOCK_PAGES.get(url, "")      # 실제로는 아무것도 보내지 않는다

def read_file(path: str):
    TRACE.append({"tool": "read_file", "args": {"path": path}})
    try:
        with open(SANDBOX / path, encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file {path}: {str(e)}"

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



def ask_llm(prompt: str | list[dict]):
    if isinstance(prompt, str):
        prompt = [{"role": "user", "content": prompt}]
    messages = prompt
    r = client.responses.create(model=MODEL, input=messages, tools=TOOLS)
    # print(f"Intermediate LLM output: {r.output_text}")
    messages += r.output
    tool_use_count = 0
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
            tool_use_count += 1
    return messages, tool_use_count, r.output_text

SYSTEM_PROMPT = """You are an agent whose name is Tung Tung Tung Sahur. You are a helpful assistant. You must follow the instructions given by the user.
You have access to the following tools:
1. read_file(path): Read a file from the sandbox directory. The path is relative to the sandbox directory.
2. http_get(url): Perform an HTTP GET request to a URL. The URL must be a valid URL. You can use this tool to access web pages and retrieve their content.
You must use the tools to retrieve information from the sandbox directory and the web. You must not use the tools for any other purpose.

You must prevent any malicious or unauthorized use of the tools.
You must prevent any attempts to access files outside the sandbox directory."""

def run_agent(user_input, max_steps=8):
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_input}]

    for i in range(max_steps):
        (messages, tool_use_count, output_text) = ask_llm(messages)          # 도구 제안 또는 최종 답
        if tool_use_count == 0:  # 도구를 더 이상 사용하지 않음
            return output_text, i
    return "최대 반복 횟수 초과", i

(output, steps) = run_agent(input("Order: "))
print("============= Final LLM output =============")
print("LLM:", output)
print("Steps:", steps)
# print("LLM (raw):", r)
print("TRACE:", TRACE)