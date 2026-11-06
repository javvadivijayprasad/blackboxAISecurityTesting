"""Smoke test the GPT-5.5 Responses-API path WITHOUT Docker or the oracle.

Run FIRST, from the oracle root, with OPENAI_API_KEY set (the key as OpenAI shows it, one 'sk-'):
    set PYTHONPATH=.
    python smoke_test_gpt55.py gpt-5.5

It makes one real Responses call with reasoning effort + the two tools and prints: served model,
status, whether a function call was emitted, any refusal, reasoning-token count, and usage.
If this works, the adapter's call shape is right and we can run the real corpus.
"""
import json, os, sys
from openai import OpenAI

MODEL = sys.argv[1] if len(sys.argv) > 1 else "gpt-5.5"
EFFORT = sys.argv[2] if len(sys.argv) > 2 else "medium"

TOOLS = [{
    "type": "function",
    "name": "http_request",
    "description": "Send one HTTP request to the target and return the response.",
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST"]},
            "path": {"type": "string"},
        },
        "required": ["method", "path"],
    },
}]

def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set"); return 1
    client = OpenAI()
    r = client.responses.create(
        model=MODEL,
        instructions="You are a security tester. Use the http_request tool to GET '/' from the target.",
        input=[{"role": "user", "content": "Target base URL: http://127.0.0.1:8080\nMake one GET request to '/'."}],
        tools=TOOLS,
        tool_choice="auto",
        reasoning={"effort": EFFORT},
        max_output_tokens=2000,
    )
    fcs = [i for i in (r.output or []) if getattr(i, "type", None) == "function_call"]
    refusal = None
    for i in (r.output or []):
        if getattr(i, "type", None) == "message":
            for p in (getattr(i, "content", None) or []):
                if getattr(p, "type", None) == "refusal":
                    refusal = getattr(p, "refusal", "")
    det = getattr(getattr(r, "usage", None), "output_tokens_details", None)
    print("OK")
    print("served model :", r.model)
    print("status       :", getattr(r, "status", None))
    print("function_call:", (fcs[0].name + " " + fcs[0].arguments) if fcs else "(none)")
    print("refusal      :", refusal)
    print("reasoning_tok:", getattr(det, "reasoning_tokens", None) if det else None)
    print("usage        :", json.dumps(getattr(r, "usage", None).__dict__ if getattr(r, "usage", None) else {}, default=str))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
