import json
from openai import OpenAI

class OpenAIProvider:
    def __init__(self, api_key, model):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def summarize(self, prompt_data):
        findings_str = json.dumps([
            {k: v for k, v in f.items() if k in ("title", "severity", "category")}
            for f in prompt_data["findings"]
        ], indent=2)
        
        target = prompt_data["target"]
        instructions = prompt_data["instructions"]
        
        messages = [
            {"role": "system", "content": instructions},
            {"role": "user", "content": f"Target: {target}\n\nFindings:\n{findings_str}"}
        ]
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.3
        )
        return response.choices[0].message.content
