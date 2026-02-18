import json
import anthropic

class AnthropicProvider:
    def __init__(self, api_key, model):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def summarize(self, prompt_data):
        findings_str = json.dumps([
            {k: v for k, v in f.items() if k in ("title", "severity", "category")}
            for f in prompt_data["findings"]
        ], indent=2)
        
        target = prompt_data["target"]
        instructions = prompt_data["instructions"]
        
        message = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=0,
            system=instructions,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": f"Target: {target}\n\nFindings:\n{findings_str}"
                        }
                    ]
                }
            ]
        )
        return message.content[0].text
