import json
import google.generativeai as genai

class GeminiProvider:
    def __init__(self, api_key, model):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)

    def summarize(self, prompt_data):
        findings_str = json.dumps([
            {k: v for k, v in f.items() if k in ("title", "severity", "category")}
            for f in prompt_data["findings"]
        ], indent=2)
        
        target = prompt_data["target"]
        instructions = prompt_data["instructions"]
        
        
        # Use list of parts for safer prompt construction
        prompt_parts = [
            instructions,
            f"\n\nTarget: {target}\n\nFindings:\n{findings_str}"
        ]

        # Try generating content, with fallback to auto-discover model if configured one fails
        try:
            response = self.model.generate_content(prompt_parts)
            return response.text
        except Exception as e:
            if "404" in str(e) and "models/" in str(e):
                print(f"[-] Gemini Model '{self.model.model_name}' not found. Attempting to auto-discover available models...")
                try:
                    # List models and find one that supports generateContent
                    found_model = None
                    for m in genai.list_models():
                        if 'generateContent' in m.supported_generation_methods:
                            if 'gemini' in m.name:
                                found_model = m.name
                                break
                    
                    if found_model:
                        print(f"[+] Switching to available model: {found_model}")
                        self.model = genai.GenerativeModel(found_model)
                        response = self.model.generate_content(prompt_parts)
                        return response.text
                    else:
                        raise ValueError("No suitable Gemini model found for this API Key.")
                except Exception as inner_e:
                    raise inner_e # Re-raise if discovery fails
            else:
                raise e
