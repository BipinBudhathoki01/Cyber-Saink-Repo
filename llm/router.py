from .openai_provider import OpenAIProvider
from .gemini_provider import GeminiProvider
from .anthropic_provider import AnthropicProvider

def get_llm(settings):
    provider = settings.llm_provider.lower()
    
    if provider == "openai":
        return OpenAIProvider(settings.openai_api_key, settings.openai_model)
    elif provider == "gemini":
        return GeminiProvider(settings.gemini_api_key, settings.gemini_model)
    elif provider == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key, settings.anthropic_model)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider}")
