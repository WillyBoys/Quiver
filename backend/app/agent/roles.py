# Shared registry so context.py can look up specialist role prompts
# without circular imports (pipeline.py → engine.py → context.py).
# pipeline.py writes here before starting each specialist loop;
# context.py reads here inside build_agent_prompt().
_specialist_role_prompts: dict[str, str] = {}  # campaign_id → role prompt text
