import os
import json
import asyncio
from typing import List, Any
from dotenv import load_dotenv
from cai.sdk.agents import function_tool
from tavily import TavilyClient


load_dotenv()

TAVILY_CLIENT = TavilyClient(api_key=os.getenv("TAVILY_KEY"))


async def _execute_tavily_search(**kwargs: Any) -> str:
    if not TAVILY_CLIENT.api_key:
        return json.dumps({"Error": "Can not found TAVILY_KEY."})
    
    try:
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,  
            lambda: TAVILY_CLIENT.search(**kwargs)
        )
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Error when calling Tavily API: {str(e)}"})
    

@function_tool
async def tavily_research(query: str, max_results: int = 7) -> str:
    return await _execute_tavily_search(
        query=query,
        search_depth="advanced",
        max_results=max_results,
        include_raw_content=True,
        include_answer=True
    )

@function_tool
async def tavily_search(
    query: str,
    include_domains: List[str] | None = None,
    exclude_domains: List[str] | None = None,
    max_results: int = 5
) -> str:
    
    return await _execute_tavily_search(
        query=query,
        search_depth="basic",
        include_domains=include_domains or [],
        exclude_domains=exclude_domains or [],
        max_results=max_results
    )
