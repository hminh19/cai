import os
import json
import asyncio
import re
from typing import List, Any, Dict
from dotenv import load_dotenv
from cai.sdk.agents import function_tool
from tavily import TavilyClient


load_dotenv()

TAVILY_CLIENT = TavilyClient(api_key=os.getenv("TAVILY_KEY"))

# Keywords that indicate actionable exploit content
EXPLOIT_KEYWORDS = [
    "exploit", "payload", "poc", "proof of concept", "vulnerability",
    "cve", "rce", "remote code execution", "sql injection", "xss",
    "buffer overflow", "privilege escalation", "bypass", "shell",
    "reverse shell", "metasploit", "nmap", "burp suite", "sqlmap"
]

CODE_PATTERNS = [
    r'```[\s\S]*?```',  # Code blocks
    r'`[^`\n]+`',       # Inline code
    r'http[s]?://[^\s]+',  # URLs
    r'CVE-\d{4}-\d{4,}',   # CVE identifiers
]


def extract_actionable_content(content: str, title: str = "") -> Dict[str, Any]:
    """Extract potentially actionable content for red team operations."""
    
    # Find code snippets
    code_snippets = []
    for pattern in CODE_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        code_snippets.extend(matches)
    
    # Find exploit-related keywords
    exploit_mentions = []
    for keyword in EXPLOIT_KEYWORDS:
        if keyword.lower() in content.lower() or keyword.lower() in title.lower():
            # Extract context around the keyword
            pattern = rf'.{{0,100}}{re.escape(keyword)}.{{0,100}}'
            matches = re.findall(pattern, content, re.IGNORECASE)
            exploit_mentions.extend(matches)
    
    # Extract potential URLs and endpoints
    urls = re.findall(r'http[s]?://[^\s]+', content)
    
    # Extract CVE references
    cves = re.findall(r'CVE-\d{4}-\d{4,}', content, re.IGNORECASE)
    
    # Calculate relevance score
    relevance_score = len(exploit_mentions) + len(code_snippets) * 2 + len(cves) * 3
    
    return {
        "code_snippets": code_snippets[:5],  # Limit to top 5
        "exploit_mentions": exploit_mentions[:3],
        "urls": urls[:5],
        "cves": cves,
        "relevance_score": relevance_score,
        "is_actionable": relevance_score > 2
    }


def prioritize_results(results: List[Dict]) -> List[Dict]:
    """Prioritize search results based on exploit potential."""
    
    enhanced_results = []
    for result in results:
        content = result.get("content", "")
        title = result.get("title", "")
        
        actionable_data = extract_actionable_content(content, title)
        
        result["actionable_content"] = actionable_data
        result["exploit_potential"] = actionable_data["relevance_score"]
        
        enhanced_results.append(result)
    
    # Sort by exploit potential (highest first)
    enhanced_results.sort(key=lambda x: x["exploit_potential"], reverse=True)
    
    return enhanced_results


async def _execute_tavily_search(**kwargs: Any) -> str:
    if not TAVILY_CLIENT.api_key:
        return json.dumps({"Error": "Cannot find TAVILY_KEY."})
    
    try:
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,  
            lambda: TAVILY_CLIENT.search(**kwargs)
        )
        
        # Process and prioritize results
        if "results" in response:
            response["results"] = prioritize_results(response["results"])
        
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Error when calling Tavily API: {str(e)}"})


@function_tool
async def tavily_exploit_research(query: str, max_results: int = 7) -> str:
    """
    Advanced search for exploit research with content filtering and prioritization.
    Returns results sorted by exploit potential with extracted actionable content.
    """
    return await _execute_tavily_search(
        query=f"{query} exploit PoC vulnerability",  # Enhanced query
        search_depth="advanced",
        max_results=max_results,
        include_raw_content=True,
        include_answer=True
    )


@function_tool
async def tavily_cve_search(cve_id: str, include_poc: bool = True) -> str:
    """
    Search for specific CVE information with focus on PoCs and exploits.
    """
    query = f"{cve_id}"
    if include_poc:
        query += " exploit PoC proof of concept"
    
    return await _execute_tavily_search(
        query=query,
        search_depth="advanced",
        max_results=5,
        include_raw_content=True,
        include_answer=True
    )


@function_tool
async def tavily_github_exploit_search(
    technology: str,
    vulnerability_type: str = "",
    max_results: int = 5
) -> str:
    """
    Search specifically for GitHub repositories containing exploits and PoCs.
    """
    query = f"site:github.com {technology} {vulnerability_type} exploit PoC"
    
    return await _execute_tavily_search(
        query=query,
        search_depth="advanced",
        include_domains=["github.com"],
        max_results=max_results,
        include_raw_content=True
    )


@function_tool
async def tavily_security_advisory_search(
    product: str,
    version: str = "",
    max_results: int = 5
) -> str:
    """
    Search for security advisories and vulnerability disclosures.
    """
    query = f"{product} {version} security advisory vulnerability disclosure"
    
    return await _execute_tavily_search(
        query=query,
        search_depth="advanced",
        exclude_domains=["social-media-sites.com", "forums.com"],  # Focus on official sources
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
    """
    Basic search with result prioritization for red team operations.
    """
    return await _execute_tavily_search(
        query=query,
        search_depth="basic",
        include_domains=include_domains or [],
        exclude_domains=exclude_domains or [],
        max_results=max_results
    )


@function_tool
async def extract_exploit_details(search_results: str) -> str:
    """
    Extract and summarize the most actionable exploit information from search results.
    This function helps the agent focus on implementable PoCs and exploits.
    """
    try:
        results_data = json.loads(search_results)
        
        if "results" not in results_data:
            return json.dumps({"error": "No results found in the provided data"})
        
        actionable_summary = {
            "high_priority_exploits": [],
            "code_snippets": [],
            "cve_references": [],
            "exploit_urls": [],
            "summary": ""
        }
        
        for result in results_data["results"][:3]:  # Focus on top 3 results
            if result.get("exploit_potential", 0) > 3:  # High potential only
                actionable_content = result.get("actionable_content", {})
                
                exploit_info = {
                    "title": result.get("title", ""),
                    "url": result.get("url", ""),
                    "code_snippets": actionable_content.get("code_snippets", []),
                    "cves": actionable_content.get("cves", []),
                    "exploit_mentions": actionable_content.get("exploit_mentions", [])
                }
                
                actionable_summary["high_priority_exploits"].append(exploit_info)
                actionable_summary["code_snippets"].extend(actionable_content.get("code_snippets", []))
                actionable_summary["cve_references"].extend(actionable_content.get("cves", []))
        
        # Create summary
        total_exploits = len(actionable_summary["high_priority_exploits"])
        total_code = len(actionable_summary["code_snippets"])
        total_cves = len(set(actionable_summary["cve_references"]))
        
        actionable_summary["summary"] = f"Found {total_exploits} high-priority exploits, {total_code} code snippets, and {total_cves} CVE references ready for implementation."
        
        return json.dumps(actionable_summary, indent=2, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error processing exploit details: {str(e)}"})