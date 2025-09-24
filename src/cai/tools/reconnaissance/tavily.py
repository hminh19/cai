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
async def tavily_search(
    query: str,
    search_depth: str = "advanced",
    include_domains: List[str] | None = None,
    exclude_domains: List[str] | None = None,
    max_results: int = 7
) -> str:
    """
    Perform a comprehensive search using the Tavily API, with content filtering and prioritization.
    Results are sorted by exploit potential, with actionable content extracted.

    :param query: The search query. You can use search operators like 'site:' to focus on specific domains.
    :param search_depth: The depth of the search. Can be "basic" or "advanced". Defaults to "advanced".
    :param include_domains: A list of domains to specifically include in the search.
    :param exclude_domains: A list of domains to exclude from the search.
    :param max_results: The maximum number of results to return.
    """
    return await _execute_tavily_search(
        query=query,
        search_depth=search_depth,
        include_domains=include_domains or [],
        exclude_domains=exclude_domains or [],
        max_results=max_results,
        include_raw_content=True,
        include_answer=True
    )


@function_tool
def extract_exploit_details(search_results: str) -> str:
    """
    Extract and summarize the most actionable exploit information from search results or plain text.
    This function helps the agent focus on implementable PoCs and exploits.
    Handles both JSON search results and plain text vulnerability information.
    """
    try:
        # Try to parse as JSON first
        try:
            results_data = json.loads(search_results)
            
            # If it's valid JSON with results structure, process it
            if isinstance(results_data, dict) and "results" in results_data:
                return _process_json_search_results(results_data)
            
        except json.JSONDecodeError:
            # If not JSON, treat as plain text vulnerability information
            pass
        
        # Process as plain text vulnerability information
        return _process_plain_text_vulnerability(search_results)
        
    except Exception as e:
        return json.dumps({"error": f"Error processing exploit details: {str(e)}"})


def _process_json_search_results(results_data: dict) -> str:
    """Process structured JSON search results."""
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


def _process_plain_text_vulnerability(text: str) -> str:
    """Process plain text vulnerability information and extract actionable intelligence."""
    
    # Extract CVE IDs
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves = re.findall(cve_pattern, text, re.IGNORECASE)
    
    # Extract version information
    version_pattern = r'v?(\d+\.\d+(?:\.\d+)?(?:[-._][a-zA-Z0-9]+)?)'
    versions = re.findall(version_pattern, text)
    
    # Look for vulnerability keywords
    vuln_keywords = [
        'vulnerability', 'exploit', 'rce', 'sql injection', 'xss', 'csrf',
        'buffer overflow', 'directory traversal', 'file inclusion',
        'authentication bypass', 'privilege escalation', 'code execution'
    ]
    
    found_keywords = []
    for keyword in vuln_keywords:
        if keyword.lower() in text.lower():
            found_keywords.append(keyword)
    
    # Extract potential software/product names (simple heuristic)
    # Look for capitalized words that might be product names
    product_pattern = r'\b([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)\b'
    products = re.findall(product_pattern, text)
    # Filter common words
    common_words = {'The', 'This', 'That', 'A', 'An', 'And', 'Or', 'But', 'In', 'On', 'At', 'To', 'For', 'Of', 'With', 'By'}
    products = [p for p in products if p not in common_words][:5]  # Limit to 5
    
    # Assess severity based on keywords
    high_severity_terms = ['rce', 'remote code execution', 'privilege escalation', 'authentication bypass']
    severity = "HIGH" if any(term in text.lower() for term in high_severity_terms) else "MEDIUM"
    
    actionable_summary = {
        "vulnerability_analysis": {
            "identified_products": products,
            "cve_references": list(set(cves)),
            "versions_mentioned": list(set(versions)),
            "vulnerability_types": found_keywords,
            "severity_assessment": severity
        },
        "exploitation_potential": {
            "has_cve": len(cves) > 0,
            "has_version_info": len(versions) > 0,
            "high_impact": severity == "HIGH",
            "actionable_score": len(cves) * 3 + len(found_keywords) * 2 + (2 if severity == "HIGH" else 1)
        },
        "recommendations": [],
        "summary": ""
    }
    
    # Generate recommendations
    if cves:
        actionable_summary["recommendations"].append(f"Search for exploits for: {', '.join(cves)}")
    
    if products and versions:
        for product in products[:2]:  # Limit to top 2 products
            for version in versions[:2]:  # Limit to top 2 versions
                actionable_summary["recommendations"].append(f"Research vulnerabilities in {product} version {version}")
    
    if found_keywords:
        top_vulns = found_keywords[:3]  # Top 3 vulnerability types
        actionable_summary["recommendations"].append(f"Focus on {', '.join(top_vulns)} attack vectors")
    
    # Generate summary
    cve_count = len(cves)
    product_count = len(products)
    vuln_count = len(found_keywords)
    
    actionable_summary["summary"] = (
        f"Identified {cve_count} CVE references, {product_count} products, "
        f"and {vuln_count} vulnerability types. Severity: {severity}. "
        f"Actionability Score: {actionable_summary['exploitation_potential']['actionable_score']}"
    )
    
    return json.dumps(actionable_summary, indent=2, ensure_ascii=False)