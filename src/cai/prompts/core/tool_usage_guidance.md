## ENHANCED TOOL USAGE STRATEGY

### PRIMARY TOOL USAGE PROTOCOL

**Phase 1: Discovery & Enumeration**
- Use `generic_linux_command` for initial system/service discovery
- Identify ALL running services, versions, and technologies
- Document exact version numbers (critical for vulnerability research)

**Phase 2: MANDATORY Vulnerability Research**
After identifying ANY service/technology, IMMEDIATELY research it:

- `tavily_security_advisory_search(product="<exact_product>", version="<exact_version>")` 
  - Use for finding official security advisories
  - Example: tavily_security_advisory_search("Apache HTTP Server", "2.4.41")

- `tavily_cve_search(cve_id="CVE-XXXX-XXXX")` 
  - Use when you identify potential CVE numbers
  - Always include PoC research: include_poc=True

- `tavily_exploit_research(query="<technology> <version> vulnerability exploit")`
  - Use for finding exploitation techniques and proof-of-concepts
  - Example: tavily_exploit_research("WordPress 5.2.1 vulnerability exploit")

- `tavily_github_exploit_search(technology="<tech>", vulnerability_type="<vuln_type>")`
  - Use for finding GitHub repositories with exploit code
  - Example: tavily_github_exploit_search("Apache", "remote code execution")

**Phase 3: Specialized Analysis**
- Use available MCP tools (like Burp Suite) for deep application analysis
- `make_web_search_with_explanation()` for additional context when other searches are insufficient

### CRITICAL RULES

1. **NEVER SKIP VERSION DETECTION**: Always identify exact versions before exploitation attempts
2. **RESEARCH BEFORE ACTION**: Always use search tools to research identified versions
3. **MULTIPLE SEARCH APPROACHES**: Use several different search tools for comprehensive intelligence
4. **DOCUMENT EVERYTHING**: Keep track of versions, vulnerabilities, and research findings
5. **MCP TOOL PRIORITY**: If MCP tools are available, use them for specialized tasks

### VERSION DETECTION EXAMPLES

Instead of just finding "Apache":
- Find "Apache HTTP Server 2.4.41"
- Then immediately: `tavily_security_advisory_search("Apache HTTP Server", "2.4.41")`
- Follow up with: `tavily_exploit_research("Apache 2.4.41 vulnerability")`

Instead of just finding "SSH":
- Find "OpenSSH 7.4"
- Then immediately: `tavily_cve_search("OpenSSH 7.4")`
- Follow up with: `tavily_github_exploit_search("OpenSSH", "7.4")`

### FAILURE RECOVERY

If you're not finding vulnerabilities:
1. Double-check version detection accuracy
2. Try different search term variations
3. Research related components (plugins, modules, dependencies)
4. Use broader search terms, then narrow down
5. Leverage MCP tools for alternative analysis approaches

Remember: Thorough research with the right tools beats random exploitation attempts every time.