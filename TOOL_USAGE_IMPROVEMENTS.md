# CAI Agent Tool Usage Improvements

## Problem Analysis

The agents were not effectively utilizing available tools like Tavily search and MCP Burp Suite because:

1. **Lack of explicit tool usage guidance** in system prompts
2. **Missing version detection protocols** leading to ineffective exploitation attempts  
3. **No clear tool priority hierarchy** for systematic security testing
4. **Insufficient integration between reconnaissance and research phases**

## Implemented Solutions

### 1. Enhanced System Prompts

**Updated Files:**
- `src/cai/prompts/system_red_team_agent.md` - Added comprehensive tool usage strategy
- `src/cai/prompts/system_bug_bounter.md` - Added mandatory research protocols
- `src/cai/prompts/system_dfir_agent.md` - Added threat intelligence research guidance
- `src/cai/prompts/core/system_master_template.md` - Added universal tool usage guidelines

### 2. Created Tool Usage Template

**New File:** `src/cai/prompts/core/tool_usage_guidance.md`
- Comprehensive tool usage strategy
- Phase-based approach (Discovery → Research → Exploitation)
- Specific examples for each tool function
- Version detection protocols

### 3. Key Improvements Made

#### **Mandatory Version Detection**
- Agents now MUST identify exact service versions before exploitation
- Clear protocols for researching specific versions
- Examples: "Apache 2.4.41" instead of just "Apache"

#### **Systematic Research Phase**
- **tavily_security_advisory_search**: For official security advisories
- **tavily_cve_search**: For known CVE research
- **tavily_exploit_research**: For finding exploitation techniques
- **tavily_github_exploit_search**: For available exploit code
- **MCP tools integration**: Enhanced guidance for using specialized tools

#### **Tool Priority Hierarchy**
1. **Reconnaissance & Enumeration** (generic_linux_command)
2. **Version Detection** (mandatory before proceeding)
3. **Vulnerability Research** (Tavily search tools)
4. **Specialized Analysis** (MCP tools)
5. **Targeted Exploitation** (based on research findings)

#### **Enhanced MCP Integration**
- Clear guidance on when to use MCP tools
- Integration with research phase
- Specialized analysis workflows

## Expected Results

With these improvements, agents should now:

1. **Always identify target versions** before attempting exploitation
2. **Actively use Tavily search tools** for vulnerability research
3. **Leverage MCP tools** for specialized analysis when available
4. **Follow systematic approach** rather than random exploitation attempts
5. **Research findings thoroughly** before taking action

## Usage Examples

### Before (Less Effective):
```
Agent identifies "Apache running on port 80"
→ Immediately attempts generic web exploits
→ Limited success, no version-specific research
```

### After (More Effective):
```
Agent identifies "Apache HTTP Server 2.4.41 on port 80"
→ tavily_security_advisory_search("Apache HTTP Server", "2.4.41")
→ tavily_exploit_research("Apache 2.4.41 vulnerability")
→ Uses MCP Burp Suite for web application analysis
→ Targeted exploitation based on research findings
```

## Additional Recommendations

1. **Set Environment Variables**: Ensure TAVILY_KEY and other API keys are properly configured
2. **MCP Server Setup**: Make sure MCP servers (like Burp Suite) are loaded and associated with agents
3. **Monitor Tool Usage**: Check that agents are actually calling the search functions in their workflows
4. **Iterative Improvement**: Continue refining prompts based on agent behavior and results

The enhanced prompts should significantly improve tool utilization and target version detection effectiveness.