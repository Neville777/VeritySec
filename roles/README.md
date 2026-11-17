# Role Configuration File Guide

This directory contains all role configuration files. Each role defines the AI's behavior pattern and available tools.

## Creating a New Role

When creating a new role, create a YAML file in the `roles/` directory using the following format:

**Method 1: Explicitly specify the tool list (recommended)**
```yaml
name: Role Name
description: Role description
user_prompt: User prompt (prepended to the user message to guide AI behavior)
icon: "Icon (optional)"
tools:
    # Add the tools you need...
    # ⚠️ Important: it is recommended to include the following core built-in MCP tools (vulnerabilities and knowledge base)
    - record_vulnerability
    - list_knowledge_risk_types
    - search_knowledge_base
enabled: true
```

**Method 2: Do not set the tools field (use all enabled tools)**
```yaml
name: Role Name
description: Role description
user_prompt: User prompt (prepended to the user message to guide AI behavior)
icon: "Icon (optional)"
# No tools field set; all tools enabled in MCP management will be used by default
enabled: true
```

## ⚠️ Important Reminder: Core Built-in MCP Tools

**If the `tools` field is set, be sure to include the following tools in the list (at least these three):**

1. **`record_vulnerability`**: vulnerability management tool, used to record discovered vulnerabilities
2. **`list_knowledge_risk_types`**: knowledge base tool, lists the available risk types
3. **`search_knowledge_base`**: knowledge base tool, searches knowledge base content

Other built-in or external tools such as WebShell and batch tasks may be added as needed (subject to the tools enabled in MCP management).

**Skills**: In **multi-agent / Eino** sessions, packages under `skills_dir` are loaded on demand by the built-in **`skill`** tool; they are not bound to role YAML files.

**Note**: If the `tools` field is not set, the system uses all tools enabled in MCP management by default. To explicitly control the tools available to a role, it is recommended to set the `tools` field.

## Role Configuration Field Reference

- **name**: role name (required)
- **description**: role description (required)
- **user_prompt**: user prompt, prepended to the user message to guide the AI to adopt specific testing methods and areas of focus (optional)
- **icon**: role icon, supports Unicode emoji (optional)
- **tools**: tool list, specifies the tools available to this role (optional)
  - **If the `tools` field is not set**: all **tools enabled in MCP management** are selected by default
  - **If the `tools` field is set**: only the tools specified in the list are used (it is recommended to include at least the core built-in tools above)
- **enabled**: whether this role is enabled (required, true/false)

## Example

Refer to the other role files in this directory, such as `penetration-testing.yaml` and `web-app-scanning.yaml`.
