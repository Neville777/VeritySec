# Tool Configuration Files

## Overview

Each tool has its own configuration file, stored in the `tools/` directory. This approach keeps tool configurations clear and easy to maintain and manage. The system automatically loads all `.yaml` and `.yml` files in the `tools/` directory.

## Configuration File Format

Each tool configuration file is a YAML file. The table below lists the currently supported top-level fields and whether they are required. Please check each item before submitting:

| Field | Required | Type | Description |
|------|------|------|------|
| `name` | Yes | string | Unique tool identifier; lowercase letters, digits, and hyphens are recommended. |
| `command` | Yes | string | The command or script name to actually execute; must be on the system PATH or given as an absolute path. |
| `enabled` | Yes | bool | Whether to register with MCP; when set to `false`, the tool is ignored. |
| `description` | Yes | string | Detailed description; supports multi-line Markdown, for AI to understand in depth and for `resources/read` queries. |
| `short_description` | Optional | string | 20-50 character summary, used in the tool list to reduce token consumption; if missing, the beginning of `description` is automatically used. |
| `args` | Optional | string[] | Fixed arguments, prepended to the command line in order; commonly used to define default scan modes. |
| `parameters` | Optional | array | List of runtime-configurable parameters; see the "Parameter Definitions" section. |
| `arg_mapping` | Optional | string | Argument mapping mode (`auto`/`manual`/`template`), default `auto`; no need to specify unless there is a special requirement. |

> If a field is filled in incorrectly or a required field is missing, the system skips that tool when loading and writes a warning to the log, but other tools are not affected.

## Tool Descriptions

### Short Description (`short_description`)

- **Purpose**: used in the tool list to reduce the number of tokens sent to the LLM
- **Requirement**: one sentence (20-50 characters) describing the tool's core purpose
- **Example**: `"Network scanning tool for discovering network hosts, open ports, and services"`

### Detailed Description (`description`)

Supports multi-line text, which should include:

1. **Tool function description**: the tool's main functions
2. **Use cases**: when to use this tool
3. **Notes**: precautions and warnings when using it
4. **Examples**: usage examples (optional)

**Important**:
- When the tool list is sent to the LLM, `short_description` is used (if present)
- If there is no `short_description`, the system automatically extracts the first line or the first 100 characters of `description`
- The detailed description can be retrieved through MCP's `resources/read` interface (URI: `tool://tool_name`)

This can greatly reduce token consumption, especially when there are many tools (e.g. 100 tools).

## Parameter Definitions

Each parameter can include the following fields:

- `name`: parameter name
- `type`: parameter type (string, int, bool, array)
- `description`: detailed parameter description (multi-line supported)
- `required`: whether it is required (true/false)
- `default`: default value
- `flag`: command-line flag (e.g. "-u", "--url", "-p")
- `position`: position of a positional argument (integer, starting from 0)
- `format`: parameter format ("flag", "positional", "combined", "template")
- `template`: template string (used with format="template")
- `options`: list of allowed values (used for enumerated types)

### Parameter Format Details

- **`flag`**: flag parameter, in the form `--flag value` or `-f value`
  - Example: `flag: "-u"` → `-u http://example.com`

- **`positional`**: positional argument, added to the command in order
  - Example: `position: 0` → used as the first positional argument

- **`combined`**: combined format, in the form `--flag=value`
  - Example: `flag: "--level"`, `format: "combined"` → `--level=3`

- **`template`**: template format, using a custom template string
  - Example: `template: "{flag} {value}"` → custom format

### Special Parameters

#### `additional_args` parameter

`additional_args` is a special parameter used to pass extra command-line options that are not defined in the parameter list. This parameter is parsed and split by spaces into multiple arguments.

**Use cases:**
- Passing advanced options of the tool
- Passing parameters that are not defined in the configuration
- Passing complex parameter combinations

**Example:**
```yaml
- name: "additional_args"
  type: "string"
  description: "Additional tool arguments, separated by spaces"
  required: false
  format: "positional"
```

**Usage examples:**
- `additional_args: "--script vuln -O"` → parsed as `["--script", "vuln", "-O"]`
- `additional_args: "-T4 --max-retries 3"` → parsed as `["-T4", "--max-retries", "3"]`

**Notes:**
- Arguments are split by spaces, but content inside quotes is preserved
- Make sure the argument format is correct to avoid command injection risks
- This parameter is appended to the end of the command

#### `scan_type` parameter (tool-specific)

Some tools (such as `nmap`) support the `scan_type` parameter, which overrides the default scan type argument.

**Example (nmap):**
```yaml
- name: "scan_type"
  type: "string"
  description: "Scan type option, can override the default scan type"
  required: false
  format: "positional"
```

**Usage examples:**
- `scan_type: "-sV -sC"` → version detection and script scanning
- `scan_type: "-A"` → comprehensive scan

**Notes:**
- If `scan_type` is specified, it replaces the default scan type arguments in the tool configuration
- Separate multiple options with spaces

### Parameter Description Requirements

A parameter description should include:

1. **Purpose**: what this parameter does
2. **Format requirements**: format requirements for the parameter value (e.g. URL format, port range format, etc.)
3. **Example values**: concrete example values (show multiple examples as a list)
4. **Notes**: things to watch out for when using it (permission requirements, performance impact, security warnings, etc.)

**Formatting tips:**
- Use Markdown formatting to improve readability
- Use `**bold**` to highlight important information
- Use lists to show multiple examples or options
- Use code blocks to show complex formats

**Example:**
```yaml
description: |
  Target IP address or domain name. Can be a single IP, IP range, CIDR format, or domain name.
  
  **Example values:**
  - Single IP: "192.168.1.1"
  - IP range: "192.168.1.1-100"
  - CIDR: "192.168.1.0/24"
  - Domain: "example.com"
  
  **Notes:**
  - Ensure the target address format is correct
  - Required parameter, cannot be empty
```

## Parameter Type Details

### Boolean type (bool)

Boolean parameters are handled specially:
- `true`: only the flag is added, with no value (e.g. `--flag`)
- `false`: no argument is added
- Multiple input formats are supported: `true`/`false`, `1`/`0`, `"true"`/`"false"`

**Example:**
```yaml
- name: "verbose"
  type: "bool"
  description: "Verbose output mode"
  required: false
  default: false
  flag: "-v"
  format: "flag"
```

### String type (string)

The most commonly used parameter type; supports any string value.

### Integer type (int/integer)

Used for numeric parameters, such as port numbers and levels.

**Example:**
```yaml
- name: "level"
  type: "int"
  description: "Testing level, range 1-5"
  required: false
  default: 3
  flag: "--level"
  format: "combined"  # --level=3
```

### Array type (array)

Arrays are automatically converted to comma-separated strings.

**Example:**
```yaml
- name: "ports"
  type: "array"
  item_type: "number"
  description: "Port list"
  required: false
  # Input: [80, 443, 8080]
  # Output: "80,443,8080"
```

## Examples

Refer to the existing tool configuration files in the `tools/` directory:

- `nmap.yaml`: network scanning tool (includes `scan_type` and `additional_args` examples)
- `sqlmap.yaml`: SQL injection detection tool (includes an `additional_args` example)
- `nikto.yaml`: web server scanning tool
- `dirb.yaml`: web directory scanning tool
- `exec.yaml`: system command execution tool

### Full Example: nmap Tool Configuration

```yaml
name: "nmap"
command: "nmap"
args: ["-sT", "-sV", "-sC"]  # default scan type
enabled: true

short_description: "Network scanning tool for discovering network hosts, open ports, and services"

description: |
  Network mapping and port scanning tool for discovering hosts, services, and open ports on a network.
  
  **Main features:**
  - Host discovery: detect active hosts on the network
  - Port scanning: identify open ports on the target host
  - Service detection: detect the type and version of services running on ports
  - OS detection: identify the target host's operating system
  - Vulnerability detection: use NSE scripts to detect common vulnerabilities

parameters:
  - name: "target"
    type: "string"
    description: "Target IP address or domain name"
    required: true
    position: 0
    format: "positional"
  
  - name: "ports"
    type: "string"
    description: "Port range, e.g.: 1-1000"
    required: false
    flag: "-p"
    format: "flag"
  
  - name: "scan_type"
    type: "string"
    description: "Scan type option, e.g.: '-sV -sC'"
    required: false
    format: "positional"
  
  - name: "additional_args"
    type: "string"
    description: "Additional Nmap arguments, e.g.: '--script vuln -O'"
    required: false
    format: "positional"
```

## Adding a New Tool

To add a new tool, simply create a new YAML file in the `tools/` directory, for example `my_tool.yaml`:

```yaml
name: "my_tool"
command: "my-command"
args: ["--default-arg"]  # fixed arguments (optional)
enabled: true

# Short description (recommended) - used in tool list to reduce token consumption
short_description: "One-sentence description of the tool's purpose"

# Detailed description - used for tool docs and AI comprehension
description: |
  Detailed tool description, supports multi-line text and Markdown formatting.
  
  **Main features:**
  - Feature 1
  - Feature 2
  
  **Use cases:**
  - Scenario 1
  - Scenario 2
  
  **Notes:**
  - Usage precautions
  - Permission requirements
  - Performance impact

parameters:
  - name: "target"
    type: "string"
    description: |
      Detailed target parameter description.
      
      **Example values:**
      - "value1"
      - "value2"
      
      **Notes:**
      - Format requirements
      - Usage limitations
    required: true
    position: 0  # positional argument
    format: "positional"
  
  - name: "option"
    type: "string"
    description: "Option parameter description"
    required: false
    flag: "--option"
    format: "flag"
  
  - name: "verbose"
    type: "bool"
    description: "Verbose output mode"
    required: false
    default: false
    flag: "-v"
    format: "flag"
  
  - name: "additional_args"
    type: "string"
    description: "Additional tool arguments, separated by spaces"
    required: false
    format: "positional"
```

After saving the file, restart the service to automatically load the new tool.

### Tool Configuration Best Practices

1. **Parameter design**
   - Define commonly used parameters separately so the AI can understand and use them easily
   - Use `additional_args` to provide flexibility and support advanced usage
   - Provide clear descriptions and examples for parameters

2. **Description optimization**
   - Use `short_description` to reduce token consumption
   - `description` should be detailed to help the AI understand the tool's purpose
   - Use Markdown formatting to improve readability

3. **Default value settings**
   - Set sensible default values for commonly used parameters
   - Boolean defaults are usually set to `false`
   - Set numeric values according to the tool's characteristics

4. **Parameter validation**
   - Clearly state parameter format requirements in the description
   - Provide multiple example values
   - Explain parameter limits and precautions

5. **Security**
   - For dangerous operations, add warnings in the description
   - State permission requirements
   - Remind users to use the tool only in authorized environments

6. **Single execution duration and timeouts (best practice)**
   - If a tool often runs for a very long time (e.g. still showing "running" after more than 10-30 minutes), this is an abnormally long hang; it is recommended to:
     - Set the maximum execution time for a single tool call in `agent.tool_timeout_minutes` in **config.yaml** (default 10 minutes); after the timeout, it is terminated automatically and resources are released;
     - When longer scans are needed, increase this value appropriately (e.g. 20 or 30); setting it to 0 (unlimited) is not recommended;
     - On the task monitoring page, use "Stop task" on the whole task to interrupt the current conversation and subsequent tool calls;
     - Where possible, make tool implementations interruptible or give them built-in timeouts (e.g. a timeout set inside the script) so they work together with the system timeout.

## Disabling a Tool

To disable a tool, simply set its `enabled` field to `false` in the configuration file, or delete/rename the configuration file.

Once disabled, the tool does not appear in the tool list, and the AI cannot call it.

## Tool Configuration Validation

The system performs basic validation when loading tool configurations:

- Checks required fields (`name`, `command`, `enabled`)
- Validates the parameter definition format
- Checks whether parameter types are supported

If a configuration is wrong, the system shows a warning in the startup log but does not prevent the server from starting. Incorrect tool configurations are skipped, and other tools remain usable.

## FAQ

### Q: How do I pass multiple parameter values?

A: For array-type parameters, the system automatically converts them to comma-separated strings. When you need to pass multiple independent arguments, you can use the `additional_args` parameter.

### Q: How do I override a tool's default arguments?

A: Some tools (such as `nmap`) support the `scan_type` parameter to override the default scan type. For other cases, you can use the `additional_args` parameter.

### Q: What if a tool runs for over 30 minutes and still shows "running"?

A: This is an abnormally long hang; it is recommended to:
1. Configure `agent.tool_timeout_minutes` in **config.yaml** (default 10); a single tool call exceeding this number of minutes is terminated automatically;
2. On the monitoring page, use "Stop task" on that task to interrupt it immediately;
3. If the tool really needs more time, you can increase `tool_timeout_minutes` appropriately, but setting it to 0 is not recommended.

### Q: What if a tool fails to execute?

A: Check the following:
1. The tool is installed and on the system PATH
2. The tool configuration is correct
3. Parameter formats meet the requirements
4. Check the server logs for detailed error information

### Q: How do I test a tool configuration?

A: You can use the `cmd/test-config/main.go` tool to test configuration loading:
```bash
go run cmd/test-config/main.go
```

### Q: How do I control parameter order?

A: Use the `position` field to control the order of positional arguments. **Positional arguments at position 0 (such as the `dir` subcommand of gobuster) are placed right after the command name and before all flag arguments**, so that CLIs taking the "subcommand + options" form are supported. The remaining flag arguments are added in the order they appear in the `parameters` list, and the other positional arguments are then added by position 1, 2, and so on. `additional_args` is appended to the end of the command.

## Tool Configuration Templates

### Basic Tool Template

```yaml
name: "tool_name"
command: "command"
enabled: true

short_description: "Short description (20-50 characters)"

description: |
  Detailed description explaining the tool's features, use cases, and notes.

parameters:
  - name: "target"
    type: "string"
    description: "Target parameter description"
    required: true
    position: 0
    format: "positional"
  
  - name: "additional_args"
    type: "string"
    description: "Additional tool arguments"
    required: false
    format: "positional"
```

### Tool Template with Flag Parameters

```yaml
name: "tool_name"
command: "command"
enabled: true

short_description: "Short description"

description: |
  Detailed description.

parameters:
  - name: "target"
    type: "string"
    description: "Target"
    required: true
    flag: "-t"
    format: "flag"
  
  - name: "option"
    type: "bool"
    description: "Option"
    required: false
    default: false
    flag: "--option"
    format: "flag"
  
  - name: "level"
    type: "int"
    description: "Level"
    required: false
    default: 3
    flag: "--level"
    format: "combined"
  
  - name: "additional_args"
    type: "string"
    description: "Additional arguments"
    required: false
    format: "positional"
```

## Related Documentation

- Main project README: see `README.md` for complete project documentation
- Tool list: see all tool configuration files in the `tools/` directory
- API documentation: see the API reference in the main README
