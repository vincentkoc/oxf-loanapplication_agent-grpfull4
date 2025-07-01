Inter-Agent Flow (with Execution Strategy & Flow Type)

Loan Application Submitted (PDF or JSON)

|
V                  
Agent Name: Application Processing Agent
Action: Validates input completeness
Action: Calls PDF to JSON if needed
Execution Strategy: Deterministic

|							     |
V							    V                   
Incomplete
Agent Name: Alerting Agent
Action: Notify the Customer
Execution Strategy: LLM-based Agent-as-Tool via MCP
Complete
Agent Name: Compliance Agent
Action: PEP/Sanction Check
Action: Identity Verification
Action: Affordability Check
Action: Check Source of Wealth 
Execution Strategy: LLM-based Agent-as-Tool via MCP
Agent Name: Fraud Detection Agent
Action: Analyse History + Behaviour
Execution Strategy: LLM-based Agent-as-Tool via MCP

  |							|
 V						           V    
Agent Name: Decision Agent
Action: Consolidates Compliance, Fraud, Application Processing Agent input
Action: Approves / Rejects / Escalates Application
Execution Strategy: Hybrid LLM-based 

|
V     
Agent Name: Alerting Agent
Action: Alerts Approval / Rejection / Escalation
Execution Strategy: LLM-based Agent-as-Tool via MCP

