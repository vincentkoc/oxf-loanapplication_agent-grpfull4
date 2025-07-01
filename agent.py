# Hybrid Agentic Loan Workflow using LangGraph
# ---------------------------------------------
# Combines deterministic agents + LLM agents with MCP tool usage

import asyncio
from typing import TypedDict, Optional, List
from agents import Agent, Runner, tool
import re

# TODO: For notebook usage, consider installing openai-agents if not present
# !pip install openai-agents

# ---------------------------
# Define the shared state
# ---------------------------
class AppState(TypedDict):
    application_data: dict
    status: str
    compliance_result: Optional[dict]
    fraud_result: Optional[dict]
    decision_result: Optional[str]
    decision_reason: Optional[str]
    alerts: List[str]
    alert_summary: Optional[str]
    metrics: dict

# ---------------------------
# Mock Data and Tools
# ---------------------------

# Mock data for fraud detection
FRAUDULENT_NAMES = ["john shady", "anna dodgy", "mr sanction"]

# TODO: In a real scenario, this would be a robust validation library or service.
@tool
def uk_postcode_validator(postcode: str) -> bool:
    """Validates a UK postcode format. This is a mock implementation."""
    # A very basic regex for UK postcodes.
    pattern = re.compile(r"^[A-Z]{1,2}[0-9R][0-9A-Z]? [0-9][A-Z]{2}$")
    return bool(pattern.match(postcode.upper()))

# ---------------------------
# Compliance Agent Tools
# ---------------------------

@tool
def pep_sanction_check(name: str) -> dict:
    """
    Checks if a name is on a Political Exposed Person (PEP) or sanctions list.
    This is a mock implementation.
    """
    # TODO: This should be replaced by an MCP call to a compliance service.
    print(f"   - Checking PEP/sanctions for: {name}")
    if name.lower() in FRAUDULENT_NAMES:
        return {"status": "fail", "reason": "Name found on a watchlist."}
    return {"status": "pass"}

@tool
def identity_verification(document_content: str) -> dict:
    """
    Verifies an identity document. This is a mock implementation.
    The content of the document is passed as a string.
    """
    # TODO: This should be replaced by an MCP call to an identity verification service.
    # TODO: Add PDF/document parsing (e.g., Docling) before this step.
    print(f"   - Verifying identity document...")
    if "invalid" in document_content:
        return {"status": "fail", "reason": "Document is invalid."}
    return {"status": "pass"}

@tool
def assess_affordability(income: int, loan_amount: int) -> dict:
    """
    Assesses the applicant's loan affordability based on income and loan amount.
    This is a mock implementation.
    """
    # TODO: This should be replaced by an MCP call to an affordability service.
    print(f"   - Assessing affordability for income {income} and loan {loan_amount}")
    if income < (loan_amount / 2):  # Simple rule
        return {"status": "fail", "reason": "Income too low for this loan amount."}
    return {"status": "pass"}

@tool
def source_of_wealth_check(source_description: str) -> dict:
    """
    Verifies the applicant's source of wealth. This is a mock implementation.
    """
    # TODO: This should be replaced by an MCP call to a Source of Wealth service.
    print(f"   - Checking source of wealth: {source_description}")
    if "illegal" in source_description.lower():
        return {"status": "fail", "reason": "Suspicious source of wealth."}
    return {"status": "pass"}

# ---------------------------
# Fraud Agent Tool
# ---------------------------

@tool
def fraud_detection(application: dict) -> dict:
    """
    Detects fraud signals in the application data. Mock implementation.
    """
    # TODO: This should be replaced by an MCP call to a fraud detection service.
    print(f"   - Running fraud detection...")
    flags = []
    score = 0.0
    name = application.get("full_name", "").lower()
    if name in FRAUDULENT_NAMES:
        flags.append("Name is on a watchlist.")
        score += 0.8
    if "postcode" in application and not uk_postcode_validator(application["postcode"]):
        flags.append("Invalid UK postcode.")
        score += 0.3

    return {"fraud_score": min(1.0, score), "flags": flags}

# ---------------------------
# Alerting Agent Tool
# ---------------------------

@tool
def send_alert(message: str) -> dict:
    """Sends an alert. Mock implementation."""
    # TODO: Replace with real MCP call to an alerting service (e.g., email, SMS).
    print(f"   - Sending alert: {message}")
    return {"status": "sent"}


# ---------------------------
# Deterministic Application Processor
# ---------------------------
def application_processor(state: AppState) -> AppState:
    """
    Validates the initial application for completeness.
    This is a deterministic step.
    """
    print("Step 1: Processing application...")
    app = state["application_data"]
    # TODO: Add PDF/markdown parsing logic here (e.g., using Docling or an OpenAI tool)
    # For now, we assume the input is structured JSON/dict.

    required_fields = ["full_name", "income", "loan_amount", "document_id", "source_of_wealth", "postcode"]
    missing_fields = [field for field in required_fields if not app.get(field)]

    if missing_fields:
        state["alerts"].append(f"Application incomplete. Missing fields: {', '.join(missing_fields)}")
        state["status"] = "incomplete"
    else:
        state["status"] = "validated"
    print(f"Application status: {state['status']}")
    return state

# ---------------------------
# Define Agents
# ---------------------------

compliance_agent = Agent(
    name="ComplianceAgent",
    instructions="""
    You are a compliance officer. Use the provided tools to perform all required compliance checks on the loan application.
    The user will provide the application data as a prompt.
    You must call all relevant tools based on the application data (pep_sanction_check, identity_verification, assess_affordability, source_of_wealth_check).
    Consolidate the results from all checks into a single JSON object.
    """,
    model="gpt-4o-mini",
    tools=[
        pep_sanction_check,
        identity_verification,
        assess_affordability,
        source_of_wealth_check,
    ],
    output_type=dict
)

fraud_agent = Agent(
    name="FraudAgent",
    instructions="You are a fraud detection specialist. Use the fraud_detection tool to assess the application for fraud risk. Return the fraud score and any flags.",
    model="gpt-4o-mini",
    tools=[fraud_detection],
    output_type=dict
)

decision_agent = Agent(
    name="DecisionAgent",
    instructions="""
    Based on the compliance and fraud results, decide if the loan application should be 'approved', 'rejected' or 'escalated'.
    Provide a clear one-sentence reason for your decision.
    - Escalate if compliance checks have failed but fraud risk is low.
    - Reject if fraud risk is high (score > 0.7).
    - Approve if all checks pass and fraud score is low.
    Return a dictionary with 'decision' and 'reason'.
    """,
    model="gpt-4o-mini",
    output_type=dict
)

alert_agent = Agent(
    name="AlertAgent",
    instructions="You are an alerting agent. A user will provide a message to send. Use the send_alert tool to deliver this message.",
    model="gpt-4o-mini",
    tools=[send_alert],
)

# ---------------------------
# Main Workflow Orchestration
# ---------------------------
async def run_workflow(application: dict):
    """
    Orchestrates the loan application workflow using OpenAI Agents SDK.
    """
    print("🚀 Starting Hybrid Agentic Workflow...")
    # Initialize state
    state = AppState(
        application_data=application,
        status="new",
        compliance_result=None,
        fraud_result=None,
        decision_result=None,
        decision_reason=None,
        alerts=[],
        alert_summary=None,
        metrics={},
    )

    # 1. Deterministic validation
    state = application_processor(state)

    # 2. Handle incomplete application
    if state["status"] == "incomplete":
        print("\nStep 2: Application incomplete. Sending alert.")
        alert_message = state["alerts"][0]
        result = await Runner.run(alert_agent, f"The application is incomplete. Please inform the user with the following message: {alert_message}")
        state["alert_summary"] = result.final_output
        print("Workflow finished: Application incomplete.")
        return state

    # 3. Parallel Compliance and Fraud checks
    print("\nStep 2: Running Compliance and Fraud agents in parallel...")
    compliance_prompt = f"Please run compliance checks for this application: {state['application_data']}"
    fraud_prompt = f"Please run a fraud check for this application: {state['application_data']}"
    
    # Use asyncio.gather to run agents concurrently
    compliance_task = Runner.run(compliance_agent, compliance_prompt)
    fraud_task = Runner.run(fraud_agent, fraud_prompt)
    
    results = await asyncio.gather(compliance_task, fraud_task)
    
    state["compliance_result"] = results[0].final_output
    state["fraud_result"] = results[1].final_output
    print(f"Compliance result: {state['compliance_result']}")
    print(f"Fraud result: {state['fraud_result']}")

    # 4. Decision Agent
    print("\nStep 3: Running Decision agent...")
    decision_prompt = f"""
    Please make a decision based on these results:
    Compliance: {state['compliance_result']}
    Fraud: {state['fraud_result']}
    """
    try:
        result = await Runner.run(decision_agent, decision_prompt)
        decision_output = result.final_output
        state["decision_result"] = decision_output.get("decision")
        state["decision_reason"] = decision_output.get("reason")
    except Exception as e:
        print(f"[Decision Agent] LLM failed: {e}. Using fallback logic.")
        # Fallback deterministic rules
        comp = state["compliance_result"]
        fraud = state["fraud_result"]
        affordability_pass = all(c.get('status') == 'pass' for c in comp.values() if isinstance(c, dict))
        
        if affordability_pass and fraud.get("fraud_score", 1.0) < 0.7:
            state["decision_result"] = "approved"
            state["decision_reason"] = "Fallback: Checks passed and fraud risk is below threshold."
        else:
            state["decision_result"] = "rejected"
            state["decision_reason"] = "Fallback: Checks failed or fraud risk is too high."

    print(f"Decision: {state['decision_result']} - Reason: {state['decision_reason']}")
    
    # 5. Alerting
    print("\nStep 4: Sending final notification alert...")
    alert_message = f"Loan application decision: {state['decision_result']}. Reason: {state['decision_reason']}"
    await Runner.run(alert_agent, alert_message)
    print("\n✅ Workflow finished.")
    return state

# ---------------------------
# Run with dummy data
# ---------------------------
async def main():
    # Example 1: A good application
    print("--- Running Scenario 1: Clean Application ---")
    clean_application = {
        "full_name": "Alice Wonderland",
        "income": 80000,
        "loan_amount": 15000,
        "document_id": "valid_passport.pdf",
        "source_of_wealth": "employment",
        "postcode": "SW1A 0AA"
    }
    final_state_1 = await run_workflow(clean_application)
    print("\n--- FINAL STATE (Scenario 1) ---")
    print(final_state_1)

    print("\n\n" + "="*50 + "\n")

    # Example 2: A fraudulent application
    print("--- Running Scenario 2: Fraudulent Application ---")
    fraudulent_application = {
        "full_name": "John Shady",
        "income": 50000,
        "loan_amount": 25000,
        "document_id": "valid_id.jpg",
        "source_of_wealth": "inheritance",
        "postcode": "B4D C0D3" # Invalid postcode
    }
    final_state_2 = await run_workflow(fraudulent_application)
    print("\n--- FINAL STATE (Scenario 2) ---")
    print(final_state_2)


# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    # Ensure you have set the OPENAI_API_KEY environment variable
    # import os
    # assert os.getenv("OPENAI_API_KEY"), "Please set the OPENAI_API_KEY environment variable."
    asyncio.run(main())
