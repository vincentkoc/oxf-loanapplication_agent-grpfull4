# Hybrid Agentic Loan Workflow using LangGraph
# ---------------------------------------------
# Combines deterministic agents + LLM agents with MCP tool usage

import asyncio
from typing_extensions import TypedDict
from typing import Optional, List, Literal
from agents import Agent, Runner, function_tool
import re
from rapidfuzz import fuzz, process  # pip install rapidfuzz
import phonenumbers  # pip install phonenumbers
from phonenumbers.phonenumberutil import NumberParseException
import json

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

# TODO: In a real scenario, this would be a robust validation library or service.
@function_tool(strict_mode=False)
def uk_postcode_validator(postcode: str) -> bool:
    """Validates a UK postcode format. This is a mock implementation."""
    # A very basic regex for UK postcodes.
    pattern = re.compile(r"^[A-Z]{1,2}[0-9R][0-9A-Z]? [0-9][A-Z]{2}$")
    return bool(pattern.match(postcode.upper()))

# ---------------------------
# Tool Output TypedDicts
# ---------------------------

class PepSanctionResult(TypedDict):
    status: Literal["pass", "fail", "manual_verification"]
    reason: Optional[str]

class IdentityVerificationResult(TypedDict):
    status: Literal["pass", "fail"]
    reason: Optional[str]

class AffordabilityResult(TypedDict):
    status: Literal["pass", "fail"]
    reason: Optional[str]

class SourceOfWealthResult(TypedDict):
    status: Literal["pass", "fail"]
    reason: Optional[str]

class FraudDetectionResult(TypedDict):
    fraud_score: float
    flags: List[str]

class SendAlertResult(TypedDict):
    status: str

# ---------------------------
# Compliance Agent Tools
# ---------------------------

# Mock data for fraud detection
FRAUDULENT_NAMES = [
    "john shady",
    "anna dodgy",
    "mr sanction",
    "lisa scammer",
    "peter fraudwell",
    "olga blacklist",
    "ivan launder",
    "maria suspect",
    "tony riskman",
    "sarah shell",
    "viktor mule",
    "nina fakeid",
    "george bribe",
    "lucy offshor",
    "mohammed sanction",
    "jane alias",
    "david ghost",
    "emily shadow",
    "frankie wire",
    "sophia mule"
]

@function_tool(strict_mode=False)
def pep_sanction_check(name: str) -> PepSanctionResult:
    """
    Checks if a name is on a Political Exposed Person (PEP) or sanctions list, with fuzzy matching.
    Returns 'fail' for exact, 'manual_verification' for close matches, 'pass' otherwise.
    """
    print(f"   - Checking PEP/sanctions for: {name}")
    name_lower = name.lower()
    # Exact match
    if name_lower in FRAUDULENT_NAMES:
        return {"status": "fail", "reason": "Name found on a watchlist (exact match)."}

    # Fuzzy match
    best_match = None
    score = 0
    try:
        best_match, score, _ = process.extractOne(name_lower, FRAUDULENT_NAMES, scorer=fuzz.ratio)
    except Exception:
        pass
    if best_match and score > 80:
        return {"status": "manual_verification", "reason": f"Name similar to watchlist entry: '{best_match}' (score: {score})"}

    return {"status": "pass", "reason": None}

@function_tool(strict_mode=False)
def identity_verification(document_content: str) -> IdentityVerificationResult:
    """
    Verifies an identity document. This is a mock implementation.
    The content of the document is passed as a string.
    """
    # TODO: This should be replaced by an MCP call to an identity verification service.
    # TODO: Add PDF/document parsing (e.g., Docling) before this step.
    print(f"   - Verifying identity document...")
    if "invalid" in document_content:
        return {"status": "fail", "reason": "Document is invalid."}
    return {"status": "pass", "reason": None}

@function_tool(strict_mode=False)
def assess_affordability(income: int, loan_amount: int) -> AffordabilityResult:
    """
    Assesses the applicant's loan affordability based on income and loan amount.
    This is a mock implementation.
    """
    # TODO: This should be replaced by an MCP call to an affordability service.
    print(f"   - Assessing affordability for income {income} and loan {loan_amount}")
    if income < (loan_amount / 2):  # Simple rule
        return {"status": "fail", "reason": "Income too low for this loan amount."}
    return {"status": "pass", "reason": None}

@function_tool(strict_mode=False)
def source_of_wealth_check(source_description: str) -> SourceOfWealthResult:
    """
    Verifies the applicant's source of wealth. This is a mock implementation.
    """
    # TODO: This should be replaced by an MCP call to a Source of Wealth service.
    print(f"   - Checking source of wealth: {source_description}")
    if "illegal" in source_description.lower():
        return {"status": "fail", "reason": "Suspicious source of wealth."}
    return {"status": "pass", "reason": None}

# ---------------------------
# Phone Number Validator Tool
# ---------------------------
@function_tool(strict_mode=False)
def phone_number_validator(phone_number: str, region: str = "GB") -> bool:
    """
    Validates a phone number using Google's libphonenumber.
    Returns True if valid, False otherwise.
    """
    try:
        parsed = phonenumbers.parse(phone_number, region)
        return phonenumbers.is_valid_number(parsed)
    except NumberParseException:
        return False

# ---------------------------
# ApplicationData TypedDict
# ---------------------------

class ApplicationData(TypedDict):
    full_name: str
    income: int
    loan_amount: int
    document_id: str
    source_of_wealth: str
    postcode: str
    phone_number: str

# ---------------------------
# Fraud Agent Tool
# ---------------------------

@function_tool(strict_mode=False)
def fraud_detection(application: ApplicationData) -> FraudDetectionResult:
    """
    Detects fraud signals in the application data. Mock implementation.
    """
    # TODO: This should be replaced by an MCP call to a fraud detection service.
    print(f"   - Running fraud detection...")
    flags = []
    score = 0.0
    name = application["full_name"].lower()
    if name in FRAUDULENT_NAMES:
        flags.append("Name is on a watchlist.")
        score += 0.8
    if not uk_postcode_validator(application["postcode"]):
        flags.append("Invalid UK postcode.")
        score += 0.3

    return {"fraud_score": min(1.0, score), "flags": flags}

# ---------------------------
# Alerting Agent Tool
# ---------------------------

@function_tool(strict_mode=False)
def send_alert(message: str) -> SendAlertResult:
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
    You must call all relevant tools based on the application data (pep_sanction_check, identity_verification, assess_affordability, source_of_wealth_check, phone_number_validator).
    Consolidate the results from all checks into a single JSON object.
    """,
    model="gpt-4o-mini",
    tools=[
        pep_sanction_check,
        identity_verification,
        assess_affordability,
        source_of_wealth_check,
        phone_number_validator,
    ],
)

fraud_agent = Agent(
    name="FraudAgent",
    instructions="You are a fraud detection specialist. Use the fraud_detection tool to assess the application for fraud risk. Return the fraud score and any flags.",
    model="gpt-4o-mini",
    tools=[fraud_detection],
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
)

alert_agent = Agent(
    name="AlertAgent",
    instructions="""
    You are an alerting agent for a loan application service. 
    When provided with a message, use the send_alert tool to deliver it to the user.
    Ensure the message is communicated in a friendly, professional, and supportive tone, 
    helping the user understand any issues or next steps regarding their loan application.
    """,
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
    compliance_prompt = f"Please run compliance checks for this application: {json.dumps(state['application_data'])}"
    fraud_prompt = f"Please run a fraud check for this application: {json.dumps(state['application_data'])}"
    
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
        # Try to parse string output as JSON if needed
        if isinstance(decision_output, str):
            try:
                decision_output = json.loads(decision_output)
            except Exception:
                pass
        if isinstance(decision_output, dict):
            state["decision_result"] = decision_output.get("decision")
            state["decision_reason"] = decision_output.get("reason")
        else:
            raise ValueError("Decision agent output is not a dict.")
    except Exception as e:
        print(f"[Decision Agent] LLM failed: {e}. Using fallback logic.")
        # Fallback deterministic rules
        comp = state["compliance_result"]
        fraud = state["fraud_result"]
        # Ensure comp is a dict before using .values()
        affordability_pass = False
        if isinstance(comp, dict):
            affordability_pass = all(
                (c.get('status') == 'pass')
                for c in comp.values() if isinstance(c, dict)
            )
        # Ensure fraud is a dict before using .get()
        fraud_score = 1.0
        if isinstance(fraud, dict):
            fraud_score = fraud.get("fraud_score", 1.0)
        if affordability_pass and fraud_score < 0.7:
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
        "postcode": "SW1A 0AA",
        "phone_number": "+447911123456"
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
        "postcode": "B4D C0D3", # Invalid postcode
        "phone_number": "07911123456"  # Invalid format (missing +44)
    }
    final_state_2 = await run_workflow(fraudulent_application)
    print("\n--- FINAL STATE (Scenario 2) ---")
    print(final_state_2)

    print("\n\n" + "="*50 + "\n")

    # Example 3: A similar name (should trigger manual verification)
    print("--- Running Scenario 3: Similar Name (Manual Verification) ---")
    similar_name_application = {
        "full_name": "Jon Shadey",  # Similar to 'john shady'
        "income": 60000,
        "loan_amount": 10000,
        "document_id": "valid_id.jpg",
        "source_of_wealth": "salary",
        "postcode": "EC1A 1BB",
        "phone_number": "+447911654321"
    }
    final_state_3 = await run_workflow(similar_name_application)
    print("\n--- FINAL STATE (Scenario 3) ---")
    print(final_state_3)

    print("\n\n" + "="*50 + "\n")

    # Example 4: Incomplete application (should trigger an alert)
    print("--- Running Scenario 4: Incomplete Application (Missing Fields) ---")
    incomplete_application = {
        "full_name": "Bob Missingfields",
        # "income" is missing
        "loan_amount": 5000,
        # "document_id" is missing
        "source_of_wealth": "savings",
        "postcode": "W1A 1AA",
        "phone_number": "+447911000000"
    }
    final_state_4 = await run_workflow(incomplete_application)
    print("\n--- FINAL STATE (Scenario 4) ---")
    print(final_state_4)


# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    # Ensure you have set the OPENAI_API_KEY environment variable
    # import os
    # assert os.getenv("OPENAI_API_KEY"), "Please set the OPENAI_API_KEY environment variable."
    asyncio.run(main())
