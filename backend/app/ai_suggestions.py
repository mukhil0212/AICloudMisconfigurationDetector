import os
from groq import Groq
from dotenv import load_dotenv

# Load .env file from the backend directory
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(env_path)

api_key = os.environ.get("GROQ_API_KEY")
if not api_key:
    print("Warning: GROQ_API_KEY not found in environment variables")

client = Groq(
    api_key=api_key,
)

def get_remediation_suggestions(misconfiguration):
    """
    Generate AI-powered remediation suggestions for cloud misconfigurations
    """
    # Check if API key is available
    if not api_key:
        return {
            "suggestion": "AI suggestions unavailable: GROQ_API_KEY not configured. Please set your Groq API key in the .env file.",
            "confidence": "low"
        }
    
    prompt = f"""
    You are a cloud security expert. Analyze this cloud misconfiguration and provide specific remediation guidance.

    Issue: {misconfiguration['type']}
    Resource: {misconfiguration['resource_id']}
    Problem: {misconfiguration['details']}

    Provide a structured response with:

    🔍 SECURITY RISK:
    [Brief explanation of why this is dangerous]

    🛠️ IMMEDIATE FIX:
    [Step-by-step remediation with specific commands]

    ⚡ QUICK CLI COMMANDS:
    [AWS CLI commands to fix this issue]

    🔒 PREVENTION:
    [Best practices to prevent this in the future]

    Keep it concise but actionable. Use bullet points and code blocks where helpful.
    """

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.1-8b-instant",
            temperature=0.3,
            max_tokens=1000,
        )
        
        return {
            "suggestion": chat_completion.choices[0].message.content,
            "confidence": "high" if "public" in misconfiguration['type'].lower() or "unrestricted" in misconfiguration['type'].lower() else "medium"
        }
    
    except Exception as e:
        print(f"Error calling Groq API: {str(e)}")
        return {
            "suggestion": f"Unable to generate AI suggestion: {str(e)}",
            "confidence": "low"
        }

def calculate_confidence_score(misconfiguration, strictness_level="balanced"):
    """
    Calculate confidence score based on issue characteristics and strictness level
    """
    base_score = 0.5
    issue_type = misconfiguration.get("type", "").lower()
    
    # Risk-based scoring
    if "public" in issue_type or "unrestricted" in issue_type:
        base_score += 0.4  # High risk = high confidence
    elif "permissive" in issue_type or "iam" in issue_type:
        base_score += 0.2  # Medium risk
    else:
        base_score += 0.1  # Low risk
    
    # Strictness adjustments
    if strictness_level == "strict":
        base_score *= 1.2  # More aggressive flagging
    elif strictness_level == "lenient":
        base_score *= 0.8  # Less aggressive flagging
    
    # Ensure score is between 0 and 1
    return min(max(base_score, 0.0), 1.0)

def get_bulk_suggestions(misconfigurations, ai_confidence_threshold=0.7, strictness_level="balanced"):
    """
    Generate suggestions for multiple misconfigurations with confidence filtering
    """
    suggestions = []
    for config in misconfigurations:
        # Calculate numeric confidence score
        confidence_score = calculate_confidence_score(config, strictness_level)
        
        # Skip if below threshold
        if confidence_score < ai_confidence_threshold:
            continue
            
        suggestion = get_remediation_suggestions(config)
        
        # Convert to categorical confidence for display
        if confidence_score >= 0.8:
            confidence_category = "high"
        elif confidence_score >= 0.6:
            confidence_category = "medium"
        else:
            confidence_category = "low"
        
        suggestions.append({
            **config,
            "ai_suggestion": suggestion["suggestion"],
            "confidence": confidence_category,
            "confidence_score": round(confidence_score, 2),
            "strictness_level": strictness_level
        })
    return suggestions