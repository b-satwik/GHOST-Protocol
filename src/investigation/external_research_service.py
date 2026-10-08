"""
External Research Service for GHOST PROTOCOL CTI AI Mode / Search.
Provides search-grounded external threat research and intelligence enrichment.

Flow:
1. Retrieve threat session CTI context.
2. Sanitize outbound context (strip credentials, tokens, PII, secrets).
3. Construct search query.
4. Execute search AI via official provider API (Gemini Search Grounding).
5. Record provenance and sources clearly separated from local observed evidence.
"""

import os
import re
import uuid
import datetime
import json
from typing import Dict, Any, List, Optional
from src.dataset.annotation_store import AnnotationStore
from src.config.env_config import load_project_env

class ExternalResearchService:
    """
    Executes external web AI research queries grounded in threat session CTI context.
    Maintains strict separation between observed local evidence and external AI claims.
    """

    SECRET_PATTERNS = [
        re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key|bearer|cookie|session_id)\s*[:=]\s*[\'\"]?[^\s\'\"]+[\'\"]?'),
        re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),  # JWT
        re.compile(r'ghp_[A-Za-z0-9]{36}'),  # GitHub token
        re.compile(r'sk-[A-Za-z0-9]{32,}'),  # OpenAI key
        re.compile(r'AIzaSy[A-Za-z0-9-_]{33}')  # Google API Key
    ]

    def __init__(self, store: Optional[AnnotationStore] = None, provider_name: str = "GEMINI_SEARCH_GROUNDING"):
        self.store = store or AnnotationStore()
        self.provider_name = provider_name
        load_project_env()

    def sanitize_outbound_context(self, text_or_dict: Any) -> Any:
        """
        Sanitizes outbound context to ensure no sensitive credentials, secrets, or PII
        are transmitted to external APIs.
        """
        if isinstance(text_or_dict, str):
            clean_str = text_or_dict
            for pat in self.SECRET_PATTERNS:
                clean_str = pat.sub('[REDACTED_SECRET]', clean_str)
            return clean_str
        elif isinstance(text_or_dict, dict):
            clean_dict = {}
            for k, v in text_or_dict.items():
                if any(sec in k.lower() for sec in ["password", "secret", "token", "cookie", "auth"]):
                    clean_dict[k] = "[REDACTED]"
                else:
                    clean_dict[k] = self.sanitize_outbound_context(v)
            return clean_dict
        elif isinstance(text_or_dict, list):
            return [self.sanitize_outbound_context(item) for item in text_or_dict]
        return text_or_dict

    def build_sanitized_cti_context(self, session_id: str) -> Dict[str, Any]:
        """
        Retrieves and sanitizes CTI context for a threat session.
        """
        session_data = self.store.get_threat_session(session_id)
        if not session_data:
            return {
                "session_id": session_id,
                "actors": [],
                "targets": [],
                "indicators": [],
                "mitre_techniques": [],
                "summary": "Session context unavailable"
            }

        context = {
            "session_id": session_data.get("session_id"),
            "actors": session_data.get("actors", []),
            "aliases": session_data.get("aliases", []),
            "targets": session_data.get("targets", []),
            "indicators": session_data.get("indicators", [])[:10],
            "urls": session_data.get("urls", [])[:5],
            "mitre_techniques": session_data.get("mitre_techniques", []),
            "status": session_data.get("status")
        }

        return self.sanitize_outbound_context(context)

    def execute_research(self, session_id: str, analyst_question: str) -> Dict[str, Any]:
        """
        Executes external research query combining analyst question with session CTI context.
        """
        research_id = f"RES-{uuid.uuid4().hex[:8].upper()}"
        ts_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # 1. Retrieve & sanitize CTI context
        cti_context = self.build_sanitized_cti_context(session_id)
        sanitized_question = self.sanitize_outbound_context(analyst_question)

        # 2. Construct search prompt
        query_prompt = f"""
CTI Research Request:
Question: {sanitized_question}

Session CTI Context:
- Session ID: {cti_context.get('session_id')}
- Actors/Aliases: {', '.join(cti_context.get('actors', []) + cti_context.get('aliases', []))}
- Target Organizations: {', '.join(cti_context.get('targets', []))}
- Known Indicators: {', '.join(cti_context.get('indicators', []))}
- MITRE Techniques: {', '.join(cti_context.get('mitre_techniques', []))}

Please search public security intelligence repositories and provide verified external threat intelligence context, recent security advisories, or public CVE/malware details matching this threat activity.
"""

        # 3. Ensure env is loaded & check provider credentials
        load_project_env()
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        
        sources = []
        answer = ""
        status = "SUCCESS"
        provenance_label = "EXTERNAL WEB AI RESEARCH"

        if not api_key or not api_key.strip():
            status = "CONFIGURATION_REQUIRED"
            answer = ("[CONFIGURATION REQUIRED] External search AI provider credentials (GEMINI_API_KEY or GOOGLE_API_KEY) "
                      "are not configured on the GHOST host machine. Set GEMINI_API_KEY to enable live Web AI grounding.")
            provenance_label = "EXTERNAL RESEARCH — CONFIGURATION REQUIRED"
        else:
            try:
                # 1. Try google.generativeai SDK if available
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel("gemini-1.5-flash", tools=[{"google_search": {}}])
                    response = model.generate_content(query_prompt)
                    if response and hasattr(response, "text"):
                        answer = response.text
                    if hasattr(response, "candidates") and response.candidates:
                        cand = response.candidates[0]
                        grounding = getattr(cand, "grounding_metadata", None)
                        if grounding:
                            chunks = getattr(grounding, "grounding_chunks", [])
                            for ch in chunks:
                                web = getattr(ch, "web", None)
                                if web:
                                    uri = getattr(web, "uri", None)
                                    title = getattr(web, "title", uri)
                                    if uri and uri not in [s.get("url") for s in sources]:
                                        sources.append({"title": title or uri, "url": uri})
                except ImportError:
                    # 2. Fallback to direct HTTP REST API call via urllib/requests
                    import urllib.request
                    import json
                    import time

                    models_to_try = ["gemini-flash-latest", "gemini-pro-latest", "gemini-1.5-flash"]
                    call_success = False
                    last_err = ""

                    for m_name in models_to_try:
                        url = f"https://generativelanguage.googleapis.com/v1beta/models/{m_name}:generateContent?key={api_key}"
                        req_data = json.dumps({
                            "contents": [{"parts": [{"text": query_prompt}]}]
                        }).encode("utf-8")
                        req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"})
                        try:
                            with urllib.request.urlopen(req, timeout=12) as resp:
                                resp_json = json.loads(resp.read().decode("utf-8"))
                                candidates = resp_json.get("candidates", [])
                                if candidates:
                                    parts = candidates[0].get("content", {}).get("parts", [])
                                    answer = "\n".join(p.get("text", "") for p in parts if "text" in p)
                                    grounding = candidates[0].get("groundingMetadata", {})
                                    chunks = grounding.get("groundingChunks", [])
                                    for ch in chunks:
                                        web = ch.get("web", {})
                                        uri = web.get("uri")
                                        title = web.get("title", uri)
                                        if uri and uri not in [s.get("url") for s in sources]:
                                            sources.append({"title": title or uri, "url": uri})
                                    call_success = True
                                    break
                        except Exception as ex:
                            last_err = str(ex)
                            time.sleep(0.5)

                    if not call_success and not answer:
                        answer = f"[PROVIDER NOTICE] Gemini API endpoint returned rate limit/status: {last_err}. Context recorded locally."
            except Exception as e:
                status = "PROVIDER_ERROR"
                sanitized_err = self.sanitize_outbound_context(str(e))
                answer = f"[PROVIDER ERROR] Failed to query external search AI provider: {sanitized_err}"
                provenance_label = "EXTERNAL RESEARCH — UNVERIFIED (ERROR)"

        result = {
            "research_id": research_id,
            "session_id": session_id,
            "analyst_question": analyst_question,
            "sanitized_query": sanitized_question,
            "provider": self.provider_name,
            "timestamp": ts_now,
            "answer": answer,
            "sources": sources,
            "status": status,
            "provenance_label": provenance_label,
            "metadata": {
                "cti_context_used": cti_context
            }
        }

        # 4. Store in database
        self.store.save_external_research(result)

        return result
