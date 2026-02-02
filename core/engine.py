# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import concurrent.futures
import time
from typing import List, Dict
from .config import config
from .session import StealthSession
from .fingerprint import Fingerprinter
from .diff import ResponseDiffer
from .detector import Detector
from .payload_manager import PayloadRanker
from .utils import logger
from .classifier import PayloadClassifier
from .context import ContextEngine
from .waf import WAFDetect
from .trace import TraceLogger
from .profiles import get_profile, OperatorProfile
from .passive import PassiveIntel
from .reasoning import ReasoningEngine
from .visualizer import SimpleVisualizer

class Engine:
    def __init__(self, target_url: str, payloads: List[Dict], options: Dict = None):
        self.target_url = target_url
        self.payloads = payloads 
        self.options = options or {}
        
        # Profile Setup
        profile_name = self.options.get("profile", "bounty")
        self.profile = get_profile(profile_name)
        logger.info(f"Loaded Profile: {self.profile.name.upper()} ({self.profile.description})")
        
        # Update config based on profile
        config.min_delay = self.profile.min_delay
        config.max_delay = self.profile.max_delay
        
        # Modules
        self.session = StealthSession()
        self.fingerprinter = Fingerprinter(self.session)
        self.differ = ResponseDiffer()
        self.detector = Detector()
        self.ranker = PayloadRanker()
        self.classifier = PayloadClassifier()
        self.context_engine = ContextEngine()
        self.waf_detector = WAFDetect()
        self.trace = TraceLogger(options.get("output_dir", "reports"))
        
        # v3 Modules
        self.passive_intel = PassiveIntel()
        self.reasoning_engine = ReasoningEngine()
        self.visualizer = SimpleVisualizer(
            mode=self.options.get("visual", "cli"),
            output_dir=self.options.get("output_dir", "reports")
        )
        self.visualizer.profile = self.profile.name
        
        self.results: List[Dict] = []
        self.active_categories = set()
        self.request_count = 0
        self.inferred_chains = []

    def start(self):
        self.visualizer.start()
        
        if self.options.get("dry_run"):
            logger.info("DRY RUN: Logic verified. No requests sent.")
            return

        self.trace.log("START", f"Scan started against {self.target_url}", {"profile": self.profile.name})
        
        # 1. Baseline
        self.baseline = self.fingerprinter.baseline(self.target_url)
        if not self.baseline:
            return

        # === STAGE 0: PASSIVE INTEL ===
        logger.info(">>> Entering STAGE 0: PASSIVE INTEL")
        self.visualizer.update(stage="PASSIVE")
        self.visualizer.print_status()
        
        intel = self.passive_intel.analyze(self.baseline)
        self.trace.log("PASSIVE", "Intel gathered", intel)
        
        # Initial Context (Passive only)
        self.context = self.context_engine.analyze(self.baseline)
        
        if self.options.get("passive_only"):
            logger.info("Passive-only mode enabled. Stopping.")
            return

        # 2. Stage Prep
        staged_payloads = {1: [], 2: [], 3: []}
        for p in self.payloads:
            # GUARDRAIL: Destructive payload check
            if self.classifier.is_destructive(p['payload']):
                # Silently drop or log
                continue
                
            stage = self.classifier.detect_stage(p['payload'], p['category'])
            p['stage'] = stage
            staged_payloads[stage].append(p)

        # === STAGE 1: PROBE ===
        logger.info(">>> Entering STAGE 1: PROBE")
        self.visualizer.update(stage="PROBE")
        # Optimization: Only run probe payloads compatible with current context (weak filter)
        probes = self._filter_by_context(staged_payloads[1])
        self._run_stage(probes, stage_id=1)
        
        # Analyze Decision to continue
        for res in self.results:
            if res.get('diff_score', 0) > 30 and not res.get('blocked'):
                self.trace.log("BRANCH_OPEN", f"Anomaly detected in {res['payload_category']}", res['diff_score'])
                self.active_categories.add(res['payload_category'])
                self.visualizer.update(branch=res['payload_category'])

        if not self.active_categories:
            logger.warning("No anomalies in probes. Aborting to preserve stealth.")
            self.trace.log("ABORT", "Stage 1 yielded no anomalies")
            return

        # === STAGE 2: CONFIRM ===
        logger.info(f">>> Entering STAGE 2: CONFIRM (Vectors: {list(self.active_categories)})")
        self.visualizer.update(stage="CONFIRM")
        self.visualizer.print_status()
        confirm_sets = [p for p in staged_payloads[2] if p['category'] in self.active_categories]
        confirm_sets = self._filter_by_context(confirm_sets)
        
        # Apply Profile Caps per stage
        if len(confirm_sets) > self.profile.max_payloads_per_stage * len(self.active_categories):
            confirm_sets = confirm_sets[:self.profile.max_payloads_per_stage * len(self.active_categories)]
            
        self._run_stage(confirm_sets, stage_id=2)
        
        # Prune branches
        confirmed_cats = set()
        for res in self.results:
            if res['diff_score'] > 50 and res['payload_category'] in self.active_categories:
                confirmed_cats.add(res['payload_category'])
        self.active_categories = confirmed_cats
        
        # === STAGE 3: EXPLOIT (VERIFY) ===
        if self.active_categories:
            logger.info(">>> Entering STAGE 3: VERIFY (Safe Execution)")
            self.visualizer.update(stage="VERIFY")
            self.visualizer.print_status()
            
            verify_sets = [p for p in staged_payloads[3] if p['category'] in self.active_categories]
            verify_sets = self._filter_by_context(verify_sets)
            
            # Strict Cap: 5 verifications per category max (defined in profile usually, enforcing strict here)
            capped = []
            counts = {c: 0 for c in self.active_categories}
            for p in verify_sets:
                if counts[p['category']] < 5:
                    capped.append(p)
                    counts[p['category']] += 1
            
            self._run_stage(capped, stage_id=3)

        # === REASONING ===
        self.inferred_chains = self.reasoning_engine.reason(self.results, self.context)
        
        logger.info("Scan Finished.")

    def _run_stage(self, payloads: List[Dict], stage_id: int):
        if not payloads: return
        
        # Sort by rank
        payloads = self.ranker.rank_payloads(payloads)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_p = {executor.submit(self._test_payload, p): p for p in payloads}
            for future in concurrent.futures.as_completed(future_to_p):
                # Hard Cap Check
                if self.request_count >= self.profile.hard_cap_total_requests:
                    logger.warning("Hard Request Cap Reached. Stopping.")
                    executor.shutdown(wait=False)
                    return

                try:
                    res = future.result()
                    if res:
                        self.results.append(res)
                        self.visualizer.update(request_count=self.request_count)
                        if res.get('findings'):
                             self.visualizer.update(finding=res, branch=res['payload_category'])
                             
                        self.ranker.update_weight(res['payload_category'], res['diff_score'])
                        if res.get('blocked') and self.profile.abort_on_waf:
                            self.visualizer.update(blocked=True)
                            logger.critical("WAF Block detected. Aborting scan based on profile.")
                            self.trace.log("ABORT", "WAF Block detected", res)
                            executor.shutdown(wait=False)
                            return
                except Exception as e:
                    logger.error(f"Err: {e}")
        
        self.visualizer.print_status()

    def _test_payload(self, p: Dict) -> Dict:
        self.request_count += 1
        
        # Basic Injection
        target = self.target_url
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}q={p['payload']}"
        
        resp = self.session.get(url)
        if not resp:
            return {"blocked": True, "diff_score": 0, "payload": p['payload'], "payload_category": p['category']}
            
        diff = self.differ.diff(self.baseline, resp)
        detections = self.detector.scan(resp.text)
        
        return {
            "payload": p['payload'],
            "payload_category": p['category'],
            "diff_score": diff['score'],
            "findings": detections,
            "blocked": False,
            "stage": p.get('stage', 0)
        }
        
    def _filter_by_context(self, payloads):
        # reuse context logic
        filtered = []
        os_win = self.context.os.get("windows", 0)
        os_lin = self.context.os.get("linux", 0)
        for p in payloads:
            text = p['payload'].lower()
            if os_lin > 0.8 and ("win.ini" in text or "windows" in text): continue
            if os_win > 0.8 and ("/etc/passwd" in text): continue
            filtered.append(p)
        return filtered
