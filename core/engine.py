import concurrent.futures
import threading
import urllib.parse
from typing import List, Dict, Optional

from .config import config
from .session import StealthSession
from .fingerprint import Fingerprinter
from .diff import ResponseDiffer
from .detector import Detector
from .payload_manager import PayloadRanker
from .utils import logger, setup_graceful_shutdown, is_shutting_down
from .classifier import PayloadClassifier
from .context import ContextEngine
from .waf import WAFDetect
from .trace import TraceLogger
from .profiles import get_profile
from .passive import PassiveIntel
from .reasoning import ReasoningEngine
from .visualizer import SimpleVisualizer
from .memory import SessionMemory
from .impact import ImpactAnalyzer
from .oob import OOBDetector, OOBConfig
from .time_based import TimeBasedDetector
from .html_analyzer import HTMLAnalyzer
from .mutation_engine import MutationEngine
from .plugin_loader import PluginLoader
from .ai import LLMAnalyzer, AnomalyCluster
from .sarif_reporter import SARIFReporter


class Engine:
    def __init__(self, target_url: str, payloads: List[Dict], options: Dict = None):
        self.target_url = target_url
        self.payloads = payloads
        self.options = options or {}

        profile_name = self.options.get("profile", "bounty")
        self.profile = get_profile(profile_name)
        logger.info(f"Loaded Profile: {self.profile.name.upper()} ({self.profile.description})")

        config.min_delay = self.profile.min_delay
        config.max_delay = self.profile.max_delay

        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        # Core modules
        self.session = StealthSession()
        self.fingerprinter = Fingerprinter(self.session)
        self.differ = ResponseDiffer()
        self.detector = Detector()
        self.ranker = PayloadRanker()
        self.classifier = PayloadClassifier()
        self.context_engine = ContextEngine()
        self.waf_detector = WAFDetect()
        self.trace = TraceLogger(options.get("output_dir", "reports"))
        self.memory = SessionMemory()
        self.impact_analyzer = ImpactAnalyzer()
        self.passive_intel = PassiveIntel()
        self.reasoning_engine = ReasoningEngine()
        self.html_analyzer = HTMLAnalyzer()

        # v4 modules
        self.mutation_engine = MutationEngine(evasion_level=options.get("stealth", "medium"))
        self.plugin_loader = PluginLoader(
            plugin_dirs=options.get("plugin_dirs", ["plugins/detectors", "plugins/reporters", "plugins/hooks"])
        ).discover()
        self.sarif_reporter = SARIFReporter()

        # OOB detection
        self.oob_config = OOBConfig(
            enabled=config.oob.enabled,
            collaborator_url=config.oob.collaborator_url,
        )
        self.oob_detector = OOBDetector(self.oob_config)

        # Time-based detection
        self.time_detector = TimeBasedDetector()

        # AI/ML modules
        ai_enabled = config.ai.enabled and options.get("ai_enabled", True)
        self.llm_analyzer = LLMAnalyzer(
            model=config.ai.model,
            endpoint=config.ai.endpoint,
        ) if ai_enabled else None
        self.cluster_engine = AnomalyCluster() if ai_enabled else None

        # Visualizer
        self.visualizer = SimpleVisualizer(
            mode=self.options.get("visual", "cli"),
            output_dir=self.options.get("output_dir", "reports"),
        )
        self.visualizer.profile = self.profile.name

        self.results: List[Dict] = []
        self.active_categories = set()
        self.request_count = 0
        self.inferred_chains = []

        if options.get("insecure"):
            config.verify_ssl = False

        setup_graceful_shutdown(engine=self)

    def stop(self):
        self._stop_event.set()
        logger.info("Engine stopping...")

    def start(self):
        self.visualizer.start()
        self.oob_detector.start_polling()

        if self.options.get("dry_run"):
            logger.info("DRY RUN: Logic verified. No requests sent.")
            self.visualizer.stop()
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

        # Extract WebSocket endpoints from passive intel
        ws_endpoints = []
        try:
            from .protocols.websocket import WebSocketTester
            ws_tester = WebSocketTester()
            if self.baseline.text:
                ws_endpoints = ws_tester.detect_endpoints(self.baseline.text)
                if ws_endpoints:
                    logger.info(f"Found {len(ws_endpoints)} WebSocket endpoints")
        except Exception:
            pass

        # Detect GraphQL endpoint
        try:
            from .protocols.graphql import GraphQLTester
            gql_tester = GraphQLTester(self.session.session)
            if gql_tester.detect_endpoint(self.target_url):
                logger.info("GraphQL endpoint detected")
                intel["graphql_detected"] = True
        except Exception:
            pass

        self.context = self.context_engine.analyze(self.baseline)

        if self.options.get("passive_only"):
            logger.info("Passive-only mode enabled. Stopping.")
            return

        # Plugin hooks: before_scan
        self.plugin_loader.run_hooks("before_scan", url=self.target_url)

        # 2. Stage Prep + Mutation
        staged_payloads = {1: [], 2: [], 3: []}
        for p in self.payloads:
            if self.classifier.is_destructive(p['payload']):
                continue

            stage = self.classifier.detect_stage(p['payload'], p['category'])
            p['stage'] = stage
            staged_payloads[stage].append(p)

            # Generate mutations for high-evasion scenarios
            if self.options.get("stealth", "medium") == "high":
                mutated = self.mutation_engine.mutate(p['payload'], p['category'])
                for variant in mutated[1:]:  # skip original
                    variant_p = {
                        "payload": variant["payload"],
                        "category": p['category'],
                        "source_file": p.get("source_file", "mutated"),
                        "stage": stage,
                        "technique": variant.get("technique", "mutated"),
                    }
                    staged_payloads[stage].append(variant_p)

        # === STAGE 1: PROBE ===
        logger.info(">>> Entering STAGE 1: PROBE")
        self.visualizer.update(stage="PROBE")
        probes = self._filter_by_context(staged_payloads[1])
        self._run_stage(probes, stage_id=1)

        for res in self.results:
            if res.get('diff_score', 0) > config.probe_anomaly_threshold and not res.get('blocked'):
                self.trace.log("BRANCH_OPEN", f"Anomaly in {res['payload_category']}", res['diff_score'])
                self.active_categories.add(res['payload_category'])
                self.visualizer.update(branch=res['payload_category'])

        if not self.active_categories:
            logger.warning("No anomalies in probes. Aborting to preserve stealth.")
            self.trace.log("ABORT", "Stage 1 yielded no anomalies")
            self.plugin_loader.run_hooks("after_scan", results=self.results, url=self.target_url)
            return

        # === STAGE 2: CONFIRM ===
        logger.info(f">>> Entering STAGE 2: CONFIRM (Vectors: {list(self.active_categories)})")
        self.visualizer.update(stage="CONFIRM")
        self.visualizer.print_status()
        confirm_sets = [p for p in staged_payloads[2] if p['category'] in self.active_categories]
        confirm_sets = self._filter_by_context(confirm_sets)

        if len(confirm_sets) > self.profile.max_payloads_per_stage * len(self.active_categories):
            confirm_sets = confirm_sets[:self.profile.max_payloads_per_stage * len(self.active_categories)]

        self._run_stage(confirm_sets, stage_id=2)

        confirmed_cats = set()
        for res in self.results:
            if res['diff_score'] > config.confirm_anomaly_threshold and res['payload_category'] in self.active_categories:
                confirmed_cats.add(res['payload_category'])
        self.active_categories = confirmed_cats

        # === STAGE 3: VERIFY ===
        if self.active_categories:
            logger.info(">>> Entering STAGE 3: VERIFY (Safe Execution)")
            self.visualizer.update(stage="VERIFY")
            self.visualizer.print_status()

            verify_sets = [p for p in staged_payloads[3] if p['category'] in self.active_categories]
            verify_sets = self._filter_by_context(verify_sets)

            capped = []
            counts = {c: 0 for c in self.active_categories}
            for p in verify_sets:
                if counts[p['category']] < config.max_verify_per_category:
                    capped.append(p)
                    counts[p['category']] += 1

            self._run_stage(capped, stage_id=3)

        # === OOB DETECTION (blind XXE/SSRF/RCE) ===
        if config.oob.enabled:
            logger.info(">>> Running OOB detection")
            for category in self.active_categories:
                if f"{category}_OOB" in OOBDetector.OOB_PAYLOADS:
                    oob_payloads = self.oob_detector.build_payload(
                        f"{category}_OOB",
                        config.oob.collaborator_url or "oob.hunterx.local",
                    )
                    for payload in oob_payloads:
                        parsed = urllib.parse.urlparse(self.target_url)
                        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        query_params['q'] = payload
                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                        url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                        try:
                            self.session.get(url)
                        except Exception:
                            pass

        # === TIME-BASED DETECTION ===
        if self.options.get("time_based", True) and self.active_categories:
            logger.info(">>> Running time-based detection")
            parsed = urllib.parse.urlparse(self.target_url)
            base_query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for cat in self.active_categories:
                timed_results = self.time_detector.scan(cat, self.target_url, self.session)
                for tr in timed_results:
                    self.results.append({
                        "payload": tr["payload"],
                        "payload_category": f"{cat}_TIME",
                        "diff_score": int(tr["confidence"] * 100),
                        "findings": [f"Time-based injection detected ({tr['actual_delay']}s)"],
                        "blocked": False,
                        "stage": 3,
                    })

        # === HTML DOM ANALYSIS ===
        logger.info(">>> Running HTML DOM analysis")
        for res in self.results:
            if res.get("response_text"):
                dom_findings = self.html_analyzer.analyze_structure(
                    self.baseline.text if hasattr(self, "baseline") else "",
                    res.get("response_text", ""),
                )
                if dom_findings:
                    res.setdefault("findings", []).extend(
                        [f"DOM: {d['detail']}" for d in dom_findings]
                    )

        # === PLUGIN DETECTORS ===
        plugin_detectors = self.plugin_loader.get_detectors()
        if plugin_detectors:
            logger.info(f"Running {len(plugin_detectors)} plugin detectors")
            for name, detector in plugin_detectors.items():
                try:
                    for res in self.results:
                        if hasattr(detector, "analyze"):
                            extra = detector.analyze(res)
                            if extra:
                                res.setdefault("findings", []).extend(extra)
                except Exception as e:
                    logger.debug(f"Plugin detector {name} failed: {e}")

        # === REASONING ===
        self.inferred_chains = self.reasoning_engine.reason(self.results, self.context)

        # === IMPACT ANALYSIS ===
        for res in self.results:
            impact = self.impact_analyzer.analyze(res, self.context)
            res['impact'] = impact

        # === AI/ML ANALYSIS ===
        if self.llm_analyzer and self.results:
            logger.info("Running LLM analysis on findings...")
            self.results = self.llm_analyzer.batch_analyze(self.results, {
                "target": self.target_url,
                "os": self.context.get_likely_os() if hasattr(self.context, "get_likely_os") else "unknown",
            })

        if self.cluster_engine and len(self.results) > 1:
            logger.info("Clustering findings...")
            clusters = self.cluster_engine.cluster(self.results)
            logger.info(f"Reduced {len(self.results)} findings to {len(clusters)} clusters")

        # === SARIF REPORT ===
        try:
            sarif_path = f"{self.options.get('output_dir', 'reports')}/hunterx_results.sarif"
            self.sarif_reporter.save(self.results, self.target_url, sarif_path)
            logger.info(f"SARIF report saved to {sarif_path}")
        except Exception as e:
            logger.debug(f"SARIF generation failed: {e}")

        # === PLUGIN HOOKS: after_scan ===
        self.plugin_loader.run_hooks("after_scan", results=self.results, url=self.target_url)

        self.visualizer.stop()
        logger.info("Scan Finished.")

    def _run_stage(self, payloads: List[Dict], stage_id: int):
        if not payloads:
            return

        payloads = self.ranker.rank_payloads(payloads)

        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_p = {}
            for p in payloads:
                if self._stop_event.is_set() or is_shutting_down():
                    break
                future_to_p[executor.submit(self._test_payload, p)] = p

            for future in concurrent.futures.as_completed(future_to_p):
                if self._stop_event.is_set() or is_shutting_down():
                    for f in future_to_p:
                        f.cancel()
                    executor.shutdown(wait=False)
                    return

                with self._lock:
                    if self.request_count >= self.profile.hard_cap_total_requests:
                        logger.warning("Hard Request Cap Reached. Stopping.")
                        for f in future_to_p:
                            f.cancel()
                        executor.shutdown(wait=False)
                        return

                try:
                    res = future.result()
                    if res:
                        with self._lock:
                            self.results.append(res)
                        self.visualizer.update(request_count=self.request_count)
                        if res.get('findings'):
                            self.visualizer.update(finding=res, branch=res['payload_category'])

                        self.ranker.update_weight(res['payload_category'], res['diff_score'])
                        if res.get('blocked') and self.profile.abort_on_waf:
                            self.visualizer.update(blocked=True)
                            logger.critical("WAF Block detected. Aborting.")
                            self.trace.log("ABORT", "WAF Block detected", res)
                            self._stop_event.set()
                            for f in future_to_p:
                                f.cancel()
                            executor.shutdown(wait=False)
                            return
                except Exception as e:
                    logger.error(f"Err: {e}")

        self.visualizer.print_status()

    def _test_payload(self, p: Dict) -> Optional[Dict]:
        with self._lock:
            self.request_count += 1

        if self.memory.should_skip(p['payload'], p['category']):
            return None

        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query_params['q'] = p['payload']
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            resp = self.session.get(url)
        except Exception:
            self.memory.record_failure(p['category'])
            return {"blocked": True, "diff_score": 0, "payload": p['payload'], "payload_category": p['category']}

        if resp is None:
            self.memory.record_failure(p['category'])
            return {"blocked": True, "diff_score": 0, "payload": p['payload'], "payload_category": p['category']}

        diff = self.differ.diff(self.baseline, resp)
        detections = self.detector.scan(resp.text)
        header_detections = self.detector.scan_headers(dict(resp.headers))
        heuristic = self.detector.check_heuristics(
            self.baseline.text if hasattr(self, "baseline") else "",
            resp.text,
            p['payload'],
        )

        all_findings = detections + header_detections + heuristic

        return {
            "payload": p['payload'],
            "payload_category": p['category'],
            "diff_score": diff['score'],
            "findings": all_findings,
            "blocked": False,
            "stage": p.get('stage', 0),
            "response_text": resp.text[:5000],
            "technique": p.get('technique', 'original'),
            "source_file": p.get('source_file', ''),
        }

    def _filter_by_context(self, payloads):
        if not hasattr(self, 'context') or self.context is None:
            return payloads
        filtered = []
        os_win = self.context.os.get("windows", 0)
        os_lin = self.context.os.get("linux", 0)
        for p in payloads:
            text = p['payload'].lower()
            if os_lin >= 0.8 and ("win.ini" in text or "windows" in text):
                continue
            if os_win >= 0.8 and ("/etc/passwd" in text):
                continue
            filtered.append(p)
        return filtered
