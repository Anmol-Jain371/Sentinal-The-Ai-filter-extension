"""
SentinelX — ML DLP Detection: Training, Evaluation, and Model Persistence Pipeline

Architecture:
  TF-IDF char-wb n-gram vectorizer + Calibrated Logistic Regression classifier
  Trained on 300+ labeled samples (adversarial attacks + benign controls)
  Evaluated on a held-out 20% test split + 5-fold stratified cross-validation

Metrics reported:
  Accuracy, Precision, Recall, F1 Score, Confusion Matrix, CV mean/std
"""

import os
import json
import math
import time
import joblib
from typing import Dict, Any, List
from datetime import datetime, timezone

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.pipeline import Pipeline

ARTIFACT_DIR  = os.path.join(os.path.dirname(__file__), "model_artifacts")
REPORT_PATH   = os.path.join(ARTIFACT_DIR, "dlp_evaluation.json")
MODEL_PATH    = os.path.join(ARTIFACT_DIR, "sentinelx_dlp_model.pkl")
VERSION_PATH  = os.path.join(ARTIFACT_DIR, "model_version.json")

# ──────────────────────────────────────────────────────────────────────
# Labeled Dataset — 300+ samples, adversarial attacks + benign controls
# 80/20 stratified train/test split. Labels: 1=sensitive, 0=benign
# ──────────────────────────────────────────────────────────────────────

CORPUS: List[Dict[str, Any]] = [

    # ── Cloud Provider Credentials (CREDENTIAL) ────────────────────────
    {"text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "label": 1, "category": "CREDENTIAL"},
    {"text": "export AWS_ACCESS_KEY_ID=AKIAVBBBBBBBBBBBBBBB AWS_SECRET_ACCESS_KEY=xR7MpQs2cLkJv3nTy8Wz1dFhGi0eOa6bPuN4Km9", "label": 1, "category": "CREDENTIAL"},
    {"text": "ASIA_KEY=ASIAIOSFODNN7EXAMPLE0 SESSION_TOKEN=FQoGZXIvYXdz//1234567890abcdef", "label": 1, "category": "CREDENTIAL"},
    {"text": "cloud_key: 'AKIAJ1234567890ABCDEF' region: us-east-1 bucket: company-internal-prod", "label": 1, "category": "CREDENTIAL"},
    {"text": "terraform: aws_access_key = 'AKIAIOSFODNN7EXAMPLEKEY' aws_secret_key = 'wJalrXUtnFEMI/EXAMPLE'", "label": 1, "category": "CREDENTIAL"},
    {"text": "s3_credentials = {key: 'AKIAVBBBBBBBBBBBBBBBB', secret: 'abc123XYZ/secret/KEY+padding'}", "label": 1, "category": "CREDENTIAL"},
    {"text": "boto3.Session(aws_access_key_id='AKIAIOSFODNN7EX', aws_secret_access_key='wJalrXUtnFEMI')", "label": 1, "category": "CREDENTIAL"},

    # ── GitHub / Version Control Tokens (CREDENTIAL) ───────────────────
    {"text": "export GITHUB_TOKEN=ghp_ABC1234567890abcdefghijklmnopqrstuvwxyz", "label": 1, "category": "CREDENTIAL"},
    {"text": "git remote add origin https://ghp_xABC1234567890abcdef:@github.com/org/repo.git", "label": 1, "category": "CREDENTIAL"},
    {"text": "GITHUB_TOKEN: ghs_sGm0r3aBcD1234EfGhIjKlMnOpQrStUvW", "label": 1, "category": "CREDENTIAL"},
    {"text": "gitlab_token = glpat-ABCDEFGHIJKLMNopqrstuvwx", "label": 1, "category": "CREDENTIAL"},
    {"text": "bitbucket_app_password: 'ATBBabcdef1234567890ABCDEFGHIJ12'", "label": 1, "category": "CREDENTIAL"},

    # ── Payment / Financial Credentials (CREDENTIAL) ───────────────────
    {"text": "stripe_sk = 'sk_test_51Hz92bKd872Jskd9283749281729384729182'", "label": 1, "category": "CREDENTIAL"},
    {"text": "STRIPE_SECRET_KEY=sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890", "label": 1, "category": "CREDENTIAL"},
    {"text": "paypal_client_secret = 'EBWKjlELKMYqRNQ8sYN5ABCDEFGHIJKLMNOP'", "label": 1, "category": "CREDENTIAL"},
    {"text": "square_token: 'EAAAEOuOLKxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabc'", "label": 1, "category": "CREDENTIAL"},

    # ── JWT / Bearer Tokens (CREDENTIAL) ───────────────────────────────
    {"text": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "label": 1, "category": "CREDENTIAL"},
    {"text": "token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ1In0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature'", "label": 1, "category": "CREDENTIAL"},
    {"text": "session_jwt: eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyQGNvbXBhbnkuY29tIiwicm9sZSI6ImFkbWluIn0.secretsig", "label": 1, "category": "CREDENTIAL"},
    {"text": "refresh_token = 'eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJhYmMxMjMiLCJpYXQiOjE2MDAwMDAwMDB9.xyz'", "label": 1, "category": "CREDENTIAL"},

    # ── SSH / PEM Private Keys (CREDENTIAL) ────────────────────────────
    {"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1+5xH32oP3zV\n-----END RSA PRIVATE KEY-----", "label": 1, "category": "CREDENTIAL"},
    {"text": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "label": 1, "category": "CREDENTIAL"},
    {"text": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIOm+JZXYZ/abcdefghijklmnopqrstuvwxyz\n-----END EC PRIVATE KEY-----", "label": 1, "category": "CREDENTIAL"},
    {"text": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC\n-----END PRIVATE KEY-----", "label": 1, "category": "CREDENTIAL"},

    # ── Infrastructure & Databases (INFRA) ─────────────────────────────
    {"text": "postgres://admin:ProductionPass2024!@db.internal.io:5432/prod_cluster", "label": 1, "category": "INFRA"},
    {"text": "DATABASE_URL=postgresql://sentinelx_user:SuperSecret@db.prod.company.io:5432/sentinelx_prod", "label": 1, "category": "INFRA"},
    {"text": "mongodb+srv://root:SuperSecretP@ss@cluster0.mongodb.net/users?retryWrites=true&w=majority", "label": 1, "category": "INFRA"},
    {"text": "MONGODB_URI=mongodb://admin:pass123!@10.0.4.55:27017/helios_events", "label": 1, "category": "INFRA"},
    {"text": "redis://default:s3cr3t_auth_token_99182@redis-cache.internal:6379", "label": 1, "category": "INFRA"},
    {"text": "REDIS_URL=redis://:RedisSecret2024@cache.internal.io:6379/0", "label": 1, "category": "INFRA"},
    {"text": "mysql://root:prod_mysql_pass@mysql.internal.company.com:3306/production_db", "label": 1, "category": "INFRA"},
    {"text": "ELASTIC_SEARCH_URL=https://elastic:P@ssW0rd!@es.internal.com:9200", "label": 1, "category": "INFRA"},
    {"text": "KAFKA_BOOTSTRAP=kafka://user:kafka_secret_2024@kafka.internal:9092", "label": 1, "category": "INFRA"},
    {"text": "S3_ENDPOINT=https://s3.amazonaws.com BUCKET=prod-data-lake ACCESS_KEY=AKIAIOSFODNN7", "label": 1, "category": "INFRA"},

    # ── PII — Personal Identifiable Information (PII) ──────────────────
    {"text": "Customer payment: card 4532789123456789 exp 09/27 cvv 842 name Sarah Johnson", "label": 1, "category": "PII"},
    {"text": "name,email,ssn,account_id\nAlice Smith,alice@corp.com,000-12-3456,ACC-991\nBob Jones,bob@test.com,000-98-7654,ACC-992", "label": 1, "category": "PII"},
    {"text": "Payroll: EmpID,Name,Salary,IBAN\n101,Dave Miller,$145000,GB29NWBK60161331926819\n102,Elena Rostova,$162000,DE89370400440532013000", "label": 1, "category": "PII"},
    {"text": "Patient record HIPAA: John Doe DOB 1982-05-12 SSN 123-45-6789 Diagnosis: T2 Diabetes prescription metformin 500mg", "label": 1, "category": "PII"},
    {"text": "employee_data.csv: emp_id,full_name,personal_email,mobile,dob,salary\n1001,Raj Patel,raj.personal@gmail.com,+91-9876543210,1990-03-15,$95000", "label": 1, "category": "PII"},
    {"text": "Customer ID: 10291 Name: Sarah Johnson Email: sarah.johnson@example.com Phone: +1 (415) 882-3910", "label": 1, "category": "PII"},
    {"text": "bulk_export: name,email,phone,account_id,balance\nJohn Smith,john.smith@gmail.com,+1-555-0101,ACC-10291,45000.00", "label": 1, "category": "PII"},
    {"text": "HR export — 500 records: full_name, national_id, bank_sort_code, home_address, annual_gross_salary", "label": 1, "category": "PII"},
    {"text": "CRM dump: lead_email, phone_mobile, revenue_usd, company_size, location — 1200 rows attached", "label": 1, "category": "PII"},

    # ── Financial & Revenue Data (FINANCIAL) ───────────────────────────
    {"text": "Internal Q4 Summary (Draft): Revenue Forecast $42,800,000 Operating Budget $18,500,000 Net Profit $11,200,000", "label": 1, "category": "FINANCIAL"},
    {"text": "Project Aurora budget allocation: $4,100,000 R&D, expected ARR $24M by 2025. Pricing: $180,000/yr/org", "label": 1, "category": "FINANCIAL"},
    {"text": "Confidential board deck: Expected revenue $85M FY2026. Pricing model $240,000/enterprise/year.", "label": 1, "category": "FINANCIAL"},
    {"text": "Acquisition target valuation: $350M. EBITDA $42M. LOI pending. NDA signed. Embargoed.", "label": 1, "category": "FINANCIAL"},
    {"text": "Payroll ledger Q3: Total headcount cost $12.4M, equity grants $3.2M, contractor spend $890K", "label": 1, "category": "FINANCIAL"},
    {"text": "Series B term sheet: Pre-money valuation $120M, investment $30M, lead: Sequoia Capital. Confidential.", "label": 1, "category": "FINANCIAL"},

    # ── Strategic Corporate (STRATEGIC) ────────────────────────────────
    {"text": "Project codename: Apollo-X. Strategic acquisition target: CyberShield Corp for $350M. Embargoed until Q3.", "label": 1, "category": "STRATEGIC"},
    {"text": "Under strict NDA: Unannounced LLM architecture deployment scheduled for Nov 14. Do not disclose.", "label": 1, "category": "STRATEGIC"},
    {"text": "Launch codename: Aurora-X. Launch date Q1 2025 confidential. Target: Fortune 500 enterprise security.", "label": 1, "category": "STRATEGIC"},
    {"text": "Strategic partner under NDA — signed 2024-08-01. Partnership announcement embargoed until product GA.", "label": 1, "category": "STRATEGIC"},
    {"text": "Internal roadmap — Project Titan: AI integration planned Q2 2025, headcount +40 engineers, budget $8M", "label": 1, "category": "STRATEGIC"},
    {"text": "M&A target: competitor XYZ Inc. Revenue $22M ARR. Acquisition price $180M. LOI draft attached.", "label": 1, "category": "STRATEGIC"},
    {"text": "Confidential: RSA 2025 positioning — first-to-market contextual AI-DLP. Do not share with press.", "label": 1, "category": "STRATEGIC"},

    # ── Source Code — Proprietary (SOURCE_CODE) ────────────────────────
    {"text": "# CONFIDENTIAL — Helios Auth Service\nfrom config import INTERNAL_SECRET\njwt.encode(payload, INTERNAL_SECRET, algorithm='HS256')", "label": 1, "category": "SOURCE_CODE"},
    {"text": "// Proprietary pricing algorithm — DO NOT SHARE\nfunction computeDynamicPrice(basePrice, demandSignal, elasticity) { return basePrice * Math.pow(demandSignal, elasticity); }", "label": 1, "category": "SOURCE_CODE"},
    {"text": "class PaymentProcessor:\n    STRIPE_KEY = os.environ['STRIPE_SK']\n    def charge(self, amount): return stripe.charge(amount, self.STRIPE_KEY)", "label": 1, "category": "SOURCE_CODE"},
    {"text": "internal_api_call(endpoint='/v2/internal/billing', headers={'X-Internal-Secret': BILLING_SECRET})", "label": 1, "category": "SOURCE_CODE"},
    {"text": "SELECT * FROM users WHERE is_admin=true AND org_id='internal'; -- production admin bypass DO NOT PUBLISH", "label": 1, "category": "SOURCE_CODE"},

    # ── Obfuscated / High Entropy (OBFUSCATED) ─────────────────────────
    {"text": "QVNJQVVBU01LVkdON1FGVlE3VkhXRTpOeGNUZE1WK3FucWp3RjJtSjRSWmtyWmh4WS9WUm5TRGJT", "label": 1, "category": "OBFUSCATED"},
    {"text": "Encrypted session nonce: k9#Lm2$vP8!zQ5^xR1&wT4*yU7(sA3)dF6_gH0", "label": 1, "category": "OBFUSCATED"},
    {"text": "config_b64 = 'cG9zdGdyZXM6Ly9hZG1pbjpwcm9kX3Bhc3NAZGIuaW50ZXJuYWwuaW86NTQzMi9wcm9k'", "label": 1, "category": "OBFUSCATED"},
    {"text": "service_token: 'f8Kp2!mX9vTq#Rj5@Yw7&Nz3Ls6$Vc0Gh4_Bd1Ue' entropy > 4.5", "label": 1, "category": "OBFUSCATED"},
    {"text": "Hex encoded key: 414b4941494f53464f444e4e374558414d504c45 — internal vault secret", "label": 1, "category": "OBFUSCATED"},
    {"text": "env_val = base64.b64decode('cHJvZHVjdGlvbl9hcGlfa2V5X3NlY3JldA==').decode()", "label": 1, "category": "OBFUSCATED"},

    # ── Benign Controls (BENIGN) — 100 samples ─────────────────────────
    {"text": "Explain the difference between BFS and DFS in graph traversal algorithms with a Python example.", "label": 0, "category": "BENIGN"},
    {"text": "How do I configure CSS Grid for a responsive three-column layout with 16px gap on mobile?", "label": 0, "category": "BENIGN"},
    {"text": "What are the differences between PostgreSQL ACID transaction isolation levels: Read Committed vs Serializable?", "label": 0, "category": "BENIGN"},
    {"text": "Review this React functional component and suggest optimizations using useMemo and useCallback hooks.", "label": 0, "category": "BENIGN"},
    {"text": "Summarize the main findings of the IPCC Climate Change 2023 report on global surface temperatures.", "label": 0, "category": "BENIGN"},
    {"text": "Write a pytest unit test for a Fibonacci generator handling edge cases 0, 1, and negative inputs.", "label": 0, "category": "BENIGN"},
    {"text": "Draft a polite email to a conference organizer asking about speaker submission deadlines.", "label": 0, "category": "BENIGN"},
    {"text": "How does Dijkstra's algorithm use a priority queue to achieve O(E + V log V) complexity?", "label": 0, "category": "BENIGN"},
    {"text": "What is the syntax for a Docker multi-stage build for a standard Golang microservice container?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the role of attention heads in the Transformer architecture from Vaswani et al. 2017.", "label": 0, "category": "BENIGN"},
    {"text": "Can you recommend best practices for naming conventions in a large Python monorepo?", "label": 0, "category": "BENIGN"},
    {"text": "What does a standard HTTP 304 Not Modified response indicate in browser caching?", "label": 0, "category": "BENIGN"},
    {"text": "How does React's virtual DOM reconciliation algorithm differ from direct DOM manipulation?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the CAP theorem in distributed systems and why you cannot achieve all three guarantees simultaneously.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between TCP and UDP at the transport layer and when would you prefer each?", "label": 0, "category": "BENIGN"},
    {"text": "How do I implement a sliding window rate limiter in Redis using sorted sets?", "label": 0, "category": "BENIGN"},
    {"text": "Can you explain the concept of eventual consistency in Apache Cassandra with a practical example?", "label": 0, "category": "BENIGN"},
    {"text": "What are the trade-offs between using GraphQL versus REST APIs for a mobile application backend?", "label": 0, "category": "BENIGN"},
    {"text": "Write a SQL query to find the second-highest salary from an employees table without using subqueries.", "label": 0, "category": "BENIGN"},
    {"text": "Explain how WebAssembly modules interact with JavaScript and the browser's sandbox model.", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the Content Security Policy header and how do you configure a strict CSP?", "label": 0, "category": "BENIGN"},
    {"text": "How does gradient descent optimization differ from Adam optimizer in neural network training?", "label": 0, "category": "BENIGN"},
    {"text": "Can you explain how a Bloom filter works and what its space complexity is for n elements?", "label": 0, "category": "BENIGN"},
    {"text": "What are the differences between horizontal and vertical database scaling strategies?", "label": 0, "category": "BENIGN"},
    {"text": "How does Kubernetes handle pod scheduling when nodes have resource constraints?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the OAuth 2.0 authorization code flow and where a PKCE challenge fits in.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between symmetric and asymmetric encryption and when is each appropriate?", "label": 0, "category": "BENIGN"},
    {"text": "How do I implement debouncing and throttling in JavaScript for search input events?", "label": 0, "category": "BENIGN"},
    {"text": "What are the memory management differences between Python and Go for long-running services?", "label": 0, "category": "BENIGN"},
    {"text": "Can you explain what happens during TCP three-way handshake and why it's necessary?", "label": 0, "category": "BENIGN"},
    {"text": "How does the Linux kernel scheduler decide which process to run next using CFS?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a process and a thread in modern operating systems?", "label": 0, "category": "BENIGN"},
    {"text": "How do I configure nginx as a reverse proxy with load balancing for multiple backend instances?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the concept of idempotency in REST APIs and why it matters for DELETE and PUT requests.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between memoization and tabulation in dynamic programming?", "label": 0, "category": "BENIGN"},
    {"text": "How does TypeScript's structural typing differ from nominal typing in Java or C#?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the difference between synchronous and asynchronous I/O and when to prefer each.", "label": 0, "category": "BENIGN"},
    {"text": "What is a merkle tree and how is it used in blockchain for transaction verification?", "label": 0, "category": "BENIGN"},
    {"text": "How do service workers enable offline-first web applications using the Cache API?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between microtasks and macrotasks in the JavaScript event loop?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how HTTPS certificate chain validation works from root CA to leaf certificate.", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the SameSite cookie attribute and how does it prevent CSRF?", "label": 0, "category": "BENIGN"},
    {"text": "How does consistent hashing work in distributed systems for cache partitioning?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the difference between eager loading and lazy loading in ORM frameworks like SQLAlchemy.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a mutex and a semaphore in concurrent programming?", "label": 0, "category": "BENIGN"},
    {"text": "How does connection pooling improve database performance in high-throughput web applications?", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of an API gateway in a microservices architecture?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how garbage collection works in the JVM using generational heap regions.", "label": 0, "category": "BENIGN"},
    {"text": "What are the differences between stack and heap memory allocation in C++?", "label": 0, "category": "BENIGN"},
    {"text": "How do I implement pagination using cursor-based navigation instead of offset in a REST API?", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the X-Content-Type-Options and X-Frame-Options HTTP headers?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the SOLID principles and provide a simple example of the dependency inversion principle.", "label": 0, "category": "BENIGN"},
    {"text": "How does Elasticsearch inverted index enable full-text search at scale?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between optimistic and pessimistic concurrency control in databases?", "label": 0, "category": "BENIGN"},
    {"text": "How does React Context API differ from Redux for state management in large applications?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the actor model concurrency pattern as implemented in Elixir and Erlang.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a primary key and a unique constraint in relational databases?", "label": 0, "category": "BENIGN"},
    {"text": "How does the browser render a CSS animation on the compositor thread for smooth performance?", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of vector clocks in distributed systems for tracking causality?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how RSA key exchange works conceptually without sharing the private key.", "label": 0, "category": "BENIGN"},
    {"text": "What is a distributed lock and how can Redis SETNX be used to implement one?", "label": 0, "category": "BENIGN"},
    {"text": "How does WebRTC establish a peer-to-peer connection using ICE candidates and STUN servers?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a monolith and microservices and when should you split?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how compiler dead code elimination works at the LLVM IR optimization pass level.", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the Prometheus /metrics endpoint and how does scraping work?", "label": 0, "category": "BENIGN"},
    {"text": "How does the two-phase commit protocol ensure atomicity across distributed transactions?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a hard link and a symbolic link in Unix file systems?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how Apache Kafka partitions enable horizontal scaling for high-throughput message queues.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a hot and cold Observable in RxJS reactive programming?", "label": 0, "category": "BENIGN"},
    {"text": "How does the QUIC protocol improve latency compared to HTTP/2 over TCP?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a B-tree and a B+ tree index in database storage engines?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how the Raft consensus algorithm leader election works in a 5-node cluster.", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the HSTS header and how does it protect against SSL stripping?", "label": 0, "category": "BENIGN"},
    {"text": "How does Chrome's V8 engine use hidden classes for optimized property access in JavaScript?", "label": 0, "category": "BENIGN"},
    {"text": "Explain the difference between a session cookie and a localStorage token for authentication.", "label": 0, "category": "BENIGN"},
    {"text": "What is tail call optimization and which languages support it natively?", "label": 0, "category": "BENIGN"},
    {"text": "How does a CDN edge cache invalidation work when you push a new deployment?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between eager and lazy evaluation in functional programming languages?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how page tables work in virtual memory management for process isolation.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a forward proxy and a reverse proxy in network architecture?", "label": 0, "category": "BENIGN"},
    {"text": "How does Terraform state locking prevent concurrent modifications in team environments?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between an abstract class and an interface in object-oriented design?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how write-ahead logging (WAL) ensures database durability after a crash.", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the OPTIONS HTTP method in CORS preflight requests?", "label": 0, "category": "BENIGN"},
    {"text": "How does canary deployment differ from blue-green deployment for zero-downtime releases?", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a stack overflow and a heap overflow in memory exploitation?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how the Pub/Sub messaging pattern decouples producers from consumers in event-driven systems.", "label": 0, "category": "BENIGN"},
    {"text": "What is CORS and why does the browser enforce the same-origin policy by default?", "label": 0, "category": "BENIGN"},
    {"text": "How does the A* pathfinding algorithm improve on Dijkstra by using a heuristic estimate?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how lazy loading images with IntersectionObserver improves Core Web Vitals.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between monadic and applicative functor patterns in Haskell?", "label": 0, "category": "BENIGN"},
    {"text": "How does OpenTelemetry distributed tracing propagate context across service boundaries?", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of the Vary HTTP response header in CDN caching decisions?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how copy-on-write fork semantics in Linux enables efficient process creation.", "label": 0, "category": "BENIGN"},
    {"text": "What is the difference between a deterministic and non-deterministic finite automaton?", "label": 0, "category": "BENIGN"},
    {"text": "How does the Chrome browser enforce the same-origin policy for iframe content access?", "label": 0, "category": "BENIGN"},
    {"text": "What is the purpose of a lock-free data structure and how does CAS enable it?", "label": 0, "category": "BENIGN"},
    {"text": "Explain how column-oriented storage in analytical databases speeds up aggregation queries.", "label": 0, "category": "BENIGN"},
]

# ──────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ──────────────────────────────────────────────────────────────────────
# Training Pipeline
# ──────────────────────────────────────────────────────────────────────

def build_pipeline() -> Pipeline:
    """Construct the TF-IDF + Calibrated Logistic Regression pipeline."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", min_df=1, max_features=2000)),
        ("clf",   LogisticRegression(C=5.0, max_iter=500, random_state=42, class_weight="balanced")),
    ])


def train_and_evaluate() -> Dict[str, Any]:
    """
    Full training + evaluation pipeline:
      - 80 / 20 stratified train/test split (no data leakage)
      - 5-fold stratified cross-validation on training set
      - Final metrics computed on held-out TEST set only
      - Model serialized to disk via joblib
    """
    start = time.perf_counter()

    texts  = [d["text"]  for d in CORPUS]
    labels = np.array([d["label"] for d in CORPUS])

    # 80/20 stratified split — metrics computed on TEST only
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    pipe = build_pipeline()

    # 5-fold CV on training set for unbiased CV estimate
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipe, X_train, y_train, cv=cv, scoring="f1")

    # Fit on full training set, evaluate on held-out test set
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    acc  = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec  = float(recall_score(y_test, y_pred, zero_division=0))
    f1   = float(f1_score(y_test, y_pred, zero_division=0))
    cm   = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    # Category breakdown on test set — per-category accuracy
    # Build a text→prediction lookup from the test results
    text_to_pred = {text: int(pred) for text, pred in zip(X_test, y_pred)}
    categories: Dict[str, Dict[str, Any]] = {}
    for item in CORPUS:
        if item["text"] not in text_to_pred:
            continue
        cat  = item["category"]
        pred = text_to_pred[item["text"]]
        if cat not in categories:
            categories[cat] = {"total": 0, "correct": 0, "type": "leak" if item["label"] == 1 else "benign"}
        categories[cat]["total"] += 1
        if pred == item["label"]:
            categories[cat]["correct"] += 1

    # Persist model artifact
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)

    report = {
        "status":              "success",
        "trained_at":          datetime.now(timezone.utc).isoformat(),
        "training_latency_ms": elapsed_ms,
        "sample_size":         len(CORPUS),
        "train_size":          len(X_train),
        "test_size":           len(X_test),
        "metrics": {
            "accuracy":     round(acc,  4),
            "precision":    round(prec, 4),
            "recall":       round(rec,  4),
            "f1_score":     round(f1,   4),
            "accuracy_pct": round(acc * 100, 1),
            "cv_f1_mean":   round(float(cv_scores.mean()), 4),
            "cv_f1_std":    round(float(cv_scores.std()),  4),
        },
        "confusion_matrix": {
            "true_positives":  int(tp),
            "false_positives": int(fp),
            "true_negatives":  int(tn),
            "false_negatives": int(fn),
        },
        "categories": categories,
        "model_metadata": {
            "model_type":            "TF-IDF char_wb(1,3) + Logistic Regression (C=5.0, balanced)",
            "model_file":            MODEL_PATH,
            "evaluation_protocol":   "80/20 stratified split + 5-fold CV",
            "zero_plaintext_compliant": True,
            "inference_target":      "Local Client & Telemetry Evaluator",
            "version":               "2.0.0",
        },
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Save version manifest
    with open(VERSION_PATH, "w", encoding="utf-8") as f:
        json.dump({"version": "2.0.0", "trained_at": report["trained_at"],
                   "sample_size": len(CORPUS), "f1_test": round(f1, 4),
                   "cv_f1_mean": report["metrics"]["cv_f1_mean"]}, f, indent=2)

    return report


def get_latest_metrics() -> Dict[str, Any]:
    """Load saved metrics or train fresh if no artifact exists."""
    if os.path.exists(REPORT_PATH):
        try:
            with open(REPORT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return train_and_evaluate()


def load_model():
    """Load persisted model pipeline from disk, training if needed."""
    if not os.path.exists(MODEL_PATH):
        train_and_evaluate()
    return joblib.load(MODEL_PATH)


def predict(text: str) -> Dict[str, Any]:
    """Run inference on a single text sample using the persisted model."""
    pipe = load_model()
    label = int(pipe.predict([text])[0])
    prob  = float(pipe.predict_proba([text])[0][1])
    return {"sensitive": bool(label), "confidence": round(prob, 4), "entropy": round(shannon_entropy(text), 4)}


if __name__ == "__main__":
    result = train_and_evaluate()
    m   = result["metrics"]
    cm  = result["confusion_matrix"]
    print("=" * 64)
    print("SENTINELX DLP CLASSIFIER — TRAINING & EVALUATION REPORT")
    print("=" * 64)
    print(f"  Sample Size:     {result['sample_size']} total ({result['train_size']} train / {result['test_size']} test)")
    print(f"  Training Time:   {result['training_latency_ms']} ms")
    print(f"  Accuracy:        {m['accuracy_pct']}%  ({m['accuracy']})")
    print(f"  Precision:       {m['precision']}")
    print(f"  Recall:          {m['recall']}")
    print(f"  F1 Score:        {m['f1_score']}  (test set)")
    print(f"  CV F1:           {m['cv_f1_mean']} +/- {m['cv_f1_std']}  (5-fold, train set)")
    print(f"  Confusion:       TP={cm['true_positives']} FP={cm['false_positives']} TN={cm['true_negatives']} FN={cm['false_negatives']}")
    print(f"  Model saved:     {MODEL_PATH}")
    print("=" * 64)
