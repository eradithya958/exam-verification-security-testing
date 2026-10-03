# Performance, Stress & Denial-of-Service (DoS) Load Testing Report

**Project:** Exam Verification & Integrity System  
**Phase:** Phase 5 (Load Testing, Concurrency Saturation & Security Control Resilience)  
**Tooling:** Locust (Distributed Load Generator v2.34.0)  
**Test Objective:** Evaluate system resilience, latency degradation, DoS thresholds, and security control integrity during realistic peak exam submission windows.

---

## 1. Test Architecture & Realistic Exam Scenarios

Exam verification systems experience acute peak traffic patterns ("the final 5-minute rush"):
1. **User Onboarding & Authentication Burst:** Hundreds of students logging in simultaneously.
2. **Biometric Pre-Verification Spike:** Concurrent identity validation requests.
3. **Mass Exam File Uploads & SHA-256 Hashing:** Heavy I/O and CPU hashing during the submission cutoff window.
4. **Result Inquiries:** Periodic polling for released grades.

### Scenarios Executed:
- **Scenario A (Moderate Peak / Baseline):** 50 concurrent students, spawn rate 10 users/sec, 20s sustained traffic.
- **Scenario B (Stress / High-Concurrency Saturation):** 200 concurrent students, spawn rate 30 users/sec, 20s sustained burst.

---

## 2. Empirical Test Results

### 2.1 Scenario A: 50 Concurrent Users (Normal / Peak Load)

| Endpoint | Method | Total Requests | RPS | Median (ms) | 90% (ms) | 99% (ms) | Max (ms) | Error Rate |
|---|---|---|---|---|---|---|---|---|
| `/api/auth/register` | POST | 50 | 2.64 | 240 ms | 270 ms | 290 ms | 290 ms | 0.00% |
| `/api/auth/login` | POST | 50 | 2.64 | 220 ms | 240 ms | 260 ms | 260 ms | 0.00% |
| `/api/sessions/` | GET | 1,040 | 54.93 | 2 ms | 4 ms | 44 ms | 46 ms | 0.00% |
| `/api/sessions/{id}/verify-identity` | POST | 678 | 35.81 | 3 ms | 7 ms | 89 ms | 89 ms | 16.22% (Intentional test rejections) |
| `/api/submissions/upload` | POST | 326 | 17.22 | 3 ms | 5 ms | 34 ms | 34 ms | 23.31% (403 pre-check blocks) |
| `/api/results/student/me` | GET | 688 | 36.34 | 2 ms | 5 ms | 38 ms | 38 ms | 0.00% |
| **Aggregated Summary** | **ALL** | **2,832** | **149.59** | **3 ms** | **7 ms** | **280 ms** | **291 ms** | **6.57%** |

---

### 2.2 Scenario B: 200 Concurrent Users (Stress Saturation & DoS Threshold)

| Metric | Scenario A (50 Users) | Scenario B (200 Users) | Degradation Factor |
|---|---|---|---|
| **Aggregated Median Latency** | 3 ms | 660 ms | **220x increase** |
| **P95 Latency (Auth / Login)** | 250 ms | 1,200 ms | **4.8x increase** |
| **Max Request Latency** | 291 ms | 1,600 ms | **5.5x increase** |
| **Read Endpoint Median Latency** | 2 ms | 890 ms | **445x increase** |
| **CPU Saturation Root Cause** | Low (~18%) | **100% CPU Core Saturation** (Bcrypt hashing) | Event loop starvation |

---

## 3. Security Control Evaluation Under Concurrency

A crucial thesis investigation was determining whether security boundaries degrade, fail open, or experience race condition bypasses under heavy load:

1. **Biometric Pre-Submission Gate Resilience:**
   - In both 50-user and 200-user scenarios, students who had not completed identity verification were consistently blocked with `403 Forbidden` (76 occurrences in Scenario A).
   - **Conclusion:** No race condition or fail-open bypass occurred in the authorization pre-check under concurrent load.

2. **SHA-256 Checksum Verification Under Concurrency:**
   - All uploaded file streams computed and validated SHA-256 checksums accurately without memory corruption or cross-thread payload collisions.

3. **Denial-of-Service (DoS) Saturation Mechanism:**
   - The lack of rate limiting on `/api/auth/login` and `/api/auth/register` creates an asymmetric resource consumption vector.
   - Bcrypt hashing is deliberately computationally expensive (~200ms CPU time). An unauthenticated attacker sending 100 concurrent login attempts easily starves the Uvicorn worker threads of CPU cycles, causing legitimate lightweight endpoints (like result viewing) to degrade from 2ms to 900ms+.

---

## 4. Key Architectural Recommendations for Load & DoS Mitigation

1. **Implement Thread Pool Offloading & Rate Limiting:**
   - Offload CPU-bound password hashing to dedicated background thread workers or an external identity provider (IdP).
   - Enforce IP/token rate limits (e.g., 5 requests/sec per IP on `/login`) using Redis/token-bucket middleware to prevent resource starvation.
2. **Asynchronous File Streaming:**
   - Stream large submission payloads directly to S3/blob storage rather than buffering chunks into local disk I/O.
