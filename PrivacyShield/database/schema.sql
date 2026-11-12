-- ==============================================================================
-- PrivacyShield – DPDP Privacy Gateway Database Schema
-- Problem Statement: PS-02 DPDP-Ready Privacy Gateway for Enterprise LLMs
-- ==============================================================================
-- SECURITY NOTICE:
-- In compliance with the Digital Personal Data Protection (DPDP) Act, 2023:
-- 1. RAW ORIGINAL DOCUMENTS ARE NEVER STORED.
-- 2. ORIGINAL PII VALUES (Aadhaar, PAN, Passport, Names, etc.) ARE NEVER STORED.
-- 3. PLACEHOLDER-TO-ORIGINAL MAPPINGS ARE NEVER STORED.
-- 4. ONLY SANITIZED OUTBOUND PAYLOADS AND SAFE AUDIT METADATA ARE RECORDED.
-- ==============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table: audit_logs
-- Stores verifiable, non-reversible audit records for each privacy gateway transaction
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    document_type VARCHAR(64) NOT NULL,
    task_selected VARCHAR(64) NOT NULL DEFAULT 'summarize',
    entity_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    masked_entity_count INTEGER NOT NULL DEFAULT 0,
    sanitized_payload TEXT NOT NULL,
    external_model VARCHAR(128) NOT NULL,
    leakage_check_passed BOOLEAN NOT NULL DEFAULT TRUE,
    processing_status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED',
    processing_latency_ms NUMERIC(10, 2) NOT NULL DEFAULT 0.0,
    reinsertion_status VARCHAR(32) NOT NULL DEFAULT 'PERFECT',
    client_ip_hash VARCHAR(64),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for lightning fast queries and audit searches
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document_type ON audit_logs(document_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_processing_status ON audit_logs(processing_status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_leakage ON audit_logs(leakage_check_passed);

-- Table: performance_benchmarks
-- Stores automated evaluation and batch testing results on synthetic Indian datasets
CREATE TABLE IF NOT EXISTS performance_benchmarks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    total_documents INTEGER NOT NULL,
    expected_entities INTEGER NOT NULL,
    detected_entities INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    false_positives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL,
    precision_score NUMERIC(5, 4) NOT NULL,
    recall_score NUMERIC(5, 4) NOT NULL,
    f1_score NUMERIC(5, 4) NOT NULL,
    reinsertion_accuracy NUMERIC(5, 4) NOT NULL,
    leakage_count INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms NUMERIC(10, 2) NOT NULL,
    breakdown_by_type JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Secure Row Level Security (RLS) Policies
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE performance_benchmarks ENABLE ROW LEVEL SECURITY;

-- Allow reading audit logs through authenticated or anon key with read permission
CREATE POLICY "Allow read audit logs" ON audit_logs FOR SELECT USING (true);
CREATE POLICY "Allow insert audit logs" ON audit_logs FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow read benchmarks" ON performance_benchmarks FOR SELECT USING (true);
CREATE POLICY "Allow insert benchmarks" ON performance_benchmarks FOR INSERT WITH CHECK (true);
