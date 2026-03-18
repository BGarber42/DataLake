-- Example Athena Queries for Security Data Lake Analysis
-- Replace 'security_db' and 'security_findings' with your actual database and table names
--
-- IMPORTANT: SQS Standard provides at-least-once delivery, so retried Lambda
-- invocations can write duplicate rows. Use the deduplicated view for accurate
-- counts. Run the "create-dedup-view" Athena named query once after first deploy.

-- =============================================================================
-- DEDUPLICATION — run once after first deploy (also available as named query)
-- =============================================================================

-- CREATE OR REPLACE VIEW security_findings_deduped AS
-- SELECT * FROM (
--   SELECT *, ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY processed_at DESC) AS _row_num
--   FROM security_db.security_findings
-- ) WHERE _row_num = 1;

-- =============================================================================
-- BASIC QUERIES (using deduplicated view)
-- =============================================================================

-- 1. Count total findings by severity
SELECT 
    severity,
    COUNT(*) as finding_count
FROM security_db.security_findings_deduped
GROUP BY severity
ORDER BY 
    CASE severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;

-- 2. Count findings by source
SELECT 
    source,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings
GROUP BY source
ORDER BY finding_count DESC;

-- 3. Count findings by type
SELECT 
    finding_type,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings
GROUP BY finding_type
ORDER BY finding_count DESC;

-- =============================================================================
-- TIME-BASED ANALYSIS
-- =============================================================================

-- 4. Daily finding trends (last 30 days)
SELECT 
    DATE(timestamp) as finding_date,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_findings
FROM security_db.security_findings
WHERE DATE(timestamp) >= CURRENT_DATE - INTERVAL '30' DAY
GROUP BY DATE(timestamp)
ORDER BY finding_date DESC;

-- 5. Hourly distribution of findings
SELECT 
    EXTRACT(HOUR FROM timestamp) as hour_of_day,
    COUNT(*) as finding_count
FROM security_db.security_findings
WHERE DATE(timestamp) >= CURRENT_DATE - INTERVAL '7' DAY
GROUP BY EXTRACT(HOUR FROM timestamp)
ORDER BY hour_of_day;

-- 6. Monthly trend analysis
SELECT 
    DATE_TRUNC('month', timestamp) as month,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_findings,
    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_findings,
    COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium_findings,
    COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low_findings
FROM security_db.security_findings
GROUP BY DATE_TRUNC('month', timestamp)
ORDER BY month DESC;

-- =============================================================================
-- RESOURCE ANALYSIS
-- =============================================================================

-- 7. Most affected resources
SELECT 
    affected_resource,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings
CROSS JOIN UNNEST(affected_resources) AS t(affected_resource)
GROUP BY affected_resource
ORDER BY finding_count DESC
LIMIT 20;

-- 8. Resource types analysis
SELECT 
    CASE 
        WHEN affected_resource LIKE 'arn:aws:ec2%' THEN 'EC2'
        WHEN affected_resource LIKE 'arn:aws:s3%' THEN 'S3'
        WHEN affected_resource LIKE 'arn:aws:iam%' THEN 'IAM'
        WHEN affected_resource LIKE 'arn:aws:rds%' THEN 'RDS'
        WHEN affected_resource LIKE 'arn:aws:lambda%' THEN 'Lambda'
        ELSE 'Other'
    END as resource_type,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings
CROSS JOIN UNNEST(affected_resources) AS t(affected_resource)
GROUP BY 
    CASE 
        WHEN affected_resource LIKE 'arn:aws:ec2%' THEN 'EC2'
        WHEN affected_resource LIKE 'arn:aws:s3%' THEN 'S3'
        WHEN affected_resource LIKE 'arn:aws:iam%' THEN 'IAM'
        WHEN affected_resource LIKE 'arn:aws:rds%' THEN 'RDS'
        WHEN affected_resource LIKE 'arn:aws:lambda%' THEN 'Lambda'
        ELSE 'Other'
    END
ORDER BY finding_count DESC;

-- =============================================================================
-- METADATA ANALYSIS
-- =============================================================================

-- 9. Findings by environment (from metadata_tags JSON)
SELECT 
    JSON_EXTRACT_SCALAR(metadata_tags, '$.Environment') as environment,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings_deduped
WHERE JSON_EXTRACT_SCALAR(metadata_tags, '$.Environment') IS NOT NULL
GROUP BY JSON_EXTRACT_SCALAR(metadata_tags, '$.Environment')
ORDER BY finding_count DESC;

-- 10. Findings by region
SELECT 
    metadata_region as region,
    COUNT(*) as finding_count,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_count
FROM security_db.security_findings_deduped
WHERE metadata_region IS NOT NULL
GROUP BY metadata_region
ORDER BY finding_count DESC;

-- =============================================================================
-- ADVANCED ANALYSIS
-- =============================================================================

-- 11. Correlation between source and severity
SELECT 
    source,
    severity,
    COUNT(*) as finding_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY source), 2) as percentage
FROM security_db.security_findings
GROUP BY source, severity
ORDER BY source, 
    CASE severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;

-- 12. Time-based severity analysis
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    severity,
    COUNT(*) as finding_count
FROM security_db.security_findings
WHERE DATE(timestamp) >= CURRENT_DATE - INTERVAL '7' DAY
GROUP BY DATE_TRUNC('hour', timestamp), severity
ORDER BY hour DESC, 
    CASE severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;

-- 13. Finding type and severity correlation
SELECT 
    finding_type,
    severity,
    COUNT(*) as finding_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY finding_type), 2) as percentage
FROM security_db.security_findings
GROUP BY finding_type, severity
ORDER BY finding_type, 
    CASE severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
    END;

-- =============================================================================
-- OPERATIONAL QUERIES
-- =============================================================================

-- 14. Recent high-severity findings (last 24 hours)
SELECT 
    event_id,
    timestamp,
    severity,
    source,
    finding_type,
    description,
    affected_resources
FROM security_db.security_findings
WHERE severity IN ('HIGH', 'CRITICAL')
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
ORDER BY timestamp DESC;

-- 15. Processing performance analysis
SELECT 
    DATE(processed_at) as processing_date,
    COUNT(*) as processed_findings,
    AVG(CAST(EXTRACT(EPOCH FROM (timestamp - processed_at)) AS DOUBLE)) as avg_processing_delay_seconds
FROM security_db.security_findings
WHERE processed_at IS NOT NULL
GROUP BY DATE(processed_at)
ORDER BY processing_date DESC;

-- 16. Data quality check
SELECT 
    'Total Records' as metric,
    COUNT(*) as value
FROM security_db.security_findings
UNION ALL
SELECT 
    'Records with Missing Event ID' as metric,
    COUNT(*) as value
FROM security_db.security_findings
WHERE event_id IS NULL OR event_id = ''
UNION ALL
SELECT 
    'Records with Missing Timestamp' as metric,
    COUNT(*) as value
FROM security_db.security_findings
WHERE timestamp IS NULL
UNION ALL
SELECT 
    'Records with Missing Severity' as metric,
    COUNT(*) as value
FROM security_db.security_findings
WHERE severity IS NULL OR severity = '';

-- =============================================================================
-- COMPLIANCE AND REPORTING QUERIES
-- =============================================================================

-- 17. Compliance summary by month
SELECT 
    DATE_TRUNC('month', timestamp) as month,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_violations,
    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_violations,
    COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium_violations,
    ROUND(COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) * 100.0 / COUNT(*), 2) as high_severity_percentage
FROM security_db.security_findings
GROUP BY DATE_TRUNC('month', timestamp)
ORDER BY month DESC;

-- 18. Security posture by finding type
SELECT 
    finding_type,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_findings,
    ROUND(COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) * 100.0 / COUNT(*), 2) as high_severity_percentage,
    MAX(timestamp) as last_occurrence
FROM security_db.security_findings
GROUP BY finding_type
ORDER BY high_severity_percentage DESC, total_findings DESC;

-- 19. Resource security score
SELECT 
    affected_resource,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_severity_findings,
    CASE 
        WHEN COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) = 0 THEN 'SECURE'
        WHEN COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) <= 2 THEN 'ATTENTION'
        ELSE 'CRITICAL'
    END as security_status
FROM security_db.security_findings
CROSS JOIN UNNEST(affected_resources) AS t(affected_resource)
GROUP BY affected_resource
HAVING COUNT(*) >= 1
ORDER BY high_severity_findings DESC, total_findings DESC
LIMIT 50; 