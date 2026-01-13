-- Drop all cached CTI objects (reverting OpenCTI Full Mirror implementation)

-- Drop views first (they depend on tables)
DROP VIEW IF EXISTS cached_intrusion_sets CASCADE;
DROP VIEW IF EXISTS cached_malware CASCADE;
DROP VIEW IF EXISTS cached_tools CASCADE;
DROP VIEW IF EXISTS cached_campaigns CASCADE;
DROP VIEW IF EXISTS cached_attack_patterns CASCADE;
DROP VIEW IF EXISTS cached_courses_of_action CASCADE;
DROP VIEW IF EXISTS cached_vulnerabilities CASCADE;
DROP VIEW IF EXISTS cached_indicators CASCADE;
DROP VIEW IF EXISTS cached_reports CASCADE;
DROP VIEW IF EXISTS cached_sectors CASCADE;
DROP VIEW IF EXISTS cached_countries CASCADE;
DROP VIEW IF EXISTS cached_regions CASCADE;
DROP VIEW IF EXISTS cached_relationships CASCADE;

-- Drop triggers
DROP TRIGGER IF EXISTS update_sectors_search_vector ON opencti_sectors;
DROP TRIGGER IF EXISTS update_countries_search_vector ON opencti_countries;
DROP TRIGGER IF EXISTS update_regions_search_vector ON opencti_regions;
DROP TRIGGER IF EXISTS update_intrusion_sets_search_vector ON opencti_intrusion_sets;
DROP TRIGGER IF EXISTS update_malware_search_vector ON opencti_malware;
DROP TRIGGER IF EXISTS update_tools_search_vector ON opencti_tools;
DROP TRIGGER IF EXISTS update_campaigns_search_vector ON opencti_campaigns;
DROP TRIGGER IF EXISTS update_attack_patterns_search_vector ON opencti_attack_patterns;
DROP TRIGGER IF EXISTS update_courses_of_action_search_vector ON opencti_courses_of_action;
DROP TRIGGER IF EXISTS update_vulnerabilities_search_vector ON opencti_vulnerabilities;
DROP TRIGGER IF EXISTS update_reports_search_vector ON opencti_reports;

-- Drop functions (CASCADE to remove dependent triggers)
DROP FUNCTION IF EXISTS update_search_vector() CASCADE;

-- Drop tables
DROP TABLE IF EXISTS opencti_sectors CASCADE;
DROP TABLE IF EXISTS opencti_countries CASCADE;
DROP TABLE IF EXISTS opencti_regions CASCADE;
DROP TABLE IF EXISTS opencti_intrusion_sets CASCADE;
DROP TABLE IF EXISTS opencti_malware CASCADE;
DROP TABLE IF EXISTS opencti_tools CASCADE;
DROP TABLE IF EXISTS opencti_campaigns CASCADE;
DROP TABLE IF EXISTS opencti_attack_patterns CASCADE;
DROP TABLE IF EXISTS opencti_courses_of_action CASCADE;
DROP TABLE IF EXISTS opencti_vulnerabilities CASCADE;
DROP TABLE IF EXISTS opencti_indicators CASCADE;
DROP TABLE IF EXISTS opencti_reports CASCADE;
DROP TABLE IF EXISTS opencti_relationships CASCADE;

-- Drop sync infrastructure tables
DROP TABLE IF EXISTS opencti_sync_jobs CASCADE;
DROP TABLE IF EXISTS opencti_sync_state CASCADE;

-- Remove use_cached_cti setting
DELETE FROM app_settings WHERE key = 'use_cached_cti';
