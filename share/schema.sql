-- schema.sql -*- mode: sql; sql-product: postgres; -*-
--
-- data storage for DMARC reports data

-- the installation script will ignore this line
\echo "--- use the: 'install-schema' script rather than loading this file directly ---" \q

-- initial setup
\connect postgres

-- note: the install-schema will use the password from etc/updaterd.conf
--       in place of the tag below when loading this file into the database
CREATE USER @CHANGE-TO-USERNAME@ ENCRYPTED PASSWORD '@CHANGE-TO-SECURE-PASSWORD@';
ALTER ROLE @CHANGE-TO-USERNAME@ ENCRYPTED PASSWORD '@CHANGE-TO-SECURE-PASSWORD@';

-- drop/create database is controlled by install-schema options
--@DROP@DROP DATABASE IF EXISTS @CHANGE-TO-DBNAME@;
--@CREATE@CREATE DATABASE @CHANGE-TO-DBNAME@;

-- connect to the database
\connect @CHANGE-TO-DBNAME@

-- drop schema and all its objects, create the schema and use it by default
DROP SCHEMA IF EXISTS dmarc CASCADE;
CREATE SCHEMA IF NOT EXISTS dmarc;

SET search_path = dmarc;                                          -- everything in this schema for schema loading
ALTER ROLE @CHANGE-TO-USERNAME@ SET search_path TO dmarc, PUBLIC; -- ensure user sees the schema first

--- grant to @CHANGE-TO-USERNAME@ ---
GRANT CONNECT ON DATABASE @CHANGE-TO-DBNAME@ TO @CHANGE-TO-USERNAME@;
GRANT USAGE ON SCHEMA dmarc TO @CHANGE-TO-USERNAME@;
ALTER DEFAULT PRIVILEGES IN SCHEMA dmarc GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO @CHANGE-TO-USERNAME@;
ALTER DEFAULT PRIVILEGES IN SCHEMA dmarc GRANT SELECT, UPDATE ON SEQUENCES TO @CHANGE-TO-USERNAME@;


-- dmarc reports
DROP TABLE IF EXISTS report;

CREATE TABLE report (
  report_id TEXT PRIMARY KEY NOT NULL,
  report_begin_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP, -- ON UPDATE CURRENT_TIMESTAMP,
  report_end_date TIMESTAMP WITH TIME ZONE NULL,
  report_domain TEXT NOT NULL,
  report_org_name TEXT NOT NULL,
  report_email TEXT NULL,
  report_extra_contact_info TEXT NULL,
  report_policy_adkim TEXT NULL,
  report_policy_aspf TEXT NULL,
  report_policy_p TEXT NULL,
  report_policy_sp TEXT NULL,
  report_policy_pct INT8 NOT NULL DEFAULT 0,
  report_created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- for domain
DROP INDEX IF EXISTS report_domain_index;
CREATE UNIQUE INDEX report_domain_index ON report(report_domain, report_id);

-- for date ordering
DROP INDEX IF EXISTS report_order_index;
CREATE UNIQUE INDEX report_orde_index ON report(report_id, report_begin_date, report_end_date, report_org_name);


-- types

CREATE TYPE disposition_type AS ENUM('none','quarantine','reject');
CREATE TYPE dkim_result_type AS ENUM('none','pass','fail','policy','neutral','temperror','permerror');
CREATE TYPE spf_result_type AS ENUM('none','neutral','pass','fail','softfail','temperror','permerror','unknown','error');
CREATE TYPE dmarc_result_type AS ENUM('pass','fail');


-- report records

DROP TABLE IF EXISTS item;

CREATE TABLE item (
  item_id SERIAL PRIMARY KEY NOT NULL,
  item_report_id TEXT REFERENCES report(report_id),
  item_ip TEXT NOT NULL,
  item_count INT8 NOT NULL,
  item_disposition disposition_type,
  item_dkim_domain TEXT,
  item_dkim_result dkim_result_type,
  item_policy_dkim dmarc_result_type,
  item_spf_domain TEXT,
  item_spf_result spf_result_type,
  item_policy_spf dmarc_result_type,
  item_reason TEXT,
  item_header_from TEXT,
  item_created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- for IP
DROP INDEX IF EXISTS item_report_id_ip_index;
CREATE INDEX item_report_id_ip_index ON item(item_report_id, item_ip);


-- finished
SET search_path TO DEFAULT;
