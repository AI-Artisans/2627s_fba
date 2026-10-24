-- =====================================================================
-- CIT 401A | Laboratory Activity #06: CRISP-DM | Testing
-- Unera, John Raven S.  --  Data Preparation script (MySQL 8 / MariaDB)
-- Usage:  mysql --local-infile=1 -u root -p < 01_import_and_prepare.sql
-- (edit the file path in LOAD DATA to where your CSV is saved)
-- =====================================================================
CREATE DATABASE IF NOT EXISTS lab06_wk12 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE lab06_wk12;

-- ---------------------------------------------------------------------
-- STEP 1. Raw table: every one of the 25 CSV fields with a proper type
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS cyber_attacks_raw;
CREATE TABLE cyber_attacks_raw (
  record_id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_timestamp      DATETIME          NOT NULL,
  source_ip            VARCHAR(15)       NOT NULL,
  destination_ip       VARCHAR(15)       NOT NULL,
  source_port          SMALLINT UNSIGNED NOT NULL,
  destination_port     SMALLINT UNSIGNED NOT NULL,
  protocol             ENUM('ICMP','TCP','UDP')          NOT NULL,
  packet_length        SMALLINT UNSIGNED NOT NULL,
  packet_type          ENUM('Control','Data')            NOT NULL,
  traffic_type         ENUM('DNS','FTP','HTTP')          NOT NULL,
  payload_data         TEXT              NOT NULL,
  malware_indicators   VARCHAR(20)       NULL,
  anomaly_score        DECIMAL(5,2)      NOT NULL,
  alerts_warnings      VARCHAR(20)       NULL,
  attack_type          ENUM('DDoS','Intrusion','Malware') NOT NULL,
  attack_signature     VARCHAR(20)       NOT NULL,
  action_taken         ENUM('Blocked','Ignored','Logged')  NOT NULL,
  severity_level       ENUM('Low','Medium','High')        NOT NULL,
  user_information     VARCHAR(100)      NOT NULL,
  device_information   VARCHAR(255)      NOT NULL,
  network_segment      VARCHAR(20)       NOT NULL,
  geo_location         VARCHAR(100)      NOT NULL,
  proxy_information    VARCHAR(15)       NULL,
  firewall_logs        VARCHAR(20)       NULL,
  ids_ips_alerts       VARCHAR(20)       NULL,
  log_source           ENUM('Firewall','Server')          NOT NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- STEP 2. Import the CSV. Fields are quoted because Payload Data holds
-- commas and line breaks; empty strings are converted to real NULLs.
-- ---------------------------------------------------------------------
LOAD DATA LOCAL INFILE 'dataset_Wk12.csv'
INTO TABLE cyber_attacks_raw
CHARACTER SET utf8mb4
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 LINES
(@ts,@sip,@dip,@sport,@dport,@proto,@plen,@ptype,@ttype,@payload,@mal,@anom,@alert,
 @atype,@asig,@action,@sev,@user,@dev,@seg,@geo,@proxy,@fw,@ids,@logsrc)
SET event_timestamp    = STR_TO_DATE(@ts,'%Y-%m-%d %H:%i:%s'),
    source_ip          = TRIM(@sip),
    destination_ip     = TRIM(@dip),
    source_port        = @sport,
    destination_port   = @dport,
    protocol           = TRIM(@proto),
    packet_length      = @plen,
    packet_type        = TRIM(@ptype),
    traffic_type       = TRIM(@ttype),
    payload_data       = @payload,
    malware_indicators = NULLIF(TRIM(@mal),''),
    anomaly_score      = @anom,
    alerts_warnings    = NULLIF(TRIM(@alert),''),
    attack_type        = TRIM(@atype),
    attack_signature   = TRIM(@asig),
    action_taken       = TRIM(@action),
    severity_level     = TRIM(@sev),
    user_information   = TRIM(@user),
    device_information = TRIM(@dev),
    network_segment    = TRIM(@seg),
    geo_location       = TRIM(@geo),
    proxy_information  = NULLIF(TRIM(@proxy),''),
    firewall_logs      = NULLIF(TRIM(@fw),''),
    ids_ips_alerts     = NULLIF(TRIM(TRIM(TRAILING '\r' FROM @ids)),''),
    log_source         = TRIM(TRIM(TRAILING '\r' FROM @logsrc));

-- ---------------------------------------------------------------------
-- STEP 3. Prepared (model-ready) table
--   * sanitation   : NULL flags -> explicit Yes/No (missing = "absent")
--   * extraction   : time parts, browser / OS, state, proxy flag
--   * selection    : identifiers & free text (IPs, names, payload,
--                    raw timestamp, city, proxy IP) are left out
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS cyber_attacks_prepared;
CREATE TABLE cyber_attacks_prepared AS
SELECT
  record_id,
  HOUR(event_timestamp)                                    AS event_hour,
  DAYNAME(event_timestamp)                                 AS event_dayofweek,
  MONTH(event_timestamp)                                   AS event_month,
  YEAR(event_timestamp)                                    AS event_year,
  source_port,
  destination_port,
  protocol,
  packet_length,
  packet_type,
  traffic_type,
  IF(malware_indicators IS NULL,'No','Yes')                AS malware_ioc_detected,
  anomaly_score,
  IF(alerts_warnings    IS NULL,'No','Yes')                AS alert_triggered,
  attack_type,
  attack_signature,
  severity_level,
  CASE
    WHEN device_information LIKE 'Opera%'   THEN 'Opera'
    WHEN device_information LIKE '%MSIE%'   THEN 'MSIE'
    WHEN device_information LIKE '%Firefox%' THEN 'Firefox'
    WHEN device_information LIKE '%Chrome%' THEN 'Chrome'
    WHEN device_information LIKE '%Safari%' THEN 'Safari'
    ELSE 'Other' END                                       AS browser,
  CASE
    WHEN device_information LIKE '%Windows%'   THEN 'Windows'
    WHEN device_information LIKE '%Android%'   THEN 'Android'
    WHEN device_information LIKE '%iPhone%' OR device_information LIKE '%iPad%'
      OR device_information LIKE '%iPod%'      THEN 'iOS'
    WHEN device_information LIKE '%Macintosh%' THEN 'Mac'
    WHEN device_information LIKE '%Linux%'     THEN 'Linux'
    ELSE 'Other' END                                       AS operating_system,
  network_segment,
  TRIM(SUBSTRING_INDEX(geo_location, ',', -1))             AS geo_state,
  CASE TRIM(SUBSTRING_INDEX(geo_location, ',', -1))
    WHEN 'Haryana' THEN 'North' WHEN 'Himachal Pradesh' THEN 'North' WHEN 'Punjab' THEN 'North'
    WHEN 'Rajasthan' THEN 'North' WHEN 'Uttar Pradesh' THEN 'North' WHEN 'Uttarakhand' THEN 'North'
    WHEN 'Andhra Pradesh' THEN 'South' WHEN 'Karnataka' THEN 'South' WHEN 'Kerala' THEN 'South'
    WHEN 'Tamil Nadu' THEN 'South' WHEN 'Telangana' THEN 'South'
    WHEN 'Bihar' THEN 'East' WHEN 'Jharkhand' THEN 'East' WHEN 'Odisha' THEN 'East' WHEN 'West Bengal' THEN 'East'
    WHEN 'Goa' THEN 'West' WHEN 'Gujarat' THEN 'West' WHEN 'Maharashtra' THEN 'West'
    WHEN 'Chhattisgarh' THEN 'Central' WHEN 'Madhya Pradesh' THEN 'Central'
    ELSE 'Northeast' END                                   AS geo_region,
  IF(proxy_information  IS NULL,'No','Yes')                AS uses_proxy,
  IF(firewall_logs      IS NULL,'No','Yes')                AS firewall_logged,
  IF(ids_ips_alerts     IS NULL,'No','Yes')                AS ids_ips_alerted,
  log_source,
  action_taken                                             -- class label
FROM cyber_attacks_raw;
ALTER TABLE cyber_attacks_prepared ADD PRIMARY KEY (record_id);

-- ---------------------------------------------------------------------
-- STEP 4. Validation queries
-- ---------------------------------------------------------------------
SELECT COUNT(*) AS raw_rows FROM cyber_attacks_raw;
SELECT COUNT(*) AS prepared_rows FROM cyber_attacks_prepared;
SELECT action_taken, COUNT(*) AS n FROM cyber_attacks_prepared GROUP BY action_taken;
