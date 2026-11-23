drop table if exists USERS cascade constraints;
create table USERS(
    user_id integer primary key,
    username varchar2(20) not null unique,
    department varchar2(20) not null,
    creation_date timestamp not null,
    actual_state varchar2(20) not null
);

drop table if exists DEVICES cascade constraints;
create table DEVICES(
    device_id integer primary key,
    device_name varchar2(20) not null,
    type varchar2(20) not null,
    operating_system varchar2(20) not null,
    actual_state varchar2(20) not null

);

drop table if exists IP_ADDRESSES cascade constraints;
create table IP_ADDRESSES(
    ip_address varchar2(39) primary key,
    classification varchar2(20) not null,
    trust_level integer not null
);

drop table if exists DEVICE_IP_ASSIGNMENTS cascade constraints;
create table DEVICE_IP_ASSIGNMENTS(
    ip_address varchar2(39),
    device_id integer,
    valid_from timestamp not null,
    valid_until timestamp null,
    constraint fk_ip_assignment
    foreign key (ip_address)
    references IP_ADDRESSES(ip_address),
    constraint fk_device_assignment
    foreign key (device_id)
    references DEVICES(device_id),
    constraint pk_device_ip_assignments primary key (ip_address, device_id, valid_from),
    constraint chk_valid_dates
    check (valid_until is null or valid_until >= valid_from)
);

create or replace trigger non_overlaping_dates before insert or update on DEVICE_IP_ASSIGNMENTS
    for each row
    declare
    c integer;
begin
    select count(*) into c from DEVICE_IP_ASSIGNMENTS dpa where dpa.device_id = :NEW.device_id and (dpa.VALID_UNTIL is not null and (:NEW.valid_until BETWEEN dpa.valid_from and dpa.valid_until) or (:NEW.valid_from BETWEEN dpa.valid_from and dpa.valid_until)) or (dpa.VALID_UNTIL is null and (:NEW.valid_from >= dpa.valid_from) or (:NEW.valid_until >= dpa.valid_from));
    if (c > 0) then
        raise_application_error(-20021, 'No se ha podido insertar, ya que se solapa con fechas existentes.');
    end if;
end;

drop table if exists EVENT_TYPES cascade constraints;
create table EVENT_TYPES(
    event_id integer primary key,
    type varchar2(20) not null unique,
    description clob null,
    classification varchar2(20) not null
);

drop table if exists INCIDENTS cascade constraints;
create table INCIDENTS(
    incident_id integer primary key,
    rating integer not null check (rating BETWEEN 0 and 5),
    creation_date timestamp not null,
    closed_date timestamp null,
    priority varchar2(20) not null,
    state varchar2(20) not null,
    constraint chk_valid_incident_dates
    check (closed_date is null or closed_date >= creation_date)
);

drop table if exists INCIDENT_RESPONSES cascade constraints;
create table INCIDENT_RESPONSES(
    incident_id integer,
    timestamp timestamp,
    description clob null,
    constraint fk_incident
    foreign key (incident_id)
    references INCIDENTS(incident_id),
    constraint pk_incident_responses PRIMARY KEY (incident_id, timestamp)
);

drop table if exists ALERTS cascade constraints;
create table ALERTS(
    alert_id integer primary key ,
    creation_date timestamp not null,
    rating integer not null check (rating BETWEEN 0 and 5),
    state varchar2(20) not null,
    description clob null,
    incident_id integer,
    constraint fk_incident_alerts
    foreign key (incident_id)
    references INCIDENTS(incident_id)
);

drop table if exists SECURITY_EVENTS cascade constraints;
create table SECURITY_EVENTS(
    security_event_id integer primary key,
    event_type_id integer not null,
    alert_id integer,
    timestamp timestamp not null,
    user_id integer null,
    device_id integer null,
    ip_address varchar2(39) null,
    aditional_info clob null,
    constraint fk_alerts_sec_events
    foreign key (alert_id)
    references ALERTS(alert_id),
    constraint fk_user_sec_events
    foreign key (user_id)
    references USERS(user_id),
    constraint fk_device_sec_events
    foreign key (device_id)
    references DEVICES(device_id),
    constraint fk_ip_sec_events
    foreign key (ip_address)
    references IP_ADDRESSES(ip_address),
    constraint fk_event_sec_events
    foreign key (event_type_id)
    references EVENT_TYPES(event_id)
);

drop table if exists THREAT_TYPES cascade constraints;
create table THREAT_TYPES(
    incident_id int,
    category varchar2(20),
    description clob null,
    rating integer not null check (rating BETWEEN 0 and 5),
    constraint fk_incident_threat_types
    foreign key (incident_id)
    references INCIDENTS(incident_id),
    constraint pk_threat_types PRIMARY KEY (incident_id, category)
);

commit;

-- 1. USERS

INSERT INTO USERS VALUES (
    1, 'alex.martin', 'IT',
    TIMESTAMP '2024-01-15 09:00:00', 'ACTIVE'
);

INSERT INTO USERS VALUES (
    2, 'maria.lopez', 'HR',
    TIMESTAMP '2023-11-20 10:30:00', 'ACTIVE'
);

INSERT INTO USERS VALUES (
    3, 'david.garcia', 'FINANCE',
    TIMESTAMP '2024-03-10 08:15:00', 'ACTIVE'
);

INSERT INTO USERS VALUES (
    4, 'laura.sanchez', 'SECURITY',
    TIMESTAMP '2022-06-05 12:00:00', 'ACTIVE'
);

INSERT INTO USERS VALUES (
    5, 'pablo.ruiz', 'IT',
    TIMESTAMP '2024-08-01 14:45:00', 'INACTIVE'
);

-- 2. DEVICES

INSERT INTO DEVICES VALUES (
    1, 'PC-IT-001', 'COMPUTER', 'Windows 11', 'ACTIVE'
);

INSERT INTO DEVICES VALUES (
    2, 'PC-HR-001', 'COMPUTER', 'Windows 10', 'ACTIVE'
);

INSERT INTO DEVICES VALUES (
    3, 'SRV-WEB-001', 'SERVER', 'Ubuntu 22.04', 'ACTIVE'
);

INSERT INTO DEVICES VALUES (
    4, 'SRV-DB-001', 'SERVER', 'Oracle Linux 9', 'ACTIVE'
);

INSERT INTO DEVICES VALUES (
    5, 'LAPTOP-SEC-01', 'LAPTOP', 'Kali Linux', 'ACTIVE'
);

INSERT INTO DEVICES VALUES (
    6, 'PC-FIN-001', 'COMPUTER', 'Windows 11', 'INACTIVE'
);


-- =========================================
-- 3. IP_ADDRESSES
-- =========================================

INSERT INTO IP_ADDRESSES VALUES (
    '192.168.1.10', 'PRIVATE', 5
);

INSERT INTO IP_ADDRESSES VALUES (
    '192.168.1.11', 'PRIVATE', 5
);

INSERT INTO IP_ADDRESSES VALUES (
    '192.168.1.20', 'PRIVATE', 4
);

INSERT INTO IP_ADDRESSES VALUES (
    '192.168.1.30', 'PRIVATE', 5
);

INSERT INTO IP_ADDRESSES VALUES (
    '10.0.0.15', 'PRIVATE', 3
);

INSERT INTO IP_ADDRESSES VALUES (
    '203.0.113.45', 'PUBLIC', 1
);

INSERT INTO IP_ADDRESSES VALUES (
    '198.51.100.27', 'PUBLIC', 0
);

INSERT INTO IP_ADDRESSES VALUES (
    '2001:db8::10', 'PUBLIC', 4
);


-- =========================================
-- 4. DEVICE_IP_ASSIGNMENTS
-- =========================================

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '192.168.1.10', 1,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '192.168.1.11', 2,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '192.168.1.20', 3,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '192.168.1.30', 4,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '10.0.0.15', 5,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);

INSERT INTO DEVICE_IP_ASSIGNMENTS VALUES (
    '2001:db8::10', 6,
    TIMESTAMP '2025-01-01 00:00:00',
    NULL
);


-- =========================================
-- 5. EVENT_TYPES
-- =========================================

INSERT INTO EVENT_TYPES VALUES (
    1, 'LOGIN_SUCCESS',
    'Successful user authentication',
    'INFO'
);

INSERT INTO EVENT_TYPES VALUES (
    2, 'LOGIN_FAILURE',
    'Failed authentication attempt',
    'WARNING'
);

INSERT INTO EVENT_TYPES VALUES (
    3, 'PRIVILEGE_CHANGE',
    'User privilege modification',
    'HIGH'
);

INSERT INTO EVENT_TYPES VALUES (
    4, 'FILE_ACCESS',
    'Access to a protected file',
    'INFO'
);

INSERT INTO EVENT_TYPES VALUES (
    5, 'PORT_SCAN',
    'Network port scanning activity',
    'WARNING'
);

INSERT INTO EVENT_TYPES VALUES (
    6, 'MALWARE_DETECTED',
    'Malicious software detected',
    'CRITICAL'
);

INSERT INTO EVENT_TYPES VALUES (
    7, 'DATA_TRANSFER',
    'Large or unusual data transfer',
    'HIGH'
);

INSERT INTO EVENT_TYPES VALUES (
    8, 'ACCOUNT_LOCKED',
    'Account locked after repeated failures',
    'WARNING'
);


-- =========================================
-- 6. INCIDENTS
-- =========================================

INSERT INTO INCIDENTS VALUES (
    1, 5,
    TIMESTAMP '2026-10-01 08:30:00',
    NULL,
    'CRITICAL',
    'OPEN'
);

INSERT INTO INCIDENTS VALUES (
    2, 3,
    TIMESTAMP '2026-10-03 11:15:00',
    TIMESTAMP '2026-10-04 16:00:00',
    'HIGH',
    'CLOSED'
);

INSERT INTO INCIDENTS VALUES (
    3, 4,
    TIMESTAMP '2026-10-05 14:20:00',
    NULL,
    'HIGH',
    'INVESTIGATING'
);

INSERT INTO INCIDENTS VALUES (
    4, 2,
    TIMESTAMP '2026-10-08 09:45:00',
    TIMESTAMP '2026-10-08 13:30:00',
    'MEDIUM',
    'CLOSED'
);


-- =========================================
-- 7. INCIDENT_RESPONSES
-- =========================================

INSERT INTO INCIDENT_RESPONSES VALUES (
    1,
    TIMESTAMP '2026-10-01 08:45:00',
    'Initial investigation started.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    1,
    TIMESTAMP '2026-10-01 09:30:00',
    'Suspicious IP address blocked.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    1,
    TIMESTAMP '2026-10-01 11:00:00',
    'Investigation ongoing. Reviewing authentication logs.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    2,
    TIMESTAMP '2026-10-03 12:00:00',
    'Affected account temporarily disabled.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    2,
    TIMESTAMP '2026-10-04 15:30:00',
    'Password reset completed and incident resolved.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    3,
    TIMESTAMP '2026-10-05 15:00:00',
    'Unusual data transfer identified.'
);

INSERT INTO INCIDENT_RESPONSES VALUES (
    4,
    TIMESTAMP '2026-10-08 10:30:00',
    'Account lockout reviewed and access restored.'
);


-- =========================================
-- 8. ALERTS
-- =========================================

INSERT INTO ALERTS VALUES (
    1,
    TIMESTAMP '2026-10-01 08:30:00',
    5,
    'OPEN',
    'Multiple failed login attempts from suspicious IP.',
    1
);

INSERT INTO ALERTS VALUES (
    2,
    TIMESTAMP '2026-10-01 08:35:00',
    4,
    'INVESTIGATING',
    'Suspicious authentication activity detected.',
    1
);

INSERT INTO ALERTS VALUES (
    3,
    TIMESTAMP '2026-10-03 11:15:00',
    3,
    'CLOSED',
    'Unexpected privilege modification.',
    2
);

INSERT INTO ALERTS VALUES (
    4,
    TIMESTAMP '2026-10-05 14:20:00',
    5,
    'OPEN',
    'Unusual outbound data transfer.',
    3
);

INSERT INTO ALERTS VALUES (
    5,
    TIMESTAMP '2026-10-08 09:45:00',
    2,
    'CLOSED',
    'Multiple authentication failures.',
    4
);

INSERT INTO ALERTS VALUES (
    6,
    TIMESTAMP '2026-10-10 17:00:00',
    3,
    'OPEN',
    'Network port scan detected without an incident assigned.',
    NULL
);


-- =========================================
-- 9. SECURITY_EVENTS
-- =========================================

INSERT INTO SECURITY_EVENTS VALUES (
    1, 1, NULL,
    TIMESTAMP '2026-10-01 08:00:00',
    1, 1, '192.168.1.10',
    'Normal login from corporate network.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    22, 1, NULL,
    TIMESTAMP '2026-10-08 08:00:00',
    1, 1, '192.168.1.10',
    'Normal login from corporate network.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    2, 2, 1,
    TIMESTAMP '2026-10-01 08:30:00',
    1, 1, '203.0.113.45',
    'First failed login attempt.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    3, 2, 1,
    TIMESTAMP '2026-10-01 08:31:00',
    1, 1, '203.0.113.45',
    'Second failed login attempt.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    4, 2, 2,
    TIMESTAMP '2026-10-01 08:35:00',
    1, 1, '203.0.113.45',
    'Repeated failed login attempts.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    5, 8, 1,
    TIMESTAMP '2026-10-01 08:40:00',
    1, 1, '203.0.113.45',
    'Account automatically locked.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    6, 1, NULL,
    TIMESTAMP '2026-10-02 09:00:00',
    2, 2, '192.168.1.11',
    'Successful login.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    7, 3, 3,
    TIMESTAMP '2026-10-03 11:15:00',
    3, 6, '10.0.0.15',
    'Unexpected privilege escalation.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    8, 4, NULL,
    TIMESTAMP '2026-10-03 12:30:00',
    3, 6, '10.0.0.15',
    'Access to financial report.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    9, 5, NULL,
    TIMESTAMP '2026-10-04 10:00:00',
    NULL, 3, '198.51.100.27',
    'Port scan detected against web server.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    10, 6, NULL,
    TIMESTAMP '2026-10-04 11:30:00',
    NULL, 3, '198.51.100.27',
    'Malware signature detected.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    11, 7, 4,
    TIMESTAMP '2026-10-05 14:20:00',
    2, 3, '192.168.1.20',
    'Unusual outbound data transfer.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    12, 7, 4,
    TIMESTAMP '2026-10-05 14:25:00',
    2, 3, '192.168.1.20',
    'Additional large data transfer.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    13, 2, 5,
    TIMESTAMP '2026-10-08 09:45:00',
    4, 5, '203.0.113.45',
    'Failed login attempt.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    14, 8, 5,
    TIMESTAMP '2026-10-08 10:00:00',
    4, 5, '203.0.113.45',
    'Security account temporarily locked.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    15, 1, NULL,
    TIMESTAMP '2026-10-09 08:15:00',
    1, 1, '192.168.1.10',
    'Normal login.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    16, 5, 6,
    TIMESTAMP '2026-10-10 17:00:00',
    NULL, 4, '198.51.100.27',
    'Port scanning activity against database server.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    17, 4, NULL,
    TIMESTAMP '2026-10-11 10:30:00',
    2, 2, '192.168.1.11',
    'Access to HR documents.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    18, 1, NULL,
    TIMESTAMP '2026-10-11 11:00:00',
    3, 6, '10.0.0.15',
    'Successful authentication.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    19, 6, NULL,
    TIMESTAMP '2026-10-12 13:00:00',
    NULL, 4, '198.51.100.27',
    'Malware detected on database server.'
);

INSERT INTO SECURITY_EVENTS VALUES (
    20, 2, NULL,
    TIMESTAMP '2026-10-12 13:15:00',
    5, 5, '203.0.113.45',
    'Failed login from an external address.'
);


-- =========================================
-- 10. THREAT_TYPES
-- =========================================

INSERT INTO THREAT_TYPES VALUES (
    1, 'BRUTE_FORCE',
    'Repeated authentication attempts.',
    5
);

INSERT INTO THREAT_TYPES VALUES (
    1, 'UNAUTHORIZED_ACCESS',
    'Attempted access using suspicious credentials.',
    4
);

INSERT INTO THREAT_TYPES VALUES (
    2, 'PRIVILEGE_ESCALATION',
    'Unexpected privilege modification.',
    3
);

INSERT INTO THREAT_TYPES VALUES (
    3, 'DATA_EXFILTRATION',
    'Possible unauthorized data extraction.',
    5
);

INSERT INTO THREAT_TYPES VALUES (
    3, 'SUSPICIOUS_ACTIVITY',
    'Unusual network and data transfer patterns.',
    4
);

INSERT INTO THREAT_TYPES VALUES (
    4, 'BRUTE_FORCE',
    'Repeated login failures resulting in account lockout.',
    2
);


COMMIT;

--Prueba de que el trigger funciona

INSERT INTO DEVICE_IP_ASSIGNMENTS (
    ip_address,
    device_id,
    valid_from,
    valid_until
) VALUES (
    '192.168.1.11',
    2,
    TIMESTAMP '2025-06-01 00:00:00',
    TIMESTAMP '2025-12-31 23:59:59'
);

