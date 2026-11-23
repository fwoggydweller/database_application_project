--1. Mostrar todos los usuarios activos de la organización.
select * from USERS where upper(ACTUAL_STATE) = 'ACTIVE';

--2. Obtener los dispositivos agrupados por tipo.
select * from DEVICES order by TYPE;

--3. Consultar los eventos registrados durante un intervalo de fechas.
select * from SECURITY_EVENTS where SECURITY_EVENTS.TIMESTAMP between TO_TIMESTAMP('01/01/2026 00:00:00.000', 'DD/MM/YYYY HH24:MI:SS.FF') AND TO_TIMESTAMP('01/01/2027 00:00:00.000', 'DD/MM/YYYY HH24:MI:SS.FF');

--4. Mostrar los eventos asociados a un usuario determinado.
select * from SECURITY_EVENTS where USER_ID is not null and USER_ID = 1;

--5. Obtener el número de eventos registrados por tipo.
select EVENT_TYPES.TYPE, count(*) from SECURITY_EVENTS join EVENT_TYPES on EVENT_TYPE_ID = EVENT_ID group by TYPE;

--6. Mostrar las alertas pendientes de gestionar, ordenadas por gravedad.
select * from ALERTS where upper(STATE) <> 'CLOSED' order by RATING;

