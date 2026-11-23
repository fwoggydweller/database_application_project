--13. Identificar posibles patrones de fuerza bruta mediante ventanas temporales.
select SECURITY_EVENTS.IP_ADDRESS, count(*) as NUM_ATTEMPTS, min(SECURITY_EVENTS.TIMESTAMP) as FIRST_TRY, max(SECURITY_EVENTS.TIMESTAMP) as LAST_TRY
from EVENT_TYPES join SECURITY_EVENTS on SECURITY_EVENTS.EVENT_TYPE_ID=EVENT_TYPES.EVENT_ID
where EVENT_ID = 2
group by SECURITY_EVENTS.IP_ADDRESS
having count(*) >= 5
order by NUM_ATTEMPTS desc;

--14. Obtener el ranking de las direcciones IP según el número de eventos sospechosos.
select SECURITY_EVENTS.IP_ADDRESS, count(*) as NUM_SUS_TRIES
from SECURITY_EVENTS join EVENT_TYPES on SECURITY_EVENTS.EVENT_TYPE_ID = EVENT_TYPES.EVENT_ID
where upper(EVENT_TYPES.CLASSIFICATION) <> 'INFO' and SECURITY_EVENTS.IP_ADDRESS is not null
group by SECURITY_EVENTS.IP_ADDRESS
order by NUM_SUS_TRIES desc;

--15. Calcular la evolución diaria y mensual de los eventos por categoría.
select EVENT_TYPES.TYPE, to_char(SECURITY_EVENTS.TIMESTAMP, 'DD') as DAY,  to_char(SECURITY_EVENTS.TIMESTAMP, 'YYYY-MM') as MONTH, to_char(SECURITY_EVENTS.TIMESTAMP, 'HH24:MI:SS') as hours, count(*) over(
    partition by EVENT_TYPES.TYPE, to_char(SECURITY_EVENTS.TIMESTAMP, 'YYYY-MM')
    ) NUM_EVENTS_OF_THIS_TYPE_PER_MONTH,
    count(*) over(
    partition by EVENT_TYPES.TYPE, to_char(SECURITY_EVENTS.TIMESTAMP, 'YYYY-MM-DD')
    ) NUM_EVENTS_OF_THIS_TYPE_PER_DAY
from SECURITY_EVENTS join EVENT_TYPES on SECURITY_EVENTS.EVENT_TYPE_ID = EVENT_TYPES.EVENT_ID
order by EXTRACT(DAY from SECURITY_EVENTS.TIMESTAMP), EXTRACT(MONTH from SECURITY_EVENTS.TIMESTAMP), EVENT_TYPES.TYPE;

--16. Obtener los tipos de amenazas más frecuentes durante cada mes.
select THREAT_TYPES.CATEGORY, to_char(INCIDENTS.CREATION_DATE, 'YYYY-MM') as INCIDENT_DATE, count(*) as COUNT_TIMES
from INCIDENTS join THREAT_TYPES on INCIDENTS.INCIDENT_ID = THREAT_TYPES.INCIDENT_ID
group by THREAT_TYPES.CATEGORY, to_char(INCIDENTS.CREATION_DATE, 'YYYY-MM');

--17. Identificar dispositivos cuyo volumen de eventos haya aumentado significativamente respecto a su actividad anterior.
with current_day_result(id_curr, name_curr, date_curr, result_curr) as (
    select d.DEVICE_ID as id_curr, d.DEVICE_NAME as name_curr, trunc(se.TIMESTAMP) as date_curr, count(*) as result
    from SECURITY_EVENTS se join DEVICES d on se.DEVICE_ID = d.DEVICE_ID
    group by d.DEVICE_ID, d.DEVICE_NAME, trunc(se.TIMESTAMP)
),
compare(id_dev, name_dev, date_last, result_curr, result_last) as(
    select id_curr, name_curr, date_curr, result_curr, LAG(result_curr, 1, 0) over(partition by id_curr order by date_curr) as result
    from current_day_result
)
select * from compare
where compare.result_last < compare.result_curr
order by date_last, id_dev;

--18. Obtener los usuarios con mayor número de alertas de gravedad elevada.
with ordered_users(id, name, num_high_rating_alerts) as (
select u.USER_ID as id, u.USERNAME as name, COUNT(DISTINCT a.ALERT_ID) as num_high_rating_alerts
from USERS u left join SECURITY_EVENTS se on u.USER_ID = se.USER_ID
left join ALERTS a on se.ALERT_ID = a.ALERT_ID and a.RATING > 2
group by u.USER_ID, u.USERNAME
)
select dense_rank() over(order by ordered_users.num_high_rating_alerts desc) as ranking, ordered_users.*
from ordered_users;

--19. Generar un informe que muestre el número de incidentes por gravedad y estado.
with pivot_table_1 as(
    select * from (select RATING, STATE from INCIDENTS)
    pivot(count(RATING) for RATING in (1 as VERY_LOW, 2 as LOW, 3 as MEDIUM, 4 as HIGH, 5 as CRITICAL)))
select * from pivot_table_1;

--20. Obtener el historial cronológico completo de actuaciones asociadas a un incidente.
select 'ALERT' as type, ALERTS.INCIDENT_ID, ALERTS.CREATION_DATE as CREATION_DATE, ALERTS.STATE, DESCRIPTION
from ALERTS
union all
select 'RESPONSE' as type, INCIDENTS.INCIDENT_ID, TIMESTAMP as CREATION_DATE, STATE, DESCRIPTION
from INCIDENTS join INCIDENT_RESPONSES on INCIDENTS.INCIDENT_ID = INCIDENT_RESPONSES.INCIDENT_ID
order by CREATION_DATE;
