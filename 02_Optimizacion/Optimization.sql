/*Luego de revisar todos los planes de ejecución de las queries, he decidido que los índices más útiles a implementar son los siguientes:*/

DROP INDEX INDEX_ALERT_RATING;

DROP INDEX IDX_EVENTS_TYPE_IP;

DROP INDEX IDX_EVENTS_TYPE_USER;

DROP INDEX IDX_EVENTS_DEVICE_ALERT;

DROP INDEX IDX_ALERTS_INCIDENT;

DROP INDEX IDX_EVENTS_DATE_USER_IP;

DROP INDEX IDX_SECURITY_EVENTS_DEVICE_TIMESTAMP;

DROP INDEX IDX_SECURITY_EVENTS_USER_ALERT;

commit;


Create index INDEX_ALERT_RATING
on ALERTS(RATING);
Create index IDX_EVENTS_TYPE_IP
on SECURITY_EVENTS(EVENT_TYPE_ID, IP_ADDRESS);
Create index IDX_EVENTS_TYPE_USER
on SECURITY_EVENTS(EVENT_TYPE_ID, USER_ID);
Create index IDX_EVENTS_DEVICE_ALERT
on SECURITY_EVENTS(DEVICE_ID, ALERT_ID);
Create index IDX_ALERTS_INCIDENT
on ALERTS(INCIDENT_ID);
Create index IDX_EVENTS_DATE_USER_IP
on SECURITY_EVENTS(TIMESTAMP, USER_ID, IP_ADDRESS);
Create index IDX_SECURITY_EVENTS_DEVICE_TIMESTAMP
on SECURITY_EVENTS(DEVICE_ID, TIMESTAMP);
Create index IDX_SECURITY_EVENTS_USER_ALERT
on SECURITY_EVENTS(USER_ID, ALERT_ID);
/*
Los mejores resultados se han obtenido con los índices compuestos IDX_EVENTS_TYPE_IP y IDX_EVENTS_TYPE_USER,
que permiten filtrar los eventos por tipo y acceder a las direcciones IP o a los usuarios correspondientes.
También destaca IDX_ALERTS_INCIDENT, que ha permitido mejorar el acceso a las alertas relacionadas con los incidentes.

A lo largo del análisis se han planteado otros índices adicionales, con bajo o nulo aprovechamiento,
pero se han descartado, puesto que tener índices innecesarios también puede penalizar al realizar inserciones,
deleciones y actualizaciones.
*/

/*Además de todos los índices, se han re-planteado algunas queries y se han eliminado joins innecesarios.

    QUERY 8-. En la query original se hace un join con EVENT_TYPES que es innecesario, puesto que los valores que se obtienen de esa tabla se pueden sacar de SECURITY_EVENTS:
  select USERS.USER_ID, USERS.USERNAME, USERS.DEPARTMENT
from SECURITY_EVENTS
join USERS on USERS.USER_ID = SECURITY_EVENTS.USER_ID
where SECURITY_EVENTS.EVENT_TYPE_ID = 8
group by USERS.USER_ID, USERS.USERNAME, USERS.DEPARTMENT
order by count(*) desc;

  QUERY 10-. En la query original, se utilizaba un left join, el cual no era necesario, puesto que posteriormente se filtra por upper(INCIDENTS.STATE) <> 'CLOSED':
  select INCIDENTS.INCIDENT_ID, INCIDENTS.RATING, INCIDENTS.CREATION_DATE, INCIDENTS.CLOSED_DATE, INCIDENTS.PRIORITY, INCIDENTS.STATE, count(distinct ALERTS.ALERT_ID)
from ALERTS join INCIDENTS on ALERTS.INCIDENT_ID = INCIDENTS.INCIDENT_ID
where upper(INCIDENTS.STATE) <> 'CLOSED'
group by INCIDENTS.INCIDENT_ID, INCIDENTS.RATING, INCIDENTS.CREATION_DATE, INCIDENTS.CLOSED_DATE, INCIDENTS.PRIORITY, INCIDENTS.STATE;

  Tras aplicar todos estos cambios, podemos observar una gran mejoría en casi todas las queries (sobretodo en las queries 7, 8 y 10) cuyo coste estimado se ha reducido a la mitad*/