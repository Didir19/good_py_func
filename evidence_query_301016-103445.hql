
SELECT intermediate_data.client_id AS IP,
       getED(intermediate_data.client_id,'company') AS COMPANY,
       getED(intermediate_data.client_id,'domain') AS DOMAIN,
       intermediate_data.heuristic_name AS HEURISTIC_NAME,
       intermediate_data.score AS SCORE,
       evidence_properties.key AS KEY ,
       evidence_properties.value AS VALUE,
       innerTable.HOSTS AS HOSTS,
       intermediate_data.ts AS TS
FROM intermediate_data
JOIN evidence_properties ON (intermediate_data.id = evidence_properties.id
                             AND intermediate_data.ts = evidence_properties.ts)
JOIN
  (SELECT host_stats.ts AS TS,
          host_stats.id ID,
          collect_set(host_stats.host) AS HOSTS
   FROM host_stats
   WHERE ts in (1475985600000, 1477540800000, 1477551600000)
   GROUP BY host_stats.id,
            host_stats.ts) innerTable ON (intermediate_data.id = innerTable.ID
                                          AND intermediate_data.ts = innerTable.TS)
WHERE intermediate_data.client_id IN ('208.53.101.233')
  AND intermediate_data.ts in (1475985600000, 1477540800000, 1477551600000)
  AND evidence_properties.ts in (1475985600000, 1477540800000, 1477551600000)
  AND intermediate_data.heuristic_name NOT LIKE '%Score%'
  AND intermediate_data.group_ids LIKE '%production%'
                                            