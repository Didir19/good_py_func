
SELECT
    ip,
    count(distinct host) AS count_hosts,
    count(distinct email_hash) as count_emails,
    collect_set(distinct host) as host_collection
FROM
    ato
WHERE
    ip IN ('208.53.101.233')
    AND ts>='@day_ago' AND ts<'@now'
GROUP BY
    ip;
