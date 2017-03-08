
    SELECT *
    FROM client_intl
    WHERE
        ip IN ('208.53.101.233')
        AND ts>='@21_days_ago' AND ts<'@now'
        AND isnotnull(heuristic_detected)
    ORDER BY ts;
    