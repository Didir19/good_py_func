
SELECT
    t1.ip as ip,
    t2.ACCOUNTNAME AS account_name,
    t3.SUBVERTICAL AS subvertical,
    t1.UA AS ua,
    t1.TOTAL AS total,
    t1.company as company,
    t1.country as country,
    t1.domain as domain,
    t1.network_type as network_type,
    t1.asnum as asnum
   FROM
     (SELECT b2s(ip) as ip,
             getED(ip, 'company') as company,
             getED(ip, 'country') as country,
             getED(ip, 'domain') as domain,
             getED(ip, 'network_type') as network_type,
             getED(ip, 'asnum') as asnum,
             cpcode AS CPCODE,
             user_agent AS UA,
             sum(total_counter) AS TOTAL
      FROM ddc_nat
      WHERE b2s(ip) in ('208.53.101.233')
        AND ts>='@day_ago' AND ts<'@now'
      GROUP BY b2s(ip), getED(ip, 'company'),
               getED(ip, 'country'),
               getED(ip, 'domain'),
               getED(ip, 'network_type'),
               getED(ip, 'asnum'), Cpcode,
               user_agent) t1
   LEFT OUTER JOIN
     (SELECT DISTINCT cpcode AS CPCODE,
                      account_name AS ACCOUNTNAME,
                      account AS ACCOUNTID
      FROM cpcode_metadata
      WHERE ts>='@day_ago' AND ts<'@now') t2 ON (t1.CPCODE = t2.CPCODE)
   LEFT OUTER JOIN
     (SELECT DISTINCT account_id AS ACCOUNTID,
                      vertical AS VERTICAL,
                      subvertical AS SUBVERTICAL
      FROM account_industries
      WHERE ts>='@day_ago' AND ts<'@now') t3 ON (t2.ACCOUNTID = t3.ACCOUNTID)
   WHERE (t3.SUBVERTICAL IN ('Logistics',
                             'Advertising Technology',
                             'Enterprise Software (B2B)',
                             'Enterprise Hardware',
                             'Asset Management',
                             'Business Services',
                             'BPO',
                             'Information Services',
                             'Security Software')
          OR t3.VERTICAL IN ('Software as a Service','Business Services'))
    ORDER BY ip
